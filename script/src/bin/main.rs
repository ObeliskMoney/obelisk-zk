//! Obelisk prover CLI.
//!
//! Reads a `ProverInput` (JSON, see docs/spec.md) from a file or stdin, then:
//! 1. runs a native pre-check with exactly the same logic as the SP1 program;
//! 2. runs the program in the zkVM (`--mode execute`) or produces a Groth16 proof (`--mode prove`).
//!
//! The prover mode is set by the `SP1_PROVER` env var (`mock` | `cpu` | `network`).
//! Output is always one JSON object on stdout. Exit code 2 = the intent breaks the policy.
//!
//! ```shell
//! SP1_PROVER=mock cargo run --release -- --mode prove --input input.json
//! ```

use alloy_sol_types::SolValue;
use clap::{Parser, ValueEnum};
use obelisk_policy::{check, ProverInput, Violation};
use serde_json::json;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Stdin,
};
use std::io::Read;

const ELF: Elf = Elf::Static(include_bytes!("../../../elf/obelisk-policy-program"));

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Mode {
    /// Native pre-check only.
    Check,
    /// Run in the zkVM without a proof.
    Execute,
    /// Produce a Groth16 proof (mock/cpu/network per SP1_PROVER).
    Prove,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, value_enum, default_value = "prove")]
    mode: Mode,
    /// JSON file path, or `-` for stdin.
    #[arg(long, default_value = "-")]
    input: String,
}

fn hex0x(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// Plain-English refusal reason for the activity log. The program's own `Display` text is frozen
/// because it is compiled into the deployed program (see docs/spec.md §3).
fn english(v: &Violation) -> String {
    use Violation::*;
    match v {
        UnsupportedVersion(x) => format!("policy version {x} is not supported"),
        ValueNotZero => "sending ETH is not allowed".into(),
        SelfCall => "the intent may not call the vault itself".into(),
        CalldataTooShort => "calldata is too short".into(),
        SelectorNotAllowed(s) => format!("function {s} is not allowed by the policy"),
        UnknownSelector(s) => format!("function {s} is not known"),
        BadCalldataLength { expected, got } => format!("calldata is {got} bytes, expected {expected}"),
        BadCalldataEncoding => "calldata encoding is invalid".into(),
        TargetNotAllowed(a) => format!("target {a} is not allowed"),
        SpenderNotAllowed(a) => format!("approval to {a} is not allowed"),
        RecipientNotAllowed(a) => format!("recipient {a} is not allowed"),
        TokenNotAllowed(a) => format!("token {a} is not covered by the policy"),
        SwapRecipientNotVault(a) => format!("swap output goes to {a}, not the vault"),
        TokenOutNotAllowed(a) => format!("swapping into token {a} is not allowed"),
        NoMinOut => "swap has no price protection (amountOutMinimum = 0)".into(),
        UnlimitedApprove(x) => format!("approval of {x} is above the limit"),
        ExceedsPerTx { spend, max } => format!("amount {spend} is above the per-transaction limit {max}"),
        ExceedsPerDay { after, max } => format!("daily total {after} is above the daily limit {max}"),
    }
}

fn fail(code: &str, reason: String, exit: i32) -> ! {
    println!("{}", json!({ "ok": false, "code": code, "reason": reason }));
    std::process::exit(exit)
}

fn main() {
    dotenv::dotenv().ok();
    let args = Args::parse();

    let raw = if args.input == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).expect("failed to read stdin");
        s
    } else {
        std::fs::read_to_string(&args.input).unwrap_or_else(|e| fail("BAD_INPUT", e.to_string(), 1))
    };
    let input: ProverInput = serde_json::from_str(&raw).unwrap_or_else(|e| fail("BAD_INPUT", e.to_string(), 1));

    let expected = match check(&input) {
        Ok(out) => out,
        Err(v) => fail(v.code(), english(&v), 2),
    };
    let expected_pv = expected.abi_encode();

    let base = json!({
        "ok": true,
        "policyHash": expected.policyHash.to_string(),
        "intentHash": expected.intentHash.to_string(),
        "spentBefore": expected.spentBefore.to_string(),
        "spentAfter": expected.spentAfter.to_string(),
        "day": expected.day,
        "publicValues": hex0x(&expected_pv),
    });

    if let Mode::Check = args.mode {
        println!("{base}");
        return;
    }

    let mut stdin = SP1Stdin::new();
    stdin.write(&input);
    let client = ProverClient::from_env();

    let mut out = base;
    match args.mode {
        Mode::Execute => {
            let (pv, report) = client
                .execute(ELF, stdin)
                .run()
                .unwrap_or_else(|e| fail("ZKVM_EXECUTE_FAILED", e.to_string(), 1));
            assert_eq!(pv.as_slice(), expected_pv.as_slice(), "zkVM output differs from the native pre-check");
            out["cycles"] = json!(report.total_instruction_count());
        }
        Mode::Prove => {
            let pk = client.setup(ELF).unwrap_or_else(|e| fail("SETUP_FAILED", e.to_string(), 1));
            let proof = client
                .prove(&pk, stdin)
                .groth16()
                .run()
                .unwrap_or_else(|e| fail("PROVE_FAILED", e.to_string(), 1));
            assert_eq!(proof.public_values.as_slice(), expected_pv.as_slice());
            out["proof"] = json!(hex0x(&proof.bytes()));
            out["vkey"] = json!(pk.verifying_key().bytes32());
            out["prover"] = json!(std::env::var("SP1_PROVER").unwrap_or_else(|_| "cpu".into()));
        }
        Mode::Check => unreachable!(),
    }
    println!("{out}");
}
