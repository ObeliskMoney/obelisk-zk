//! Generates the cross-language test vectors (Rust ↔ Solidity ↔ TypeScript).
//! Output: fixtures/vectors.json
use alloy_primitives::{address, aliases::{U160, U24}, Address, U256};
use alloy_sol_types::{SolCall, SolValue};
use obelisk_policy::*;
use serde_json::json;

fn main() {
    let vault: Address = address!("00000000000000000000000000000000000000Aa");
    let policy: Policy = serde_json::from_str(include_str!("../../fixtures/policy.example.json")).unwrap();
    let params = ExactInputSingleParams {
        tokenIn: policy.token,
        tokenOut: policy.allowed_tokens_out[0],
        fee: U24::from(500),
        recipient: vault,
        amountIn: U256::from(50_000_000u64),
        amountOutMinimum: U256::from(18_000_000_000_000_000u64),
        sqrtPriceLimitX96: U160::ZERO,
    };
    let intent = Intent {
        target: policy.allowed_targets[0],
        value: U256::ZERO,
        data: exactInputSingleCall { params }.abi_encode().into(),
        nonce: U256::from(7),
        deadline: 1_790_003_600,
    };
    let input = ProverInput {
        chain_id: 84532,
        vault,
        policy: policy.clone(),
        intent: intent.clone(),
        spent_before: U256::from(100_000_000u64),
        day: 20_717,
    };
    let out = check(&input).unwrap();
    let v = json!({
        "input": input,
        "policyHash": policy.hash(),
        "intentHash": intent.hash(input.chain_id, vault),
        "publicValues": format!("0x{}", alloy_primitives::hex::encode(out.abi_encode())),
    });
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/vectors.json");
    std::fs::create_dir_all(std::path::Path::new(path).parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
    println!("{}", serde_json::to_string_pretty(&v).unwrap());
}
