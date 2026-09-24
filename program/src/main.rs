//! Obelisk SP1 program: proves that an intent follows the vault's policy.
//! If any rule is broken the program panics, so no proof can be produced.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolValue;
use obelisk_policy::{check, ProverInput};

pub fn main() {
    let input = sp1_zkvm::io::read::<ProverInput>();
    let out = match check(&input) {
        Ok(out) => out,
        Err(e) => panic!("policy violation: {e}"),
    };
    sp1_zkvm::io::commit_slice(&out.abi_encode());
}
