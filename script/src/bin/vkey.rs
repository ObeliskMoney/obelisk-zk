//! Prints the programVKey for deployments (ObeliskVaultFactory).
use sp1_sdk::{blocking::MockProver, blocking::Prover, Elf, HashableKey, ProvingKey};

const ELF: Elf = Elf::Static(include_bytes!("../../../elf/obelisk-policy-program"));

fn main() {
    let pk = MockProver::new().setup(ELF).expect("setup failed");
    println!("{}", pk.verifying_key().bytes32());
}
