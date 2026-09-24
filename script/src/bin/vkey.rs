//! Prints the programVKey for deployments (ObeliskVaultFactory).
use sp1_sdk::{blocking::MockProver, blocking::Prover, Elf, HashableKey, ProvingKey};

const ELF: Elf = Elf::Static(include_bytes!("../../../elf/obelisk-policy-program"));

fn main() {
    let pk = MockProver::new().setup(ELF).expect("setup failed");
    println!("{}", pk.verifying_key().bytes32());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed ELF must be the program the mainnet factory is fixed to.
    /// If this fails after an ELF rebuild, deploy a new factory and update the deployment record.
    #[test]
    fn committed_elf_matches_mainnet_program_vkey() {
        let raw = include_str!("../../../fixtures/robinhood.json");
        let dep: serde_json::Value = serde_json::from_str(raw).unwrap();
        let pk = MockProver::new().setup(ELF).expect("setup failed");
        assert_eq!(pk.verifying_key().bytes32(), dep["programVKey"].as_str().unwrap());
    }
}
