The SP1 program ELF, built reproducibly with Docker:

    cd program && cargo prove build --docker --locked --output-directory ../elf --elf-name obelisk-policy-program

Every vault's `programVKey` is derived from this file, and the mainnet factory is fixed to it
(`0x005837e0791c16ed77947585ad983c678684500b27c6ff2ea54b700637f929bb`). Any change to `lib` or
`program` that alters this binary (code, strings, or even line numbers used in panic locations)
produces a new vkey, which existing vaults will not accept. After such a change: rebuild, commit the ELF,
print the new vkey (`cargo run --release --bin vkey`) and deploy a new factory.
