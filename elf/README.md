The SP1 program ELF, built reproducibly with Docker:

    cd program && cargo prove build --docker --locked --output-directory ../elf --elf-name obelisk-policy-program

Every vault's `programVKey` is derived from this file, and the mainnet factory is fixed to it
(`0x002c72fab9e46ad169621189cf082ed7a585af657aa44c4ef657d3d0621c53bd`, policy v3). Any change to `lib` or
`program` that alters this binary (code, strings, or even line numbers used in panic locations)
produces a new vkey, which existing vaults will not accept. After such a change: rebuild, commit the ELF,
print the new vkey (`cargo run --release --bin vkey`) and deploy a new factory.
