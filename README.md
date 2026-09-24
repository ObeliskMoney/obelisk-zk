# Obelisk policy program

The SP1 zero-knowledge program behind [Obelisk](https://obelisk.cash), an onchain vault for AI agents on Robinhood Chain mainnet.

An AI agent can only move a vault's funds with a proof from this program. The program reads the vault's policy and the agent's intent, checks every rule, and commits `PolicyOutput{policyHash, intentHash, spentBefore, spentAfter, day}`. If any rule is broken it panics, so no proof exists and the vault contract reverts. A prompt-injected agent can sign whatever it likes; it still cannot produce a proof for a transfer the owner did not allow.

> Beta. This program has not had a third-party audit.

## What it checks

- The intent sends no ETH and does not call the vault itself
- The function is on the policy's list, and the calldata has exactly the expected ABI length (odd calldata is refused)
- `approve`: only to an allowed spender, capped at the daily limit
- `transfer`: only to an allowed payee
- `exactInputSingle` (Uniswap SwapRouter02): only from the policy token, only into an allowed output token, only through an allowed pool (fee tier), output goes back to the vault, and a minimum output at or above the owner's price floor (`amountOutMinimum * 1e18 >= amountIn * minOutPerIn`, in 512-bit math)
- The policy itself is well formed (`BAD_POLICY` otherwise): fees fit in uint24 and every output token has a non-zero price floor
- The spend stays within the per-transaction and per-day limits, with overflow-checked math

Refusals return stable codes (`SELECTOR_NOT_ALLOWED`, `EXCEEDS_PER_DAY`, ...) that the agent and the public activity log use.

## Layout

| Path | Contents |
|---|---|
| [`lib/`](lib/src/lib.rs) | The policy rules (`obelisk-policy`). The same code runs inside the zkVM and on the host for a fast pre-check. |
| [`program/`](program/src/main.rs) | The SP1 guest entry point |
| [`script/`](script/src/bin/main.rs) | Prover CLI (`check`, `execute`, `prove` with mock, CPU or network provers) and the `vkey` tool |
| [`elf/`](elf/README.md) | The program binary, built reproducibly in Docker. Every vault's `programVKey` is derived from it. |
| [`fixtures/`](fixtures/) | Example policy, the cross-language test vectors and the mainnet deployment record (the `vkey` tool's test checks the committed ELF against it) |

Mainnet program verification key (policy v3): `0x002c72fab9e46ad169621189cf082ed7a585af657aa44c4ef657d3d0621c53bd`. The v2 program (`0x005837e0...29bb`) had no pool or price bound; see self-audit F-15 in the main repository.

## Tests

```bash
cargo test -p obelisk-policy
```

38 tests cover every rule, odd calldata, dirty padding, overflow, the price floor at its exact boundary, malformed policies and the example policy. The vectors in `fixtures/vectors.json` are regenerated from Rust and checked in Solidity and TypeScript:

```bash
cargo run -q -p obelisk-policy --example vectors
```

## Rebuild the ELF

```bash
cd program && cargo prove build --docker --locked --output-directory ../elf --elf-name obelisk-policy-program
```

```bash
cd script && cargo run --release --bin vkey
```

## Related

- [ObeliskMoney/Obelisk](https://github.com/ObeliskMoney/Obelisk): the full system (agent, executor, website, docs, spec and threat model)
- [ObeliskMoney/obelisk-contracts](https://github.com/ObeliskMoney/obelisk-contracts): the vault, factory and registry contracts

## License

MIT
