//! Obelisk policy logic (docs/spec.md §2 to §4).
//!
//! Used in two places with exactly the same code:
//! - inside the SP1 program (guest), to produce the proof;
//! - on the host (native), for a fast pre-check and clear refusal codes.

use alloy_primitives::{aliases::U24, keccak256, Address, Bytes, FixedBytes, B256, U256, U512};
use alloy_sol_types::{sol, SolCall, SolValue};
use serde::{Deserialize, Serialize};

sol! {
    /// Public values committed by the program. Must match the struct in IObeliskVault.sol.
    #[derive(Debug, PartialEq, Eq)]
    struct PolicyOutput {
        bytes32 policyHash;
        bytes32 intentHash;
        uint256 spentBefore;
        uint256 spentAfter;
        uint64 day;
    }

    function approve(address spender, uint256 amount);
    function transfer(address to, uint256 amount);

    /// Uniswap SwapRouter02 (no deadline field).
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams params);
}

/// v2: adds `allowedTokensOut` and requires `amountOutMinimum > 0` for swaps.
/// v3: adds `allowedFees` (pins the swap pool) and `minOutPerIn` (an owner-set price floor per output token).
pub const POLICY_VERSION: u8 = 3;

/// `minOutPerIn` is the minimum `amountOut` per unit of `amountIn`, scaled by 1e18.
pub const PRICE_SCALE: u64 = 1_000_000_000_000_000_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub version: u8,
    pub token: Address,
    pub max_per_tx: U256,
    pub max_per_day: U256,
    pub allowed_targets: Vec<Address>,
    #[serde(default)]
    pub allowed_recipients: Vec<Address>,
    pub allowed_selectors: Vec<FixedBytes<4>>,
    pub deny_unlimited_approve: bool,
    /// Tokens a swap may output (v2).
    #[serde(default)]
    pub allowed_tokens_out: Vec<Address>,
    /// Uniswap fee tiers a swap may use, which pins the pool (v3). Each must fit in uint24.
    #[serde(default)]
    pub allowed_fees: Vec<u32>,
    /// Price floor for `allowed_tokens_out[i]`: minimum amountOut per unit of amountIn, times 1e18 (v3).
    /// Same length as `allowed_tokens_out`, every entry above zero.
    #[serde(default)]
    pub min_out_per_in: Vec<U256>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Intent {
    pub target: Address,
    pub value: U256,
    pub data: Bytes,
    pub nonce: U256,
    pub deadline: u64,
}

/// All program inputs. `chain_id`, `vault`, `spent_before` and `day` need not be
/// trusted: they are all bound to public values that the vault checks again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProverInput {
    pub chain_id: u64,
    pub vault: Address,
    pub policy: Policy,
    pub intent: Intent,
    pub spent_before: U256,
    pub day: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Violation {
    UnsupportedVersion(u8),
    BadPolicy,
    ValueNotZero,
    SelfCall,
    CalldataTooShort,
    SelectorNotAllowed(FixedBytes<4>),
    UnknownSelector(FixedBytes<4>),
    BadCalldataLength { expected: usize, got: usize },
    BadCalldataEncoding,
    TargetNotAllowed(Address),
    SpenderNotAllowed(Address),
    RecipientNotAllowed(Address),
    TokenNotAllowed(Address),
    SwapRecipientNotVault(Address),
    TokenOutNotAllowed(Address),
    NoMinOut,
    FeeNotAllowed(u32),
    MinOutBelowFloor { min_out: U256, required: U256 },
    UnlimitedApprove(U256),
    ExceedsPerTx { spend: U256, max: U256 },
    ExceedsPerDay { after: U256, max: U256 },
}

impl Violation {
    /// Stable code for the activity log and the agent.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedVersion(_) => "UNSUPPORTED_VERSION",
            Self::BadPolicy => "BAD_POLICY",
            Self::ValueNotZero => "VALUE_NOT_ZERO",
            Self::SelfCall => "SELF_CALL",
            Self::CalldataTooShort => "CALLDATA_TOO_SHORT",
            Self::SelectorNotAllowed(_) => "SELECTOR_NOT_ALLOWED",
            Self::UnknownSelector(_) => "UNKNOWN_SELECTOR",
            Self::BadCalldataLength { .. } => "BAD_CALLDATA_LENGTH",
            Self::BadCalldataEncoding => "BAD_CALLDATA_ENCODING",
            Self::TargetNotAllowed(_) => "TARGET_NOT_ALLOWED",
            Self::SpenderNotAllowed(_) => "SPENDER_NOT_ALLOWED",
            Self::RecipientNotAllowed(_) => "RECIPIENT_NOT_ALLOWED",
            Self::TokenNotAllowed(_) => "TOKEN_NOT_ALLOWED",
            Self::SwapRecipientNotVault(_) => "SWAP_RECIPIENT_NOT_VAULT",
            Self::TokenOutNotAllowed(_) => "TOKEN_OUT_NOT_ALLOWED",
            Self::NoMinOut => "NO_MIN_OUT",
            Self::FeeNotAllowed(_) => "FEE_NOT_ALLOWED",
            Self::MinOutBelowFloor { .. } => "MIN_OUT_BELOW_FLOOR",
            Self::UnlimitedApprove(_) => "UNLIMITED_APPROVE",
            Self::ExceedsPerTx { .. } => "EXCEEDS_PER_TX",
            Self::ExceedsPerDay { .. } => "EXCEEDS_PER_DAY",
        }
    }
}

impl core::fmt::Display for Violation { // Frozen: these messages are compiled into the deployed program (programVKey); the prover CLI reports English text (docs/spec.md §3).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "versi policy {v} tidak didukung"),
            Self::BadPolicy => write!(f, "policy tidak valid"),
            Self::ValueNotZero => write!(f, "pengiriman ETH tidak diizinkan"),
            Self::SelfCall => write!(f, "intent tidak boleh memanggil vault sendiri"),
            Self::CalldataTooShort => write!(f, "calldata terlalu pendek"),
            Self::SelectorNotAllowed(s) => write!(f, "fungsi {s} tidak diizinkan policy"),
            Self::UnknownSelector(s) => write!(f, "fungsi {s} tidak dikenal"),
            Self::BadCalldataLength { expected, got } => {
                write!(f, "panjang calldata {got} byte, seharusnya {expected}")
            }
            Self::BadCalldataEncoding => write!(f, "encoding calldata tidak valid"),
            Self::TargetNotAllowed(a) => write!(f, "target {a} tidak di whitelist"),
            Self::SpenderNotAllowed(a) => write!(f, "approve ke {a} tidak di whitelist"),
            Self::RecipientNotAllowed(a) => write!(f, "penerima {a} tidak di whitelist"),
            Self::TokenNotAllowed(a) => write!(f, "token {a} tidak diatur policy"),
            Self::SwapRecipientNotVault(a) => write!(f, "hasil swap dikirim ke {a}, bukan ke vault"),
            Self::TokenOutNotAllowed(a) => write!(f, "swap ke token {a} tidak di whitelist"),
            Self::NoMinOut => write!(f, "swap tanpa batas slippage (amountOutMinimum = 0)"),
            Self::FeeNotAllowed(x) => write!(f, "fee pool {x} tidak di whitelist"),
            Self::MinOutBelowFloor { min_out, required } => {
                write!(f, "amountOutMinimum {min_out} di bawah batas harga {required}")
            }
            Self::UnlimitedApprove(x) => write!(f, "approve {x} melebihi batas"),
            Self::ExceedsPerTx { spend, max } => {
                write!(f, "nominal {spend} melebihi batas per transaksi {max}")
            }
            Self::ExceedsPerDay { after, max } => {
                write!(f, "total harian {after} melebihi batas harian {max}")
            }
        }
    }
}

impl Policy {
    /// docs/spec.md §2.
    pub fn hash(&self) -> B256 {
        keccak256(
            (
                // abi.encode encodes uint8 as a 32-byte word, the same as uint256.
                U256::from(self.version),
                self.token,
                self.max_per_tx,
                self.max_per_day,
                self.allowed_targets.clone(),
                self.allowed_recipients.clone(),
                self.allowed_selectors.clone(),
                self.deny_unlimited_approve,
                self.allowed_tokens_out.clone(),
                // Encoded as uint24[]; `check` refuses a policy with a fee above uint24.
                self.allowed_fees.iter().map(|f| U24::saturating_from(*f)).collect::<Vec<_>>(),
                self.min_out_per_in.clone(),
            )
                .abi_encode_params(),
        )
    }
}

impl Policy {
    /// v3 shape rules: fees fit in uint24, one non-zero price floor per output token.
    fn validate(&self) -> Result<(), Violation> {
        let fees_ok = self.allowed_fees.iter().all(|f| *f <= 0xFF_FFFF);
        let floors_ok = self.min_out_per_in.len() == self.allowed_tokens_out.len()
            && self.min_out_per_in.iter().all(|x| !x.is_zero());
        if fees_ok && floors_ok {
            Ok(())
        } else {
            Err(Violation::BadPolicy)
        }
    }
}

impl Intent {
    /// docs/spec.md §1.1.
    pub fn hash(&self, chain_id: u64, vault: Address) -> B256 {
        keccak256(
            (
                U256::from(chain_id),
                vault,
                self.target,
                self.value,
                keccak256(&self.data),
                self.nonce,
                self.deadline,
            )
                .abi_encode_params(),
        )
    }
}

fn expect_len(data: &[u8], expected: usize) -> Result<(), Violation> {
    if data.len() != expected {
        return Err(Violation::BadCalldataLength { expected, got: data.len() });
    }
    Ok(())
}

/// Computes how much `policy.token` the intent spends, or refuses it.
fn spend_of(input: &ProverInput) -> Result<U256, Violation> {
    let p = &input.policy;
    let i = &input.intent;
    let data = i.data.as_ref();

    let selector = FixedBytes::<4>::from_slice(&data[..4]);
    if !p.allowed_selectors.contains(&selector) {
        return Err(Violation::SelectorNotAllowed(selector));
    }

    match selector.0 {
        approveCall::SELECTOR => {
            expect_len(data, 4 + 32 * 2)?;
            if i.target != p.token {
                return Err(Violation::TargetNotAllowed(i.target));
            }
            let c = approveCall::abi_decode_validate(data).map_err(|_| Violation::BadCalldataEncoding)?;
            if !p.allowed_targets.contains(&c.spender) {
                return Err(Violation::SpenderNotAllowed(c.spender));
            }
            // The allowance can only be used by an allowed router, and the router only pulls from
            // its caller (the vault), so a maxPerDay cap is enough; swaps still count as spend.
            if p.deny_unlimited_approve && c.amount > p.max_per_day {
                return Err(Violation::UnlimitedApprove(c.amount));
            }
            Ok(U256::ZERO)
        }
        transferCall::SELECTOR => {
            expect_len(data, 4 + 32 * 2)?;
            if i.target != p.token {
                return Err(Violation::TargetNotAllowed(i.target));
            }
            let c = transferCall::abi_decode_validate(data).map_err(|_| Violation::BadCalldataEncoding)?;
            if !p.allowed_recipients.contains(&c.to) {
                return Err(Violation::RecipientNotAllowed(c.to));
            }
            Ok(c.amount)
        }
        exactInputSingleCall::SELECTOR => {
            expect_len(data, 4 + 32 * 7)?;
            if !p.allowed_targets.contains(&i.target) {
                return Err(Violation::TargetNotAllowed(i.target));
            }
            let c = exactInputSingleCall::abi_decode_validate(data)
                .map_err(|_| Violation::BadCalldataEncoding)?
                .params;
            if c.tokenIn != p.token {
                return Err(Violation::TokenNotAllowed(c.tokenIn));
            }
            if c.recipient != input.vault {
                return Err(Violation::SwapRecipientNotVault(c.recipient));
            }
            let fee = c.fee.to::<u32>();
            if !p.allowed_fees.contains(&fee) {
                return Err(Violation::FeeNotAllowed(fee));
            }
            let Some(k) = p.allowed_tokens_out.iter().position(|t| *t == c.tokenOut) else {
                return Err(Violation::TokenOutNotAllowed(c.tokenOut));
            };
            if c.amountOutMinimum.is_zero() {
                return Err(Violation::NoMinOut);
            }
            // amountOutMinimum * 1e18 >= amountIn * minOutPerIn, in 512 bits so nothing overflows.
            let scale = U512::from(PRICE_SCALE);
            let need = U512::from(c.amountIn) * U512::from(p.min_out_per_in[k]);
            if U512::from(c.amountOutMinimum) * scale < need {
                let required = need.div_ceil(scale);
                return Err(Violation::MinOutBelowFloor {
                    min_out: c.amountOutMinimum,
                    required: U256::saturating_from(required),
                });
            }
            Ok(c.amountIn)
        }
        _ => Err(Violation::UnknownSelector(selector)),
    }
}

/// The full rules of docs/spec.md §3. `Ok` means a proof may be produced.
pub fn check(input: &ProverInput) -> Result<PolicyOutput, Violation> {
    let p = &input.policy;
    let i = &input.intent;

    if p.version != POLICY_VERSION {
        return Err(Violation::UnsupportedVersion(p.version));
    }
    p.validate()?;
    if !i.value.is_zero() {
        return Err(Violation::ValueNotZero);
    }
    if i.target == input.vault {
        return Err(Violation::SelfCall);
    }
    if i.data.len() < 4 {
        return Err(Violation::CalldataTooShort);
    }

    let spend = spend_of(input)?;
    if spend > p.max_per_tx {
        return Err(Violation::ExceedsPerTx { spend, max: p.max_per_tx });
    }
    let after = input
        .spent_before
        .checked_add(spend)
        .filter(|a| *a <= p.max_per_day)
        .ok_or(Violation::ExceedsPerDay {
            after: input.spent_before.saturating_add(spend),
            max: p.max_per_day,
        })?;

    Ok(PolicyOutput {
        policyHash: p.hash(),
        intentHash: i.hash(input.chain_id, input.vault),
        spentBefore: input.spent_before,
        spentAfter: after,
        day: input.day,
    })
}

#[cfg(test)]
mod tests;
