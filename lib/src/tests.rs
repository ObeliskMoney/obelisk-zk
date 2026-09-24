use super::*;
use alloy_primitives::{address, fixed_bytes};

const USDC: Address = address!("036CbD53842c5426634e7929541eC2318f3dCF7e");
const WETH: Address = address!("4200000000000000000000000000000000000006");
const ROUTER: Address = address!("94cC0AaC535CCDB3C01d6787D6413C739ae12bc4");
const VAULT: Address = address!("00000000000000000000000000000000000000Aa");
const ATTACKER: Address = address!("00000000000000000000000000000000000BAD00");
const FRIEND: Address = address!("0000000000000000000000000000000000F00D00");
const UNIT: u64 = 1_000_000;

fn usdc(n: u64) -> U256 {
    U256::from(n * UNIT)
}

fn policy() -> Policy {
    Policy {
        version: 2,
        token: USDC,
        max_per_tx: usdc(100),
        max_per_day: usdc(300),
        allowed_targets: vec![ROUTER],
        allowed_recipients: vec![FRIEND],
        allowed_selectors: vec![
            approveCall::SELECTOR.into(),
            transferCall::SELECTOR.into(),
            exactInputSingleCall::SELECTOR.into(),
        ],
        deny_unlimited_approve: true,
        allowed_tokens_out: vec![WETH],
    }
}

fn intent(target: Address, data: Vec<u8>) -> Intent {
    Intent { target, value: U256::ZERO, data: data.into(), nonce: U256::from(1), deadline: 1_790_003_600 }
}

fn swap(amount_in: U256, token_in: Address, recipient: Address) -> Intent {
    swap_to(amount_in, token_in, recipient, WETH, U256::from(1))
}

fn swap_to(amount_in: U256, token_in: Address, recipient: Address, token_out: Address, min_out: U256) -> Intent {
    let params = ExactInputSingleParams {
        tokenIn: token_in,
        tokenOut: token_out,
        fee: alloy_primitives::aliases::U24::from(500),
        recipient,
        amountIn: amount_in,
        amountOutMinimum: min_out,
        sqrtPriceLimitX96: alloy_primitives::aliases::U160::ZERO,
    };
    intent(ROUTER, exactInputSingleCall { params }.abi_encode())
}

fn input(intent: Intent, spent_before: U256) -> ProverInput {
    ProverInput { chain_id: 84532, vault: VAULT, policy: policy(), intent, spent_before, day: 20_717 }
}

fn err(i: ProverInput) -> Violation {
    check(&i).expect_err("should have been refused")
}

// ---------------------------------------------------------------- demo scenarios

#[test]
fn demo_swap_50_ok() {
    let out = check(&input(swap(usdc(50), USDC, VAULT), U256::ZERO)).unwrap();
    assert_eq!(out.spentBefore, U256::ZERO);
    assert_eq!(out.spentAfter, usdc(50));
    assert_eq!(out.day, 20_717);
    assert_eq!(out.policyHash, policy().hash());
}

#[test]
fn demo_prompt_injection_transfer_all_rejected() {
    let data = transferCall { to: ATTACKER, amount: usdc(500) }.abi_encode();
    assert_eq!(err(input(intent(USDC, data), U256::ZERO)), Violation::RecipientNotAllowed(ATTACKER));
}

#[test]
fn demo_fourth_swap_hits_daily_limit() {
    let mut spent = U256::ZERO;
    for _ in 0..3 {
        spent = check(&input(swap(usdc(100), USDC, VAULT), spent)).unwrap().spentAfter;
    }
    assert_eq!(spent, usdc(300));
    assert_eq!(
        err(input(swap(usdc(100), USDC, VAULT), spent)),
        Violation::ExceedsPerDay { after: usdc(400), max: usdc(300) }
    );
}

// ---------------------------------------------------------------- rules

#[test]
fn approve_bounded_ok_and_spends_nothing() {
    let data = approveCall { spender: ROUTER, amount: usdc(100) }.abi_encode();
    let out = check(&input(intent(USDC, data), usdc(42))).unwrap();
    assert_eq!(out.spentAfter, usdc(42));
}

#[test]
fn approve_up_to_daily_limit_ok() {
    let data = approveCall { spender: ROUTER, amount: usdc(300) }.abi_encode();
    assert!(check(&input(intent(USDC, data), U256::ZERO)).is_ok());
    let data = approveCall { spender: ROUTER, amount: usdc(300) + U256::from(1) }.abi_encode();
    assert!(matches!(err(input(intent(USDC, data), U256::ZERO)), Violation::UnlimitedApprove(_)));
}

#[test]
fn approve_unlimited_rejected() {
    let data = approveCall { spender: ROUTER, amount: U256::MAX }.abi_encode();
    assert_eq!(err(input(intent(USDC, data), U256::ZERO)), Violation::UnlimitedApprove(U256::MAX));
}

#[test]
fn approve_unlimited_ok_when_policy_allows() {
    let data = approveCall { spender: ROUTER, amount: U256::MAX }.abi_encode();
    let mut i = input(intent(USDC, data), U256::ZERO);
    i.policy.deny_unlimited_approve = false;
    assert!(check(&i).is_ok());
}

#[test]
fn approve_to_attacker_rejected() {
    let data = approveCall { spender: ATTACKER, amount: U256::from(1) }.abi_encode();
    assert_eq!(err(input(intent(USDC, data), U256::ZERO)), Violation::SpenderNotAllowed(ATTACKER));
}

#[test]
fn approve_on_other_token_rejected() {
    let data = approveCall { spender: ROUTER, amount: U256::from(1) }.abi_encode();
    assert_eq!(err(input(intent(WETH, data), U256::ZERO)), Violation::TargetNotAllowed(WETH));
}

#[test]
fn transfer_to_whitelisted_counts_as_spend() {
    let data = transferCall { to: FRIEND, amount: usdc(10) }.abi_encode();
    assert_eq!(check(&input(intent(USDC, data), U256::ZERO)).unwrap().spentAfter, usdc(10));
}

#[test]
fn swap_to_non_whitelisted_router_rejected() {
    let mut i = swap(usdc(1), USDC, VAULT);
    i.target = ATTACKER;
    assert_eq!(err(input(i, U256::ZERO)), Violation::TargetNotAllowed(ATTACKER));
}

#[test]
fn swap_output_to_attacker_rejected() {
    assert_eq!(
        err(input(swap(usdc(1), USDC, ATTACKER), U256::ZERO)),
        Violation::SwapRecipientNotVault(ATTACKER)
    );
}

#[test]
fn swap_other_token_in_rejected() {
    assert_eq!(err(input(swap(usdc(1), WETH, VAULT), U256::ZERO)), Violation::TokenNotAllowed(WETH));
}

#[test]
fn per_tx_limit() {
    assert!(check(&input(swap(usdc(100), USDC, VAULT), U256::ZERO)).is_ok());
    assert_eq!(
        err(input(swap(usdc(100) + U256::from(1), USDC, VAULT), U256::ZERO)),
        Violation::ExceedsPerTx { spend: usdc(100) + U256::from(1), max: usdc(100) }
    );
}

#[test]
fn spent_before_overflow_rejected_not_panic() {
    let e = err(input(swap(usdc(1), USDC, VAULT), U256::MAX));
    assert!(matches!(e, Violation::ExceedsPerDay { .. }));
}

#[test]
fn value_not_zero_rejected() {
    let mut i = swap(usdc(1), USDC, VAULT);
    i.value = U256::from(1);
    assert_eq!(err(input(i, U256::ZERO)), Violation::ValueNotZero);
}

#[test]
fn self_call_rejected() {
    let mut i = swap(usdc(1), USDC, VAULT);
    i.target = VAULT;
    assert_eq!(err(input(i, U256::ZERO)), Violation::SelfCall);
}

#[test]
fn selector_not_in_policy_rejected() {
    let data = transferCall { to: FRIEND, amount: U256::from(1) }.abi_encode();
    let mut i = input(intent(USDC, data), U256::ZERO);
    i.policy.allowed_selectors.retain(|s| s.0 != transferCall::SELECTOR);
    assert_eq!(err(i), Violation::SelectorNotAllowed(transferCall::SELECTOR.into()));
}

#[test]
fn unknown_selector_rejected_even_if_listed() {
    let mut i = input(intent(ROUTER, vec![0xde, 0xad, 0xbe, 0xef]), U256::ZERO);
    i.policy.allowed_selectors.push(fixed_bytes!("deadbeef"));
    assert_eq!(err(i), Violation::UnknownSelector(fixed_bytes!("deadbeef")));
}

#[test]
fn short_calldata_rejected() {
    assert_eq!(err(input(intent(USDC, vec![0x09, 0x5e]), U256::ZERO)), Violation::CalldataTooShort);
}

#[test]
fn trailing_bytes_rejected() {
    let mut data = transferCall { to: FRIEND, amount: U256::from(1) }.abi_encode();
    data.push(0);
    assert!(matches!(err(input(intent(USDC, data), U256::ZERO)), Violation::BadCalldataLength { .. }));
}

#[test]
fn dirty_address_padding_rejected() {
    let mut data = transferCall { to: FRIEND, amount: U256::from(1) }.abi_encode();
    data[4] = 0xff; // the upper bytes of an address word must be zero
    assert_eq!(err(input(intent(USDC, data), U256::ZERO)), Violation::BadCalldataEncoding);
}

#[test]
fn unsupported_version_rejected() {
    let mut i = input(swap(usdc(1), USDC, VAULT), U256::ZERO);
    i.policy.version = 3;
    assert_eq!(err(i), Violation::UnsupportedVersion(3));
}

// ---------------------------------------------------------------- hashing

#[test]
fn intent_hash_binds_chain_and_vault() {
    let i = swap(usdc(1), USDC, VAULT);
    assert_ne!(i.hash(84532, VAULT), i.hash(1, VAULT));
    assert_ne!(i.hash(84532, VAULT), i.hash(84532, ATTACKER));
}

#[test]
fn policy_json_matches_docs_example() {
    let raw = include_str!("../../fixtures/policy.example.json");
    let p: Policy = serde_json::from_str(raw).unwrap();
    assert_eq!(p.max_per_tx, usdc(100));
    assert_eq!(p.allowed_selectors, vec![fixed_bytes!("095ea7b3"), fixed_bytes!("04e45aaf")]);
}

// ---------------------------------------------------------------- policy v2

#[test]
fn swap_into_unlisted_token_rejected() {
    let junk = address!("000000000000000000000000000000000000dEaD");
    assert_eq!(
        err(input(swap_to(usdc(1), USDC, VAULT, junk, U256::from(1)), U256::ZERO)),
        Violation::TokenOutNotAllowed(junk)
    );
}

#[test]
fn swap_without_min_out_rejected() {
    assert_eq!(err(input(swap_to(usdc(1), USDC, VAULT, WETH, U256::ZERO), U256::ZERO)), Violation::NoMinOut);
}

#[test]
fn v1_policy_rejected() {
    let mut i = input(swap(usdc(1), USDC, VAULT), U256::ZERO);
    i.policy.version = 1;
    assert_eq!(err(i), Violation::UnsupportedVersion(1));
}

#[test]
fn tokens_out_change_policy_hash() {
    let mut p = policy();
    let h = p.hash();
    p.allowed_tokens_out.push(USDC);
    assert_ne!(h, p.hash());
}
