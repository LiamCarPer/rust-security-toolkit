use rust_security_toolkit::patterns::{detect_patterns_with_config, parse_pattern_config};
use rust_security_toolkit::types::*;

const FEE_PAYER: &str = "FeePayer111111111111111111111111111111111";
const WALLET_A: &str = "WalletA111111111111111111111111111111";
const WALLET_B: &str = "WalletB111111111111111111111111111111";
const DELEGATE: &str = "Delegate11111111111111111111111111111";

fn named(pubkey: &str, name: &str, is_signer: bool) -> MappedAccount {
    MappedAccount {
        name: Some(name.to_string()),
        pubkey: pubkey.to_string(),
        account_index: 0,
        is_signer,
        is_writable: true,
    }
}

fn instruction(
    index: u8,
    program_id: &str,
    name: &str,
    accounts: Vec<MappedAccount>,
    data: serde_json::Value,
) -> DecodedInstruction {
    DecodedInstruction {
        index,
        program_id: program_id.to_string(),
        program_name: String::new(),
        instruction_name: Some(name.to_string()),
        accounts,
        data,
        raw_data_hex: String::new(),
        token_amount: None,
    }
}

fn report(instructions: Vec<DecodedInstruction>) -> TransactionReport {
    TransactionReport {
        status: "OK".into(),
        fee_payer: FEE_PAYER.into(),
        signatures: Vec::new(),
        recent_blockhash: "11111111111111111111111111111111".into(),
        message_version: None,
        accounts: Vec::new(),
        instructions,
        address_lookup_tables: Vec::new(),
        compute_budget: None,
        risk_flags: Vec::new(),
        simulation: None,
        warnings: Vec::new(),
        signature_verification: Vec::new(),
        inner_instructions: Vec::new(),
        balance_changes_sol: Vec::new(),
        token_balance_changes: Vec::new(),
    }
}

fn approve_then_transfer_report() -> TransactionReport {
    report(vec![
        instruction(
            0,
            TOKEN_PROGRAM_ID,
            "Approve",
            vec![named("SRC_A", "source", true), named(DELEGATE, "delegate", false), named(WALLET_A, "owner", true)],
            serde_json::json!({"amount": 1000}),
        ),
        instruction(
            1,
            TOKEN_PROGRAM_ID,
            "Transfer",
            vec![
                named("SRC_B", "source", false),
                named(WALLET_B, "destination", false),
                named(DELEGATE, "authority", true),
            ],
            serde_json::json!({"amount": 1000}),
        ),
    ])
}

#[test]
fn parse_pattern_config_accepts_empty_object() {
    let config = parse_pattern_config("{}").unwrap();
    assert!(config.rules.is_empty());
}

#[test]
fn parse_pattern_config_accepts_valid_overrides() {
    let config = parse_pattern_config(
        r#"{"rules":{"approve_then_transfer":{"severity":"critical"},"nonsigner_transfer_authority":{"enabled":false}}}"#,
    )
    .unwrap();
    assert_eq!(config.rules.get("approve_then_transfer").unwrap().severity.as_deref(), Some("critical"));
    assert_eq!(config.rules.get("nonsigner_transfer_authority").unwrap().enabled, Some(false));
}

#[test]
fn parse_pattern_config_rejects_unknown_rule() {
    let err = parse_pattern_config(r#"{"rules":{"does_not_exist":{"severity":"warning"}}}"#).unwrap_err();
    assert!(err.to_string().contains("does_not_exist"), "err: {}", err);
}

#[test]
fn parse_pattern_config_rejects_bad_severity() {
    let err = parse_pattern_config(r#"{"rules":{"approve_then_transfer":{"severity":"catastrophic"}}}"#).unwrap_err();
    assert!(err.to_string().contains("catastrophic"), "err: {}", err);
}

#[test]
fn parse_pattern_config_rejects_malformed_json() {
    assert!(parse_pattern_config("not json").is_err());
}

#[test]
fn detect_with_critical_override_emits_critical() {
    let config = parse_pattern_config(r#"{"rules":{"approve_then_transfer":{"severity":"critical"}}}"#).unwrap();
    let flags = detect_patterns_with_config(&approve_then_transfer_report(), &config);
    assert_eq!(flags.len(), 1, "flags: {:?}", flags);
    assert_eq!(flags[0].severity, RiskSeverity::Critical);
    assert_eq!(flags[0].instruction_index, Some(1));
}

#[test]
fn detect_with_disabled_rule_emits_nothing() {
    let config = parse_pattern_config(r#"{"rules":{"approve_then_transfer":{"enabled":false}}}"#).unwrap();
    let flags = detect_patterns_with_config(&approve_then_transfer_report(), &config);
    assert!(flags.is_empty(), "flags: {:?}", flags);
}

#[test]
fn detect_with_default_config_matches_default_severities() {
    let flags = detect_patterns_with_config(&approve_then_transfer_report(), &PatternConfig::default());
    assert_eq!(flags.len(), 1, "flags: {:?}", flags);
    assert_eq!(flags[0].severity, RiskSeverity::Warning);
}

#[test]
fn detect_with_unknown_rule_key_in_parsed_config_is_impossible() {
    let err = parse_pattern_config(r#"{"rules":{"not_a_rule":{"severity":"warning"}}}"#).unwrap_err();
    assert!(err.to_string().contains("not_a_rule"), "err: {}", err);
}

#[test]
fn mixed_overrides_apply_per_rule() {
    let mixed_report = report(vec![
        instruction(
            0,
            TOKEN_PROGRAM_ID,
            "Approve",
            vec![named("SRC_A", "source", true), named(DELEGATE, "delegate", false), named(WALLET_A, "owner", true)],
            serde_json::json!({"amount": 1000}),
        ),
        instruction(
            1,
            TOKEN_PROGRAM_ID,
            "Transfer",
            vec![
                named("SRC_B", "source", false),
                named(FEE_PAYER, "destination", false),
                named(DELEGATE, "authority", true),
            ],
            serde_json::json!({"amount": 1000}),
        ),
    ]);
    let config = parse_pattern_config(
        r#"{"rules":{"approve_then_transfer":{"severity":"critical"},"fee_payer_recipient":{"enabled":false}}}"#,
    )
    .unwrap();
    let flags = detect_patterns_with_config(&mixed_report, &config);
    assert_eq!(flags.len(), 1, "flags: {:?}", flags);
    assert_eq!(flags[0].severity, RiskSeverity::Critical);
    assert_eq!(flags[0].instruction_index, Some(1));
    let default_flags = detect_patterns_with_config(&mixed_report, &PatternConfig::default());
    assert_eq!(default_flags.len(), 2, "flags: {:?}", default_flags);
}
