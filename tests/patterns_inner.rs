use rust_security_toolkit::patterns::detect_patterns;
use rust_security_toolkit::types::*;

const FEE_PAYER: &str = "FeePayer111111111111111111111111111111111";
const WALLET_A: &str = "WalletA111111111111111111111111111111";
const WALLET_B: &str = "WalletB111111111111111111111111111111";
const SHARED_DEST: &str = "SharedDest1111111111111111111111111111";
const DELEGATE: &str = "Delegate11111111111111111111111111111";
const MINT_KEY: &str = "MintKey111111111111111111111111111111";
const NEW_AUTHORITY: &str = "NewAuth111111111111111111111111111111";
const UNKNOWN_PROGRAM: &str = "UnknownProg111111111111111111111111111111";

fn named(pubkey: &str, name: &str, is_signer: bool) -> MappedAccount {
    MappedAccount {
        name: Some(name.to_string()),
        pubkey: pubkey.to_string(),
        account_index: 0,
        is_signer,
        is_writable: true,
    }
}

fn instruction(index: u8, program_id: &str, name: &str, accounts: Vec<MappedAccount>) -> DecodedInstruction {
    DecodedInstruction {
        index,
        program_id: program_id.to_string(),
        program_name: String::new(),
        instruction_name: Some(name.to_string()),
        accounts,
        data: serde_json::json!({}),
        raw_data_hex: String::new(),
        token_amount: None,
    }
}

fn inner(
    inner_index: u32,
    parent_instruction_index: u8,
    program_id: &str,
    name: &str,
    accounts: Vec<MappedAccount>,
    data: serde_json::Value,
) -> InnerInstruction {
    InnerInstruction {
        inner_index,
        parent_instruction_index,
        program_id: program_id.to_string(),
        program_name: String::new(),
        instruction_name: Some(name.to_string()),
        accounts,
        data,
        raw_data_hex: String::new(),
        token_amount: None,
    }
}

fn unknown(index: u8) -> DecodedInstruction {
    instruction(index, UNKNOWN_PROGRAM, "Custom", Vec::new())
}

fn report(instructions: Vec<DecodedInstruction>, inner_instructions: Vec<InnerInstruction>) -> TransactionReport {
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
        inner_instructions,
    }
}

fn single_flag(flags: &[RiskFlag]) -> &RiskFlag {
    assert_eq!(flags.len(), 1, "expected exactly one flag, got {:?}", flags);
    &flags[0]
}

#[test]
fn approve_then_transfer_both_inner_same_parent() {
    let flags = detect_patterns(&report(
        vec![unknown(0)],
        vec![
            inner(
                0,
                0,
                TOKEN_PROGRAM_ID,
                "Approve",
                vec![
                    named("SRC_A", "source", true),
                    named(DELEGATE, "delegate", false),
                    named(WALLET_A, "owner", true),
                ],
                serde_json::json!({"amount": 1000}),
            ),
            inner(
                1,
                0,
                TOKEN_PROGRAM_ID,
                "Transfer",
                vec![
                    named("SRC_B", "source", false),
                    named(WALLET_B, "destination", false),
                    named(DELEGATE, "authority", true),
                ],
                serde_json::json!({"amount": 1000}),
            ),
        ],
    ));
    let flag = single_flag(&flags);
    assert_eq!(flag.severity, RiskSeverity::Warning);
    assert_eq!(flag.category, RiskCategory::PatternDetection);
    assert_eq!(flag.instruction_index, Some(0));
    assert!(flag.message.contains("inner #1"), "message: {}", flag.message);
    assert!(flag.message.contains("inner #0"), "message: {}", flag.message);
}

#[test]
fn approve_then_transfer_cross_parents_not_flagged() {
    let flags = detect_patterns(&report(
        vec![unknown(0), unknown(1)],
        vec![
            inner(
                0,
                0,
                TOKEN_PROGRAM_ID,
                "Approve",
                vec![
                    named("SRC_A", "source", true),
                    named(DELEGATE, "delegate", false),
                    named(WALLET_A, "owner", true),
                ],
                serde_json::json!({"amount": 1000}),
            ),
            inner(
                0,
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
        ],
    ));
    assert!(flags.is_empty(), "unexpected flags: {:?}", flags);
}

#[test]
fn approve_top_level_transfer_inner_same_parent() {
    let flags = detect_patterns(&report(
        vec![instruction(
            0,
            TOKEN_PROGRAM_ID,
            "Approve",
            vec![named("SRC_A", "source", true), named(DELEGATE, "delegate", false), named(WALLET_A, "owner", true)],
        )],
        vec![inner(
            0,
            0,
            TOKEN_PROGRAM_ID,
            "Transfer",
            vec![
                named("SRC_B", "source", false),
                named(WALLET_B, "destination", false),
                named(DELEGATE, "authority", true),
            ],
            serde_json::json!({"amount": 1000}),
        )],
    ));
    let flag = single_flag(&flags);
    assert_eq!(flag.severity, RiskSeverity::Warning);
    assert_eq!(flag.category, RiskCategory::PatternDetection);
    assert_eq!(flag.instruction_index, Some(0));
    assert!(flag.message.contains("(inner #0 of instruction #0)"), "message: {}", flag.message);
}

#[test]
fn approve_inner_transfer_other_parent_not_flagged() {
    let flags = detect_patterns(&report(
        vec![
            unknown(0),
            instruction(
                1,
                TOKEN_PROGRAM_ID,
                "Transfer",
                vec![
                    named("SRC_B", "source", false),
                    named(WALLET_B, "destination", false),
                    named(DELEGATE, "authority", true),
                ],
            ),
        ],
        vec![inner(
            0,
            0,
            TOKEN_PROGRAM_ID,
            "Approve",
            vec![named("SRC_A", "source", true), named(DELEGATE, "delegate", false), named(WALLET_A, "owner", true)],
            serde_json::json!({"amount": 1000}),
        )],
    ));
    assert!(flags.is_empty(), "unexpected flags: {:?}", flags);
}

#[test]
fn mint_takeover_inner_same_parent() {
    let flags = detect_patterns(&report(
        vec![unknown(0)],
        vec![
            inner(
                0,
                0,
                TOKEN_PROGRAM_ID,
                "SetAuthority",
                vec![named(MINT_KEY, "account", false), named(WALLET_A, "current_authority", true)],
                serde_json::json!({"authority_type": 0, "new_authority": NEW_AUTHORITY}),
            ),
            inner(
                1,
                0,
                TOKEN_PROGRAM_ID,
                "MintToChecked",
                vec![
                    named(MINT_KEY, "mint", false),
                    named(WALLET_B, "to", false),
                    named(NEW_AUTHORITY, "authority", true),
                ],
                serde_json::json!({"amount": 1000, "decimals": 6}),
            ),
        ],
    ));
    let flag = single_flag(&flags);
    assert_eq!(flag.severity, RiskSeverity::Warning);
    assert_eq!(flag.category, RiskCategory::PatternDetection);
    assert_eq!(flag.instruction_index, Some(0));
    assert!(flag.message.contains("takeover"), "message: {}", flag.message);
}

#[test]
fn fee_payer_recipient_inner() {
    let flags = detect_patterns(&report(
        vec![unknown(0)],
        vec![inner(
            0,
            0,
            TOKEN_PROGRAM_ID,
            "Transfer",
            vec![
                named("SRC_B", "source", false),
                named(FEE_PAYER, "destination", false),
                named(WALLET_A, "authority", true),
            ],
            serde_json::json!({"amount": 1000}),
        )],
    ));
    let flag = single_flag(&flags);
    assert_eq!(flag.severity, RiskSeverity::Info);
    assert_eq!(flag.category, RiskCategory::PatternDetection);
    assert_eq!(flag.instruction_index, Some(0));
    assert!(flag.message.contains(FEE_PAYER), "message: {}", flag.message);
}

#[test]
fn repeated_destination_inner() {
    let flags = detect_patterns(&report(
        vec![unknown(0), unknown(1)],
        vec![
            inner(
                0,
                0,
                TOKEN_PROGRAM_ID,
                "Transfer",
                vec![
                    named("SRC_A", "source", false),
                    named(SHARED_DEST, "destination", false),
                    named(WALLET_A, "authority", true),
                ],
                serde_json::json!({"amount": 1000}),
            ),
            inner(
                1,
                1,
                TOKEN_PROGRAM_ID,
                "Transfer",
                vec![
                    named("SRC_B", "source", false),
                    named(SHARED_DEST, "destination", false),
                    named(WALLET_B, "authority", true),
                ],
                serde_json::json!({"amount": 2000}),
            ),
        ],
    ));
    let flag = single_flag(&flags);
    assert_eq!(flag.severity, RiskSeverity::Info);
    assert_eq!(flag.category, RiskCategory::PatternDetection);
    assert_eq!(flag.instruction_index, Some(0));
    assert!(flag.message.contains(SHARED_DEST), "message: {}", flag.message);
    assert!(flag.message.contains("receives funds in multiple"), "message: {}", flag.message);
}

#[test]
fn empty_inner_matches_top_level_behavior() {
    let top_level = vec![
        instruction(
            0,
            TOKEN_PROGRAM_ID,
            "Approve",
            vec![named("SRC_A", "source", true), named(DELEGATE, "delegate", false), named(WALLET_A, "owner", true)],
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
        ),
    ];
    let with_empty_inners = report(top_level.clone(), Vec::new());
    let flags = detect_patterns(&with_empty_inners);
    let expected = detect_patterns(&report(top_level, Vec::new()));
    assert_eq!(flags.len(), expected.len(), "flags: {:?} vs {:?}", flags, expected);
    assert_eq!(flags.len(), 1, "flags: {:?}", flags);
    assert_eq!(flags[0].instruction_index, Some(1));
}
