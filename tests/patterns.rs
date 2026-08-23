use rust_security_toolkit::patterns::detect_patterns;
use rust_security_toolkit::types::*;

const FEE_PAYER: &str = "FeePayer111111111111111111111111111111111";
const WALLET_A: &str = "WalletA111111111111111111111111111111";
const WALLET_B: &str = "WalletB111111111111111111111111111111";
const SHARED_DEST: &str = "SharedDest1111111111111111111111111111";
const DELEGATE: &str = "Delegate11111111111111111111111111111";
const MINT_KEY: &str = "MintKey111111111111111111111111111111";
const NEW_AUTHORITY: &str = "NewAuth111111111111111111111111111111";
const OTHER_AUTHORITY: &str = "OtherAuth11111111111111111111111111111";

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
        oracle_feeds: Vec::new(),
        idl_source: None,
    }
}

fn inner_instruction(
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

fn report_with_inner(
    instructions: Vec<DecodedInstruction>,
    inner_instructions: Vec<InnerInstruction>,
) -> TransactionReport {
    let mut report = report(instructions);
    report.inner_instructions = inner_instructions;
    report
}

fn single_flag(flags: &[RiskFlag]) -> &RiskFlag {
    assert_eq!(flags.len(), 1, "expected exactly one flag, got {:?}", flags);
    &flags[0]
}

#[test]
fn empty_report_produces_no_flags() {
    assert!(detect_patterns(&report(Vec::new())).is_empty());
}

// ── Approve → transfer ───────────────────────────────────────────────────────

#[test]
fn approve_then_transfer_via_delegated_authority_is_flagged() {
    let flags = detect_patterns(&report(vec![
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
    ]));
    let flag = single_flag(&flags);
    assert_eq!(flag.severity, RiskSeverity::Warning);
    assert_eq!(flag.category, RiskCategory::PatternDetection);
    assert_eq!(flag.instruction_index, Some(1));
    assert!(flag.message.contains("Approve"), "message: {}", flag.message);
    assert!(flag.message.contains(DELEGATE), "message: {}", flag.message);
}

#[test]
fn approve_checked_then_transfer_checked_via_delegated_authority_is_flagged() {
    let flags = detect_patterns(&report(vec![
        instruction(
            0,
            TOKEN_2022_PROGRAM_ID,
            "ApproveChecked",
            vec![
                named("SRC_A", "source", true),
                named(MINT_KEY, "mint", false),
                named(DELEGATE, "delegate", false),
                named(WALLET_A, "owner", true),
            ],
            serde_json::json!({"amount": 1000, "decimals": 6}),
        ),
        instruction(
            1,
            TOKEN_2022_PROGRAM_ID,
            "TransferChecked",
            vec![
                named("SRC_B", "source", false),
                named(MINT_KEY, "mint", false),
                named(WALLET_B, "destination", false),
                named(DELEGATE, "authority", true),
            ],
            serde_json::json!({"amount": 1000, "decimals": 6}),
        ),
    ]));
    let flag = single_flag(&flags);
    assert_eq!(flag.severity, RiskSeverity::Warning);
    assert_eq!(flag.instruction_index, Some(1));
}

#[test]
fn approve_then_transfer_with_different_authority_is_not_flagged() {
    let flags = detect_patterns(&report(vec![
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
                named(OTHER_AUTHORITY, "authority", true),
            ],
            serde_json::json!({"amount": 1000}),
        ),
    ]));
    assert!(flags.is_empty(), "unexpected flags: {:?}", flags);
}

#[test]
fn transfer_without_prior_approve_is_not_flagged() {
    let flags = detect_patterns(&report(vec![instruction(
        0,
        TOKEN_PROGRAM_ID,
        "Transfer",
        vec![
            named("SRC_B", "source", false),
            named(WALLET_B, "destination", false),
            named(DELEGATE, "authority", true),
        ],
        serde_json::json!({"amount": 1000}),
    )]));
    assert!(flags.is_empty(), "unexpected flags: {:?}", flags);
}

#[test]
fn approve_then_non_token_transfer_is_not_flagged() {
    let flags = detect_patterns(&report(vec![
        instruction(
            0,
            TOKEN_PROGRAM_ID,
            "Approve",
            vec![named("SRC_A", "source", true), named(DELEGATE, "delegate", false), named(WALLET_A, "owner", true)],
            serde_json::json!({"amount": 1000}),
        ),
        instruction(
            1,
            SYSTEM_PROGRAM_ID,
            "Transfer",
            vec![named(DELEGATE, "from", true), named(WALLET_B, "to", false)],
            serde_json::json!({"lamports": 1000}),
        ),
    ]));
    assert!(flags.is_empty(), "unexpected flags: {:?}", flags);
}

// ── Non-signer transfer authority ───────────────────────────────────────────

#[test]
fn transfer_checked_with_non_signing_authority_is_flagged() {
    let flags = detect_patterns(&report(vec![instruction(
        7,
        TOKEN_PROGRAM_ID,
        "TransferChecked",
        vec![
            named("SRC_B", "source", false),
            named(MINT_KEY, "mint", false),
            named(WALLET_B, "destination", false),
            named(WALLET_A, "authority", false),
        ],
        serde_json::json!({"amount": 1000, "decimals": 6}),
    )]));
    let flag = single_flag(&flags);
    assert_eq!(flag.severity, RiskSeverity::Warning);
    assert_eq!(flag.instruction_index, Some(7));
    assert!(flag.message.contains("does not sign"), "message: {}", flag.message);
    assert!(flag.message.contains("#7"), "message: {}", flag.message);
}

#[test]
fn system_transfer_with_seed_with_non_signing_from_is_flagged() {
    let flags = detect_patterns(&report(vec![instruction(
        0,
        SYSTEM_PROGRAM_ID,
        "TransferWithSeed",
        vec![named("FROM_PK", "from", false), named("BASE_PK", "from_base", true), named(WALLET_B, "to", false)],
        serde_json::json!({"lamports": 1000, "from_seed": "seed", "from_owner": "11111111111111111111111111111111"}),
    )]));
    let flag = single_flag(&flags);
    assert_eq!(flag.severity, RiskSeverity::Warning);
    assert_eq!(flag.instruction_index, Some(0));
}

#[test]
fn transfer_checked_with_signing_authority_is_not_flagged() {
    let flags = detect_patterns(&report(vec![instruction(
        0,
        TOKEN_PROGRAM_ID,
        "TransferChecked",
        vec![
            named("SRC_B", "source", false),
            named(MINT_KEY, "mint", false),
            named(WALLET_B, "destination", false),
            named(WALLET_A, "authority", true),
        ],
        serde_json::json!({"amount": 1000, "decimals": 6}),
    )]));
    assert!(flags.is_empty(), "unexpected flags: {:?}", flags);
}

#[test]
fn transfer_without_authority_account_is_not_flagged() {
    let flags = detect_patterns(&report(vec![instruction(
        0,
        TOKEN_PROGRAM_ID,
        "Transfer",
        vec![named("SRC_B", "source", false), named(WALLET_B, "destination", false)],
        serde_json::json!({"amount": 1000}),
    )]));
    assert!(flags.is_empty(), "unexpected flags: {:?}", flags);
}

// ── Fee payer as recipient ──────────────────────────────────────────────────

#[test]
fn fee_payer_as_mint_destination_is_flagged() {
    let flags = detect_patterns(&report(vec![instruction(
        3,
        TOKEN_PROGRAM_ID,
        "MintTo",
        vec![named(MINT_KEY, "mint", false), named(FEE_PAYER, "to", false), named(WALLET_A, "authority", true)],
        serde_json::json!({"amount": 1000}),
    )]));
    let flag = single_flag(&flags);
    assert_eq!(flag.severity, RiskSeverity::Info);
    assert_eq!(flag.instruction_index, Some(3));
    assert!(flag.message.contains(FEE_PAYER), "message: {}", flag.message);
}

#[test]
fn fee_payer_as_system_recipient_is_flagged() {
    let flags = detect_patterns(&report(vec![instruction(
        0,
        SYSTEM_PROGRAM_ID,
        "Transfer",
        vec![named(WALLET_A, "from", true), named(FEE_PAYER, "to", false)],
        serde_json::json!({"lamports": 1000}),
    )]));
    let flag = single_flag(&flags);
    assert_eq!(flag.severity, RiskSeverity::Info);
    assert_eq!(flag.instruction_index, Some(0));
}

#[test]
fn fee_payer_not_a_recipient_is_not_flagged() {
    let flags = detect_patterns(&report(vec![instruction(
        0,
        TOKEN_PROGRAM_ID,
        "MintTo",
        vec![named(MINT_KEY, "mint", false), named(WALLET_B, "to", false), named(WALLET_A, "authority", true)],
        serde_json::json!({"amount": 1000}),
    )]));
    assert!(flags.is_empty(), "unexpected flags: {:?}", flags);
}

// ── Repeated destination ────────────────────────────────────────────────────

#[test]
fn repeated_destination_across_transfers_is_flagged() {
    let transfers = vec![
        instruction(
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
        instruction(
            2,
            TOKEN_PROGRAM_ID,
            "Transfer",
            vec![
                named("SRC_B", "source", false),
                named(SHARED_DEST, "destination", false),
                named(WALLET_B, "authority", true),
            ],
            serde_json::json!({"amount": 2000}),
        ),
    ];
    let flags = detect_patterns(&report(transfers));
    let flag = single_flag(&flags);
    assert_eq!(flag.severity, RiskSeverity::Info);
    assert_eq!(flag.instruction_index, Some(0));
    assert!(flag.message.contains("#2"), "message: {}", flag.message);
    assert!(flag.message.contains(SHARED_DEST), "message: {}", flag.message);
}

#[test]
fn distinct_destinations_are_not_flagged() {
    let flags = detect_patterns(&report(vec![
        instruction(
            0,
            TOKEN_PROGRAM_ID,
            "Transfer",
            vec![
                named("SRC_A", "source", false),
                named(WALLET_A, "destination", false),
                named(DELEGATE, "authority", true),
            ],
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
            serde_json::json!({"amount": 2000}),
        ),
    ]));
    assert!(flags.is_empty(), "unexpected flags: {:?}", flags);
}

// ── Mint authority takeover + mint ──────────────────────────────────────────

#[test]
fn mint_authority_takeover_with_same_authority_mint_is_flagged() {
    let flags = detect_patterns(&report(vec![
        instruction(
            0,
            TOKEN_PROGRAM_ID,
            "SetAuthority",
            vec![named(MINT_KEY, "account", false), named(WALLET_A, "current_authority", true)],
            serde_json::json!({"authority_type": 0, "new_authority": NEW_AUTHORITY}),
        ),
        instruction(
            1,
            TOKEN_PROGRAM_ID,
            "MintTo",
            vec![named(MINT_KEY, "mint", false), named(WALLET_B, "to", false), named(NEW_AUTHORITY, "authority", true)],
            serde_json::json!({"amount": 1000}),
        ),
    ]));
    let flag = single_flag(&flags);
    assert_eq!(flag.severity, RiskSeverity::Warning);
    assert_eq!(flag.instruction_index, Some(0));
    assert!(flag.message.contains("SetAuthority"), "message: {}", flag.message);
}

#[test]
fn mint_authority_takeover_with_unrelated_mint_authority_is_not_flagged() {
    let flags = detect_patterns(&report(vec![
        instruction(
            0,
            TOKEN_PROGRAM_ID,
            "SetAuthority",
            vec![named(MINT_KEY, "account", false), named(WALLET_A, "current_authority", true)],
            serde_json::json!({"authority_type": 0, "new_authority": NEW_AUTHORITY}),
        ),
        instruction(
            1,
            TOKEN_PROGRAM_ID,
            "MintToChecked",
            vec![
                named(MINT_KEY, "mint", false),
                named(WALLET_B, "to", false),
                named(OTHER_AUTHORITY, "authority", true),
            ],
            serde_json::json!({"amount": 1000, "decimals": 6}),
        ),
    ]));
    assert!(flags.is_empty(), "unexpected flags: {:?}", flags);
}

#[test]
fn mint_authority_takeover_of_different_mint_is_not_flagged() {
    let flags = detect_patterns(&report(vec![
        instruction(
            0,
            TOKEN_PROGRAM_ID,
            "SetAuthority",
            vec![named(MINT_KEY, "account", false), named(WALLET_A, "current_authority", true)],
            serde_json::json!({"authority_type": 0, "new_authority": NEW_AUTHORITY}),
        ),
        instruction(
            1,
            TOKEN_PROGRAM_ID,
            "MintTo",
            vec![
                named("OtherMint11111111111111111111111111111", "mint", false),
                named(WALLET_B, "to", false),
                named(NEW_AUTHORITY, "authority", true),
            ],
            serde_json::json!({"amount": 1000}),
        ),
    ]));
    assert!(flags.is_empty(), "unexpected flags: {:?}", flags);
}

#[test]
fn non_mint_authority_type_change_is_not_flagged() {
    let flags = detect_patterns(&report(vec![
        instruction(
            0,
            TOKEN_PROGRAM_ID,
            "SetAuthority",
            vec![named(MINT_KEY, "account", false), named(WALLET_A, "current_authority", true)],
            serde_json::json!({"authority_type": 1, "new_authority": NEW_AUTHORITY}),
        ),
        instruction(
            1,
            TOKEN_PROGRAM_ID,
            "MintTo",
            vec![named(MINT_KEY, "mint", false), named(WALLET_B, "to", false), named(NEW_AUTHORITY, "authority", true)],
            serde_json::json!({"amount": 1000}),
        ),
    ]));
    assert!(flags.is_empty(), "unexpected flags: {:?}", flags);
}

#[test]
fn inner_instructions_present_do_not_break_top_level_rules() {
    let flags = detect_patterns(&report_with_inner(
        vec![
            instruction(
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
        ],
        vec![inner_instruction(
            0,
            0,
            SYSTEM_PROGRAM_ID,
            "CreateAccount",
            vec![named(WALLET_A, "from", true), named("NewAcct11111111111111111111111111111", "to", false)],
            serde_json::json!({"lamports": 1000, "space": 100}),
        )],
    ));
    let flag = single_flag(&flags);
    assert_eq!(flag.severity, RiskSeverity::Warning);
    assert_eq!(flag.category, RiskCategory::PatternDetection);
    assert_eq!(flag.instruction_index, Some(1));
    assert!(flag.message.contains("Approve"), "message: {}", flag.message);
    assert!(flag.message.contains(DELEGATE), "message: {}", flag.message);
    assert!(!flag.message.contains("inner #"), "message: {}", flag.message);
}
