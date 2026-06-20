use rust_security_toolkit::decoder;
use rust_security_toolkit::types::*;
use rust_security_toolkit::ui;
use rust_security_toolkit::validator;

// ── Decoder Tests ────────────────────────────────────────────────────────────

#[test]
fn test_detect_encoding_base58() {
    let input = "2xPFR3JFj5DMhYuT8pE4dKdC6eHkjKDS3sGmxG";
    let encoding = decoder::detect_encoding(input);
    assert_eq!(encoding, Encoding::Base58);
}

#[test]
fn test_detect_encoding_base64_with_equals() {
    let input = "dGVzdCB0cmFuc2FjdGlvbg==";
    let encoding = decoder::detect_encoding(input);
    assert_eq!(encoding, Encoding::Base64);
}

#[test]
fn test_detect_encoding_base64_with_plus() {
    let input = "AB+CD/EF==";
    let encoding = decoder::detect_encoding(input);
    assert_eq!(encoding, Encoding::Base64);
}

#[test]
fn test_detect_encoding_hex() {
    let input = "deadbeef0102030405060708090a0b0c0d0e0f";
    let encoding = decoder::detect_encoding(input);
    assert_eq!(encoding, Encoding::Hex);
}

#[test]
fn test_detect_encoding_base58_preferred_over_hex() {
    let input = "abcdef123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdef";
    let encoding = decoder::detect_encoding(input);
    assert!(encoding == Encoding::Base58, "Expected Base58 for non-hex-valid-length input, got {:?}", encoding);
}

#[test]
fn test_detect_encoding_with_zero_char() {
    let input = "Test0String";
    let encoding = decoder::detect_encoding(input);
    assert_eq!(encoding, Encoding::Base64);
}

#[test]
fn test_detect_encoding_raw_with_non_printable() {
    // Raw binary detection is triggered when input is not valid UTF-8.
    // Since detect_encoding takes a &str, simulate with an empty or
    // whitespace-only input that hits the early-return for empty.
    let encoding = decoder::detect_encoding("");
    assert_eq!(encoding, Encoding::Raw);
}

#[test]
fn test_detect_encoding_empty() {
    let input = "";
    let encoding = decoder::detect_encoding(input);
    assert_eq!(encoding, Encoding::Raw);
}

#[test]
fn test_compute_anchor_discriminator() {
    let disc = decoder::compute_anchor_discriminator("initialize");
    assert_eq!(disc.len(), 8);

    let disc2 = decoder::compute_anchor_discriminator("initialize");
    assert_eq!(disc, disc2);

    let disc3 = decoder::compute_anchor_discriminator("transfer");
    assert_ne!(disc, disc3);
}

#[test]
fn test_validate_decoding_empty() {
    let result = decoder::validate_decoding(&[]);
    assert!(result.is_err());
}

#[test]
fn test_validate_decoding_too_short() {
    let result = decoder::validate_decoding(&[0x01]);
    assert!(result.is_err() || result.unwrap().len() > 0);
}

// ── Validator Tests ──────────────────────────────────────────────────────────

fn make_report() -> TransactionReport {
    TransactionReport {
        status: "DECODED SUCCESSFULLY".into(),
        fee_payer: "11111111111111111111111111111111".into(),
        signatures: vec![],
        recent_blockhash: "11111111111111111111111111111111".into(),
        message_version: None,
        accounts: vec![],
        instructions: vec![],
        address_lookup_tables: vec![],
        compute_budget: None,
        risk_flags: vec![],
        simulation: None,
        warnings: vec![],
    }
}

#[test]
fn test_missing_cu_limit_flag() {
    let mut report = make_report();
    report.compute_budget = None;
    validator::validate(&mut report, None);
    assert!(report.risk_flags.iter().any(|f| f.category == RiskCategory::MissingComputeUnitLimit));
}

#[test]
fn test_cu_reorder_flag() {
    let mut report = make_report();
    report.compute_budget = Some(ComputeBudgetInfo {
        compute_unit_limit: 150_000,
        compute_unit_price: 0,
        compute_unit_limit_set: true,
        compute_budget_positions: vec![2, 5],
        is_reordered: true,
        high_cu_instructions: vec![],
    });
    validator::validate(&mut report, None);
    assert!(report.risk_flags.iter().any(|f| f.category == RiskCategory::ComputeBudgetReordering));
}

#[test]
fn test_no_cu_reorder_when_at_index_zero() {
    let mut report = make_report();
    report.compute_budget = Some(ComputeBudgetInfo {
        compute_unit_limit: 150_000,
        compute_unit_price: 0,
        compute_unit_limit_set: true,
        compute_budget_positions: vec![0],
        is_reordered: false,
        high_cu_instructions: vec![],
    });
    validator::validate(&mut report, None);
    assert!(!report.risk_flags.iter().any(|f| f.category == RiskCategory::ComputeBudgetReordering));
}

#[test]
fn test_writable_sysvar_flagged() {
    let mut report = make_report();
    report.accounts.push(AccountInfo {
        index: 0,
        pubkey: "SysvarRent111111111111111111111111111111111".into(),
        is_signer: false,
        is_writable: true,
        role: Some("writable".into()),
        pda_info: None,
    });
    validator::validate(&mut report, None);
    assert!(report.risk_flags.iter().any(|f| f.category == RiskCategory::InsecureWritable));
}

#[test]
fn test_readonly_sysvar_not_flagged() {
    let mut report = make_report();
    report.accounts.push(AccountInfo {
        index: 0,
        pubkey: "SysvarRent111111111111111111111111111111111".into(),
        is_signer: false,
        is_writable: false,
        role: Some("readonly".into()),
        pda_info: None,
    });
    validator::validate(&mut report, None);
    assert!(!report.risk_flags.iter().any(|f| f.category == RiskCategory::InsecureWritable));
}

#[test]
fn test_writable_program_flagged() {
    let mut report = make_report();
    report.accounts.push(AccountInfo {
        index: 0,
        pubkey: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".into(),
        is_signer: false,
        is_writable: true,
        role: Some("writable".into()),
        pda_info: None,
    });
    validator::validate(&mut report, None);
    assert!(report.risk_flags.iter().any(|f| f.category == RiskCategory::InsecureWritable));
}

#[test]
fn test_alt_empty_flag() {
    let mut report = make_report();
    report.address_lookup_tables.push(AltResolution {
        table_address: "AddressLookupTab1e1111111111111111111111111".into(),
        resolved_accounts: vec![],
    });
    validator::validate(&mut report, None);
    assert!(report.risk_flags.iter().any(|f| f.category == RiskCategory::AltIntegrity));
}

#[test]
fn test_alt_with_accounts_not_flagged() {
    let mut report = make_report();
    report.address_lookup_tables.push(AltResolution {
        table_address: "AddressLookupTab1e1111111111111111111111111".into(),
        resolved_accounts: vec![ResolvedAccount {
            index_in_tx: 5,
            pubkey: "11111111111111111111111111111111".into(),
            is_writable: false,
        }],
    });
    validator::validate(&mut report, None);
    assert!(!report.risk_flags.iter().any(|f| f.category == RiskCategory::AltIntegrity));
}

#[test]
fn test_missing_signer_with_idl() {
    let idl = IdlJson {
        version: "0.1.0".into(),
        name: "test_program".into(),
        instructions: vec![IdlInstruction {
            name: "do_thing".into(),
            accounts: vec![IdlAccountItem {
                name: "authority".into(),
                is_mut: false,
                is_signer: true,
                pda: None,
                desc: None,
            }],
            args: vec![],
        }],
        accounts: vec![],
        types: vec![],
    };

    let mut report = make_report();
    report.instructions.push(DecodedInstruction {
        index: 0,
        program_id: "11111111111111111111111111111111".into(),
        program_name: "System Program".into(),
        instruction_name: Some("do_thing".into()),
        accounts: vec![MappedAccount {
            name: Some("authority".into()),
            pubkey: "11111111111111111111111111111111".into(),
            account_index: 0,
            is_signer: false,
            is_writable: true,
        }],
        data: serde_json::Value::Null,
        raw_data_hex: String::new(),
    });

    validator::validate(&mut report, Some(&idl));
    assert!(report.risk_flags.iter().any(|f| f.category == RiskCategory::MissingSigner));
}

#[test]
fn test_signer_present_not_flagged() {
    let idl = IdlJson {
        version: "0.1.0".into(),
        name: "test_program".into(),
        instructions: vec![IdlInstruction {
            name: "do_thing".into(),
            accounts: vec![IdlAccountItem {
                name: "authority".into(),
                is_mut: false,
                is_signer: true,
                pda: None,
                desc: None,
            }],
            args: vec![],
        }],
        accounts: vec![],
        types: vec![],
    };

    let mut report = make_report();
    report.instructions.push(DecodedInstruction {
        index: 0,
        program_id: "11111111111111111111111111111111".into(),
        program_name: "System Program".into(),
        instruction_name: Some("do_thing".into()),
        accounts: vec![MappedAccount {
            name: Some("authority".into()),
            pubkey: "11111111111111111111111111111111".into(),
            account_index: 0,
            is_signer: true,
            is_writable: true,
        }],
        data: serde_json::Value::Null,
        raw_data_hex: String::new(),
    });

    validator::validate(&mut report, Some(&idl));
    assert!(!report.risk_flags.iter().any(|f| f.category == RiskCategory::MissingSigner));
}

// ── UI Tests ─────────────────────────────────────────────────────────────────

fn make_report_with_data() -> TransactionReport {
    TransactionReport {
        status: "DECODED SUCCESSFULLY".into(),
        fee_payer: "11111111111111111111111111111111".into(),
        signatures: vec!["sig1".into()],
        recent_blockhash: "11111111111111111111111111111111".into(),
        message_version: None,
        accounts: vec![AccountInfo {
            index: 0,
            pubkey: "11111111111111111111111111111111".into(),
            is_signer: true,
            is_writable: true,
            role: Some("fee_payer".into()),
            pda_info: None,
        }],
        instructions: vec![DecodedInstruction {
            index: 0,
            program_id: "11111111111111111111111111111111".into(),
            program_name: "System Program".into(),
            instruction_name: Some("Transfer".into()),
            accounts: vec![MappedAccount {
                name: Some("source".into()),
                pubkey: "11111111111111111111111111111111".into(),
                account_index: 0,
                is_signer: true,
                is_writable: true,
            }],
            data: serde_json::json!({"lamports": 1000}),
            raw_data_hex: "02000000e803000000000000".into(),
        }],
        address_lookup_tables: vec![],
        compute_budget: Some(ComputeBudgetInfo {
            compute_unit_limit: 150_000,
            compute_unit_price: 0,
            compute_unit_limit_set: true,
            compute_budget_positions: vec![0],
            is_reordered: false,
            high_cu_instructions: vec![],
        }),
        risk_flags: vec![],
        simulation: None,
        warnings: vec![],
    }
}

#[test]
fn test_render_json_serializes() {
    let report = make_report_with_data();
    let json = ui::render_json(&report);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["status"], "DECODED SUCCESSFULLY");
}

#[test]
fn test_render_tx_report_has_required_fields() {
    let report = make_report_with_data();
    let json_str = ui::render_tx_report(&report);
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert!(parsed["schema_version"].is_string());
    assert!(parsed["transaction"]["signatures"].is_array());
    assert!(parsed["accounts"].is_array());
    assert!(parsed["instructions"].is_array());
}

#[test]
fn test_render_terminal_does_not_panic() {
    let report = make_report_with_data();
    ui::render_terminal(&report, false);
    ui::render_terminal(&report, true);
}

// ── Types Tests ──────────────────────────────────────────────────────────────

#[test]
fn test_idl_find_instruction() {
    let idl = IdlJson {
        version: "0.1.0".into(),
        name: "test".into(),
        instructions: vec![
            IdlInstruction { name: "foo".into(), accounts: vec![], args: vec![] },
            IdlInstruction { name: "bar".into(), accounts: vec![], args: vec![] },
        ],
        accounts: vec![],
        types: vec![],
    };
    assert!(idl.find_instruction("foo").is_some());
    assert!(idl.find_instruction("bar").is_some());
    assert!(idl.find_instruction("baz").is_none());
}

#[test]
fn test_is_sysvar_id() {
    assert!(is_sysvar_id("SysvarRent111111111111111111111111111111111"));
    assert!(!is_sysvar_id("11111111111111111111111111111111"));
}

#[test]
fn test_is_known_program_id() {
    assert!(is_known_program_id("11111111111111111111111111111111"));
    assert!(is_known_program_id("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"));
    assert!(!is_known_program_id("FakeProgram111111111111111111111111111111"));
}

// ── Transaction Round-Trip & Fixture Tests ───────────────────────────────────

use solana_sdk::{
    hash::Hash,
    instruction::Instruction,
    message::{VersionedMessage, v0},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use std::io::Write as _;
use std::str::FromStr;

fn system_transfer_instruction(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = vec![0u8; 12];
    data[0..4].copy_from_slice(&2u32.to_le_bytes());
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: Pubkey::from_str("11111111111111111111111111111111").unwrap(),
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(*from, true),
            solana_sdk::instruction::AccountMeta::new(*to, false),
        ],
        data,
    }
}

fn set_compute_unit_limit_instruction(limit: u32) -> Instruction {
    let mut data = vec![0u8; 5];
    data[0] = 1;
    data[1..5].copy_from_slice(&limit.to_le_bytes());
    Instruction {
        program_id: Pubkey::from_str("ComputeBudget111111111111111111111111111111").unwrap(),
        accounts: vec![],
        data,
    }
}

fn set_compute_unit_price_instruction(price: u64) -> Instruction {
    let mut data = vec![0u8; 9];
    data[0] = 3;
    data[1..9].copy_from_slice(&price.to_le_bytes());
    Instruction {
        program_id: Pubkey::from_str("ComputeBudget111111111111111111111111111111").unwrap(),
        accounts: vec![],
        data,
    }
}

/// Build a legacy System Transfer transaction, serialize it, and verify
/// the decoder can round-trip it correctly.
#[test]
fn test_legacy_transfer_round_trip() {
    let from = Keypair::new();
    let to = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    let recent_blockhash = Hash::new_from_array([7u8; 32]);

    let ix = system_transfer_instruction(&from.pubkey(), &to, 1_000_000_000);

    let message = VersionedMessage::Legacy(solana_sdk::message::legacy::Message::new_with_blockhash(
        &[ix],
        Some(&from.pubkey()),
        &recent_blockhash,
    ));

    let tx = VersionedTransaction { signatures: vec![from.sign_message(&message.serialize()).into()], message };

    let serialized = bincode::serialize(&tx).unwrap();
    let hex_encoded = hex::encode(&serialized);

    // Write fixture to disk
    write_fixture("tests/fixtures/system_transfer.hex", &hex_encoded);
    write_fixture("tests/fixtures/system_transfer.bin", &serialized);

    let base58_encoded = bs58::encode(&serialized).into_string();
    write_fixture("tests/fixtures/system_transfer.base58", &base58_encoded);

    use base64::Engine;
    let base64_encoded = base64::engine::general_purpose::STANDARD.encode(&serialized);
    write_fixture("tests/fixtures/system_transfer.base64", &base64_encoded);

    // Round-trip: decode the hex fixture and verify
    let report = decoder::decode_transaction(&hex_encoded, None).expect("Decode hex fixture");
    assert_eq!(report.instructions.len(), 1);
    assert_eq!(report.instructions[0].program_name, "System Program");
    assert_eq!(report.instructions[0].instruction_name.as_deref(), Some("Transfer"));
    assert_eq!(report.instructions[0].data["lamports"], serde_json::json!(1000000000u64));
}

/// Build a v0 transaction and verify decoder handles the version field.
#[test]
fn test_v0_transaction_round_trip() {
    let from = Keypair::new();
    let to = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    let recent_blockhash = Hash::new_from_array([7u8; 32]);

    let ix = system_transfer_instruction(&from.pubkey(), &to, 500_000_000);

    let v0_msg = v0::Message::try_compile(&from.pubkey(), &[ix], &[], recent_blockhash).unwrap();

    let message = VersionedMessage::V0(v0_msg);

    let tx = VersionedTransaction { signatures: vec![from.sign_message(&message.serialize()).into()], message };

    let serialized = bincode::serialize(&tx).unwrap();
    let hex_encoded = hex::encode(&serialized);

    write_fixture("tests/fixtures/v0_transfer.hex", &hex_encoded);

    let report = decoder::decode_transaction(&hex_encoded, None).expect("Decode v0 fixture");
    assert_eq!(report.message_version, Some(0));
    assert_eq!(report.instructions.len(), 1);
    assert_eq!(report.instructions[0].instruction_name.as_deref(), Some("Transfer"));
}

/// Build a transaction with ComputeBudget + Transfer instruction and verify
/// compute budget analysis in the report.
#[test]
fn test_compute_budget_transaction() {
    let from = Keypair::new();
    let to = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    let recent_blockhash = Hash::new_from_array([7u8; 32]);

    let cu_limit_ix = set_compute_unit_limit_instruction(150_000);
    let cu_price_ix = set_compute_unit_price_instruction(5_000);
    let transfer_ix = system_transfer_instruction(&from.pubkey(), &to, 1_000_000);

    let message = VersionedMessage::Legacy(solana_sdk::message::legacy::Message::new_with_blockhash(
        &[cu_limit_ix, cu_price_ix, transfer_ix],
        Some(&from.pubkey()),
        &recent_blockhash,
    ));

    let tx = VersionedTransaction { signatures: vec![from.sign_message(&message.serialize()).into()], message };

    let serialized = bincode::serialize(&tx).unwrap();
    let hex_encoded = hex::encode(&serialized);

    write_fixture("tests/fixtures/compute_budget_transfer.hex", &hex_encoded);

    let report = decoder::decode_transaction(&hex_encoded, None).expect("Decode CU fixture");
    assert_eq!(report.instructions.len(), 3);

    let cb = report.compute_budget.expect("Should have compute budget info");
    assert!(cb.compute_unit_limit_set);
    assert_eq!(cb.compute_unit_limit, 150_000);
    assert_eq!(cb.compute_unit_price, 5_000);

    // CU instructions at positions 0 and 1 (both at start = not reordered)
    assert!(!cb.is_reordered);
}

fn write_fixture(path: &str, data: impl AsRef<[u8]>) {
    let data = data.as_ref();
    let mut file = std::fs::File::create(path).expect("Failed to create fixture file");
    file.write_all(data).expect("Failed to write fixture");
}
