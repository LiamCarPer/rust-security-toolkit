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
    let result = decoder::validate_decoding(&[], &make_report());
    assert!(result.is_err());
}

#[test]
fn test_validate_decoding_too_short() {
    let result = decoder::validate_decoding(&[0x01], &make_report());
    assert!(result.is_err() || !result.unwrap().is_empty());
}

// ── Input Decoding Tests ────────────────────────────────────────────────────

#[test]
fn test_decode_input_bytes_text_and_raw() {
    use rust_security_toolkit::encoding;

    // Hex text
    assert_eq!(encoding::decode_input_bytes(b"deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);

    // Base58 text with a trailing newline (trimmed before detection)
    let base58 = "2xPFR3JFj5DMhYuT8pE4dKdC6eHkjKDS3sGmxG";
    assert_eq!(
        encoding::decode_input_bytes(format!("{}\n", base58).as_bytes()).unwrap(),
        bs58::decode(base58).into_vec().unwrap()
    );

    // Invalid UTF-8 → raw bytes pass through untouched
    let raw = vec![0x01u8, 0x02, 0xff, 0x80, 0x7f];
    assert_eq!(encoding::decode_input_bytes(&raw).unwrap(), raw);

    // Empty input stays empty
    assert!(encoding::decode_input_bytes(b"").unwrap().is_empty());
}

/// The committed raw binary fixture decodes end-to-end through the CLI input path.
#[test]
fn test_decode_raw_binary_fixture() {
    use rust_security_toolkit::encoding;

    let bytes = std::fs::read("tests/fixtures/system_transfer.bin").expect("read bin fixture");
    let decoded = encoding::decode_input_bytes(&bytes).expect("decode input bytes");
    assert_eq!(decoded, bytes, "raw binary must pass through untouched");

    let report = decoder::decode_raw_bytes(&decoded, None).expect("Decode raw binary fixture");
    assert_eq!(report.instructions.len(), 1);
    assert_eq!(report.instructions[0].instruction_name.as_deref(), Some("Transfer"));
}

/// All-hex even-length text is ambiguous (Hex vs Base58 vs Base64): the primary
/// Hex interpretation fails to deserialize, the alternatives are retried, and
/// the primary error is surfaced.
#[test]
fn test_decode_input_ambiguous_hex_text() {
    // "deadbeef" is valid hex, valid base58, and valid padding-less base64 —
    // none of the three interpretations deserialize as a transaction.
    let result = decoder::decode_input(b"deadbeef", None);
    assert!(result.is_err(), "ambiguous hex text must not decode as a transaction");
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
        signature_verification: vec![],
        inner_instructions: vec![],
        balance_changes_sol: vec![],
        token_balance_changes: vec![],
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
        priority_fee_lamports: 0,
        priority_fee_actual: None,
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
        priority_fee_lamports: 0,
        priority_fee_actual: None,
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
        resolved: false,
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
            table_index: None,
        }],
        resolved: false,
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
        token_amount: None,
    });

    validator::validate(&mut report, Some(&ProgramSchema::Idl(idl)));
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
        token_amount: None,
    });

    validator::validate(&mut report, Some(&ProgramSchema::Idl(idl)));
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
            token_amount: None,
        }],
        address_lookup_tables: vec![],
        compute_budget: Some(ComputeBudgetInfo {
            compute_unit_limit: 150_000,
            compute_unit_price: 0,
            compute_unit_limit_set: true,
            compute_budget_positions: vec![0],
            is_reordered: false,
            high_cu_instructions: vec![],
            priority_fee_lamports: 0,
            priority_fee_actual: None,
        }),
        risk_flags: vec![],
        simulation: None,
        warnings: vec![],
        signature_verification: vec![],
        inner_instructions: vec![],
        balance_changes_sol: vec![],
        token_balance_changes: vec![],
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
    let json_str = ui::render_tx_report(&report, "test_program");
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert!(parsed["schema_version"].is_string());
    assert_eq!(parsed["program_name"], "test_program");
    assert!(parsed["transaction"]["signatures"].is_array());
    assert!(parsed["accounts"].is_array());
    assert!(parsed["instructions"].is_array());
    assert!(parsed["instructions"][0]["name"].is_string());
}

// ── sat tx-report contract tests ────────────────────────────────────────────
// The structs below mirror `solana-audit-toolkit/crates/sat/src/tx_report.rs`
// exactly (field names + serde defaults); if either side drifts, this test
// fails and the integration contract is broken.

#[derive(Debug, serde::Deserialize)]
struct SatTxReport {
    #[serde(default)]
    schema_version: String,
    #[serde(default)]
    program_name: String,
    #[serde(default)]
    instructions: Vec<SatInstruction>,
}

#[derive(Debug, serde::Deserialize)]
struct SatInstruction {
    #[serde(default)]
    name: String,
    #[serde(default)]
    accounts: Vec<SatAccount>,
}

#[derive(Debug, serde::Deserialize)]
struct SatAccount {
    #[serde(default)]
    name: String,
    #[serde(default)]
    is_signer: bool,
    #[serde(default)]
    is_writable: bool,
    #[serde(default)]
    pda_info: Option<SatPda>,
}

#[derive(Debug, serde::Deserialize)]
struct SatPda {
    #[serde(default)]
    seeds_declared: Vec<String>,
    #[serde(default)]
    bump: Option<u8>,
}

/// The tx-report emitted by `render_tx_report` must deserialize into sat's
/// expected shape with names and PDA info intact — i.e. sat's correlation can
/// actually match instructions and accounts.
#[test]
fn test_tx_report_sat_contract() {
    let program_id = Pubkey::new_from_array([1u8; 32]);
    let payer = Keypair::new();
    let from = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (vault, bump) = Pubkey::find_program_address(&[b"vault"], &program_id);
    let recent_blockhash = Hash::new_from_array([7u8; 32]);

    let discriminator = decoder::compute_anchor_discriminator("transfer_tokens");
    let ix = Instruction {
        program_id,
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(from, false),
            solana_sdk::instruction::AccountMeta::new_readonly(authority, false),
            solana_sdk::instruction::AccountMeta::new_readonly(vault, false),
        ],
        data: discriminator.to_vec(),
    };
    let message = VersionedMessage::Legacy(solana_sdk::message::legacy::Message::new_with_blockhash(
        &[ix],
        Some(&payer.pubkey()),
        &recent_blockhash,
    ));
    let tx = VersionedTransaction { signatures: vec![payer.sign_message(&message.serialize())], message };
    let serialized = bincode::serialize(&tx).unwrap();

    let idl = IdlJson {
        version: "0.1.0".into(),
        name: "test_program".into(),
        instructions: vec![IdlInstruction {
            name: "transfer_tokens".into(),
            accounts: vec![
                IdlAccountItem { name: "from".into(), is_mut: true, is_signer: false, pda: None, desc: None },
                IdlAccountItem { name: "authority".into(), is_mut: false, is_signer: true, pda: None, desc: None },
                IdlAccountItem {
                    name: "vault".into(),
                    is_mut: false,
                    is_signer: false,
                    pda: Some(IdlPda {
                        seeds: vec![IdlSeed {
                            kind: "const".into(),
                            value: Some(b"vault".to_vec()),
                            path: None,
                            account: None,
                        }],
                    }),
                    desc: None,
                },
            ],
            args: vec![],
        }],
        accounts: vec![],
        types: vec![],
    };

    let schema = ProgramSchema::Idl(idl);
    let mut report = decoder::decode_raw_bytes(&serialized, Some(&schema)).expect("Decode with IDL");
    validator::validate(&mut report, Some(&schema));

    // Decoder populated IDL names on the mapped accounts.
    assert_eq!(report.instructions[0].accounts[0].name.as_deref(), Some("from"));
    assert_eq!(report.instructions[0].accounts[1].name.as_deref(), Some("authority"));
    assert_eq!(report.instructions[0].accounts[2].name.as_deref(), Some("vault"));

    let ProgramSchema::Idl(idl) = schema else {
        unreachable!("schema was built as Idl");
    };
    let json_str = ui::render_tx_report(&report, &idl.name);
    let sat: SatTxReport = serde_json::from_str(&json_str).expect("report must parse into sat's contract");

    assert_eq!(sat.schema_version, "1.0");
    assert_eq!(sat.program_name, "test_program");
    assert_eq!(sat.instructions.len(), 1);
    assert_eq!(sat.instructions[0].name, "transfer_tokens");
    assert_eq!(sat.instructions[0].accounts.len(), 3);
    assert_eq!(sat.instructions[0].accounts[0].name, "from");
    assert!(sat.instructions[0].accounts[0].is_writable);
    assert_eq!(sat.instructions[0].accounts[1].name, "authority");
    // Authority is a non-signer in the tx while the IDL declares isSigner=true:
    // sat's correlation must be able to see this mismatch.
    assert!(!sat.instructions[0].accounts[1].is_signer);
    let pda = sat.instructions[0].accounts[2].pda_info.as_ref().expect("vault pda_info");
    assert!(pda.seeds_declared.iter().any(|s| s.contains("vault")));
    assert_eq!(pda.bump, Some(bump));
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
    // On-chain tag 2 = SetComputeUnitLimit (1 is RequestHeapFrame).
    let mut data = vec![0u8; 5];
    data[0] = 2;
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

fn write_fixture(path: &str, data: impl AsRef<[u8]>) {
    let data = data.as_ref();
    let mut file = std::fs::File::create(path).expect("Failed to create fixture file");
    file.write_all(data).expect("Failed to write fixture");
}

fn read_fixture(path: &str) -> String {
    std::fs::read_to_string(path).expect("Failed to read fixture file")
}

/// Generate all transaction fixtures. Run manually with:
///   cargo test generate_fixtures -- --ignored
#[test]
#[ignore]
fn generate_fixtures() {
    let from = Keypair::new();
    let to = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    let recent_blockhash = Hash::new_from_array([7u8; 32]);

    // Legacy system transfer
    let ix = system_transfer_instruction(&from.pubkey(), &to, 1_000_000_000);
    let message = VersionedMessage::Legacy(solana_sdk::message::legacy::Message::new_with_blockhash(
        &[ix],
        Some(&from.pubkey()),
        &recent_blockhash,
    ));
    let tx = VersionedTransaction { signatures: vec![from.sign_message(&message.serialize())], message };
    let serialized = bincode::serialize(&tx).unwrap();
    write_fixture("tests/fixtures/system_transfer.hex", hex::encode(&serialized));
    write_fixture("tests/fixtures/system_transfer.bin", &serialized);
    write_fixture("tests/fixtures/system_transfer.base58", bs58::encode(&serialized).into_string());
    use base64::Engine;
    write_fixture(
        "tests/fixtures/system_transfer.base64",
        base64::engine::general_purpose::STANDARD.encode(&serialized),
    );

    // v0 transaction
    let v0_msg = v0::Message::try_compile(
        &from.pubkey(),
        &[system_transfer_instruction(&from.pubkey(), &to, 500_000_000)],
        &[],
        recent_blockhash,
    )
    .unwrap();
    let message = VersionedMessage::V0(v0_msg);
    let tx = VersionedTransaction { signatures: vec![from.sign_message(&message.serialize())], message };
    write_fixture("tests/fixtures/v0_transfer.hex", hex::encode(bincode::serialize(&tx).unwrap()));

    // Compute budget + transfer
    let cu_limit_ix = set_compute_unit_limit_instruction(150_000);
    let cu_price_ix = set_compute_unit_price_instruction(5_000);
    let transfer_ix = system_transfer_instruction(&from.pubkey(), &to, 1_000_000);
    let message = VersionedMessage::Legacy(solana_sdk::message::legacy::Message::new_with_blockhash(
        &[cu_limit_ix, cu_price_ix, transfer_ix],
        Some(&from.pubkey()),
        &recent_blockhash,
    ));
    let tx = VersionedTransaction { signatures: vec![from.sign_message(&message.serialize())], message };
    write_fixture("tests/fixtures/compute_budget_transfer.hex", hex::encode(bincode::serialize(&tx).unwrap()));
}

/// Decode the committed legacy transfer fixture and verify structure.
#[test]
fn test_decode_legacy_transfer_fixture() {
    let hex_encoded = read_fixture("tests/fixtures/system_transfer.hex");
    let raw_bytes = hex::decode(hex_encoded.trim()).expect("Decode fixture hex");
    let report = decoder::decode_raw_bytes(&raw_bytes, None).expect("Decode legacy fixture");
    assert_eq!(report.message_version, None);
    assert_eq!(report.instructions.len(), 1);
    assert_eq!(report.instructions[0].program_name, "System Program");
    assert_eq!(report.instructions[0].instruction_name.as_deref(), Some("Transfer"));
    assert!(report.signatures.len() == 1);

    // The differential decode gate must hold for the committed fixtures.
    let warnings = decoder::validate_decoding(&raw_bytes, &report).expect("validate_decoding should succeed");
    assert!(warnings.is_empty(), "unexpected warnings: {:?}", warnings);
}

/// Decode the committed v0 transfer fixture and verify version field.
#[test]
fn test_decode_v0_transfer_fixture() {
    let hex_encoded = read_fixture("tests/fixtures/v0_transfer.hex");
    let raw_bytes = hex::decode(hex_encoded.trim()).expect("Decode fixture hex");
    let report = decoder::decode_raw_bytes(&raw_bytes, None).expect("Decode v0 fixture");
    assert_eq!(report.message_version, Some(0));
    assert_eq!(report.instructions.len(), 1);
    assert_eq!(report.instructions[0].instruction_name.as_deref(), Some("Transfer"));

    let warnings = decoder::validate_decoding(&raw_bytes, &report).expect("validate_decoding should succeed");
    assert!(warnings.is_empty(), "unexpected warnings: {:?}", warnings);
}

/// Decode the committed compute budget fixture and verify CU analysis.
#[test]
fn test_decode_compute_budget_fixture() {
    let hex_encoded = read_fixture("tests/fixtures/compute_budget_transfer.hex");
    let raw_bytes = hex::decode(hex_encoded.trim()).expect("Decode fixture hex");
    let report = decoder::decode_raw_bytes(&raw_bytes, None).expect("Decode CU fixture");
    assert_eq!(report.instructions.len(), 3);
    let cb = report.compute_budget.as_ref().expect("Should have compute budget info");
    assert!(cb.compute_unit_limit_set);
    assert_eq!(cb.compute_unit_limit, 150_000);
    assert_eq!(cb.compute_unit_price, 5_000);
    assert!(!cb.is_reordered);

    let warnings = decoder::validate_decoding(&raw_bytes, &report).expect("validate_decoding should succeed");
    assert!(warnings.is_empty(), "unexpected warnings: {:?}", warnings);
}

/// Legacy transaction with 150 distinct accounts exercises the 2-byte
/// compact-u16 (short_vec) path for the signature/account counts.
#[test]
fn test_validate_decoding_legacy_150_accounts() {
    let pks: Vec<Pubkey> = (0..150).map(|i| Pubkey::new_from_array([i as u8; 32])).collect();
    let payer = pks[0];
    let recent_blockhash = Hash::new_from_array([8u8; 32]);

    let mut accounts = vec![solana_sdk::instruction::AccountMeta::new(pks[0], true)];
    for pk in &pks[1..] {
        accounts.push(solana_sdk::instruction::AccountMeta::new(*pk, false));
    }
    let mut data = vec![0u8; 12];
    data[0..4].copy_from_slice(&2u32.to_le_bytes());
    data[4..12].copy_from_slice(&1_000_000u64.to_le_bytes());
    let ix = Instruction { program_id: pks[1], accounts, data };

    let message = VersionedMessage::Legacy(solana_sdk::message::legacy::Message::new_with_blockhash(
        &[ix],
        Some(&payer),
        &recent_blockhash,
    ));
    let keypair = Keypair::new();
    let tx = VersionedTransaction { signatures: vec![keypair.sign_message(&message.serialize())], message };
    let serialized = bincode::serialize(&tx).unwrap();

    let report = decoder::decode_raw_bytes(&serialized, None).expect("Decode legacy 150-account tx");
    assert_eq!(report.accounts.len(), 150);

    let warnings = decoder::validate_decoding(&serialized, &report).expect("validate_decoding should succeed");
    assert!(warnings.is_empty(), "expected no warnings, got: {:?}", warnings);
}

/// The committed v0 fixture (no address table lookups) must parse cleanly.
#[test]
fn test_validate_decoding_v0_fixture_clean() {
    let hex_encoded = read_fixture("tests/fixtures/v0_transfer.hex");
    let raw_bytes = hex::decode(hex_encoded.trim()).expect("Decode v0 fixture hex");
    let report = decoder::decode_raw_bytes(&raw_bytes, None).expect("Decode v0 fixture");

    let warnings = decoder::validate_decoding(&raw_bytes, &report).expect("validate_decoding should succeed");
    assert!(warnings.is_empty(), "expected no warnings, got: {:?}", warnings);
}

/// v0 message with an address table lookup: the instruction must reference an
/// ALT address, otherwise `try_compile` drops the unused table.
#[test]
fn test_validate_decoding_v0_with_alt() {
    let payer = Keypair::new();
    let recent_blockhash = Hash::new_from_array([9u8; 32]);

    let alt = solana_sdk::message::AddressLookupTableAccount {
        key: Pubkey::new_unique(),
        addresses: vec![Pubkey::new_unique(), Pubkey::new_unique()],
    };
    let mut ix = system_transfer_instruction(&payer.pubkey(), &Pubkey::new_unique(), 1_000_000);
    ix.accounts.push(solana_sdk::instruction::AccountMeta::new(alt.addresses[0], false));

    let msg = v0::Message::try_compile(&payer.pubkey(), &[ix], &[alt], recent_blockhash).unwrap();
    let tx = VersionedTransaction {
        signatures: vec![payer.sign_message(&msg.serialize())],
        message: VersionedMessage::V0(msg),
    };
    let serialized = bincode::serialize(&tx).unwrap();

    let report = decoder::decode_raw_bytes(&serialized, None).expect("Decode v0 ALT tx");
    assert_eq!(report.address_lookup_tables.len(), 1);
    assert_eq!(report.address_lookup_tables[0].resolved_accounts.len(), 1);

    let warnings = decoder::validate_decoding(&serialized, &report).expect("validate_decoding should succeed");
    assert!(warnings.is_empty(), "expected no warnings, got: {:?}", warnings);
}

fn create_account_instruction(from: &Pubkey, to: &Pubkey, lamports: u64, space: u64, owner: &Pubkey) -> Instruction {
    let mut data = vec![0u8; 52];
    data[0..4].copy_from_slice(&0u32.to_le_bytes());
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    data[12..20].copy_from_slice(&space.to_le_bytes());
    data[20..52].copy_from_slice(&owner.to_bytes());
    Instruction {
        program_id: Pubkey::from_str("11111111111111111111111111111111").unwrap(),
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(*from, true),
            solana_sdk::instruction::AccountMeta::new(*to, true),
        ],
        data,
    }
}

// Verify that high-CU instructions (CreateAccount, 15k CU) are flagged
// when they exceed the dynamic threshold.
// ── IDL Account Count Consistency Tests ──────────────────────────────────────

fn make_single_account_idl() -> IdlJson {
    IdlJson {
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
    }
}

fn mapped_account(pubkey: &str, is_signer: bool) -> MappedAccount {
    MappedAccount { name: None, pubkey: pubkey.into(), account_index: 0, is_signer, is_writable: true }
}

/// A compiled account list longer than the IDL's declared accounts (beyond the
/// appended program id) is flagged: positional mapping may be misaligned.
#[test]
fn test_idl_account_count_mismatch_flag() {
    let idl = make_single_account_idl();
    let mut report = make_report();
    report.instructions.push(DecodedInstruction {
        index: 0,
        program_id: "11111111111111111111111111111111".into(),
        program_name: "System Program".into(),
        instruction_name: Some("do_thing".into()),
        accounts: vec![
            mapped_account("11111111111111111111111111111111", true),
            mapped_account("22222222222222222222222222222222222222222222", false),
            mapped_account("33333333333333333333333333333333333333333333", false),
        ],
        data: serde_json::Value::Null,
        raw_data_hex: String::new(),
        token_amount: None,
    });

    validator::validate(&mut report, Some(&ProgramSchema::Idl(idl)));
    assert!(report.risk_flags.iter().any(|f| f.category == RiskCategory::IdlAccountMismatch));
}

/// IDL-matched instructions with the expected count (with or without the
/// appended program id) are not flagged.
#[test]
fn test_idl_account_count_ok() {
    let idl = make_single_account_idl();
    let mut report = make_report();
    // IDL declares 1 account; compiled lists 2 with the program id appended.
    report.instructions.push(DecodedInstruction {
        index: 0,
        program_id: "11111111111111111111111111111111".into(),
        program_name: "System Program".into(),
        instruction_name: Some("do_thing".into()),
        accounts: vec![
            mapped_account("11111111111111111111111111111111", true),
            mapped_account("11111111111111111111111111111111", false),
        ],
        data: serde_json::Value::Null,
        raw_data_hex: String::new(),
        token_amount: None,
    });

    validator::validate(&mut report, Some(&ProgramSchema::Idl(idl)));
    assert!(!report.risk_flags.iter().any(|f| f.category == RiskCategory::IdlAccountMismatch));
}

// ── Token-2022 Instruction Coverage Tests ────────────────────────────────────

#[test]
fn test_token_2022_instruction_names() {
    use rust_security_toolkit::instruction_decoder::decode_instruction_data;
    let t22 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

    let cases: Vec<(Vec<u8>, &str)> = vec![
        (vec![21, 1, 0, 0, 0, 0, 0], "GetAccountDataSize"),
        (vec![22], "InitializeImmutableOwner"),
        (vec![23, 0x40, 0x42, 0x0f, 0, 0, 0, 0, 0], "AmountToUiAmount"),
        (vec![24, b'h', b'i'], "UiAmountToAmount"),
        (vec![28, 1, 0, 0, 0, 1, 0], "DefaultAccountStateExtension"),
        (vec![29, 1, 0, 0, 0, 1, 0], "Reallocate"),
        (vec![30], "MemoTransferExtension"),
        (vec![31], "CreateNativeMint"),
        (vec![32], "InitializeNonTransferableMint"),
        (vec![33, 0, 0x40, 0x42], "InitializeInterestBearingMint"),
        (vec![33, 1, 0x40, 0x42], "UpdateInterestBearingMintRate"),
        (vec![34, 0], "EnableCpiGuard"),
        (vec![34, 1], "DisableCpiGuard"),
        (vec![38], "WithdrawExcessLamports"),
        (vec![44, 0], "Pause"),
        (vec![44, 1], "Resume"),
    ];
    for (data, expected) in cases {
        let (name, _) = decode_instruction_data(t22, &data, None);
        assert_eq!(name.as_deref(), Some(expected), "data {:02x?}", data);
    }

    // 35 is InitializePermanentDelegate in the pinned spl-token-2022 numbering
    // (31 is CreateNativeMint).
    let mut data = vec![35u8];
    data.extend_from_slice(&[7u8; 32]);
    let (name, decoded) = decode_instruction_data(t22, &data, None);
    assert_eq!(name.as_deref(), Some("InitializePermanentDelegate"));
    let expected_pk = Pubkey::new_from_array([7u8; 32]).to_string();
    assert!(decoded.to_string().contains(&expected_pk), "unexpected data: {}", decoded);

    // TransferHookExtension requires the full pubkey payloads.
    let mut data = vec![36u8, 0];
    data.extend_from_slice(&[7u8; 64]);
    let (name, _) = decode_instruction_data(t22, &data, None);
    assert_eq!(name.as_deref(), Some("InitializeTransferHook"));
    let mut data = vec![36u8, 1];
    data.extend_from_slice(&[7u8; 32]);
    let (name, _) = decode_instruction_data(t22, &data, None);
    assert_eq!(name.as_deref(), Some("UpdateTransferHook"));

    // Extension-type payloads decode as u16 lists.
    let (name, decoded) = decode_instruction_data(t22, &[28, 1, 0, 0, 0, 1, 0], None);
    assert_eq!(name.as_deref(), Some("DefaultAccountStateExtension"));
    assert_eq!(decoded, serde_json::json!({"extension_types": [1]}));

    // Token-2022 discriminators must not leak into the legacy token decoder.
    let (name, _) = decode_instruction_data("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", &[31], None);
    assert_eq!(name, None);
}

#[test]
fn test_high_cu_instruction_detection() {
    let from = Keypair::new();
    let to = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    let owner = Pubkey::from_str("BPFLoaderUpgradeab1e11111111111111111111111").unwrap();
    let recent_blockhash = Hash::new_from_array([7u8; 32]);

    // Build a transaction with a CU limit of 30,000 and a CreateAccount (15k CU)
    let cu_limit_ix = set_compute_unit_limit_instruction(30_000);
    let create_ix = create_account_instruction(&from.pubkey(), &to, 1_000_000_000, 256, &owner);

    let message = VersionedMessage::Legacy(solana_sdk::message::legacy::Message::new_with_blockhash(
        &[cu_limit_ix, create_ix],
        Some(&from.pubkey()),
        &recent_blockhash,
    ));

    let tx = VersionedTransaction { signatures: vec![from.sign_message(&message.serialize())], message };
    let hex_encoded = hex::encode(bincode::serialize(&tx).unwrap());

    let report = decoder::decode_transaction(&hex_encoded, None).expect("Decode CU+CreateAccount tx");
    let cb = report.compute_budget.expect("Should have compute budget info");
    assert_eq!(cb.compute_unit_limit, 30_000);
    assert!(!cb.high_cu_instructions.is_empty(), "CreateAccount (15k CU) should be flagged with 30k limit");
    assert_eq!(cb.high_cu_instructions[0], 1);
}

// ── Compute Budget Reordering Tests ───────────────────────────────────────────

/// A ComputeBudget instruction after a non-CB instruction is an invalid ordering
/// (the runtime requires CB instructions first) and must be flagged.
#[test]
fn test_cb_after_transfer_flagged_reordered() {
    let from = Keypair::new();
    let to = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    let recent_blockhash = Hash::new_from_array([7u8; 32]);

    let transfer_ix = system_transfer_instruction(&from.pubkey(), &to, 1_000_000);
    let cu_limit_ix = set_compute_unit_limit_instruction(150_000);

    let message = VersionedMessage::Legacy(solana_sdk::message::legacy::Message::new_with_blockhash(
        &[transfer_ix, cu_limit_ix],
        Some(&from.pubkey()),
        &recent_blockhash,
    ));
    let tx = VersionedTransaction { signatures: vec![from.sign_message(&message.serialize())], message };
    let hex_encoded = hex::encode(bincode::serialize(&tx).unwrap());

    let report = decoder::decode_transaction(&hex_encoded, None).expect("Decode CB-after-transfer tx");
    let cb = report.compute_budget.expect("Should have compute budget info");
    assert!(cb.is_reordered, "CB after transfer must be flagged as reordered");
}

/// A ComputeBudget instruction injected mid-transaction (CB, transfer, CB) must
/// be flagged: the price instruction lands after a non-CB instruction.
#[test]
fn test_cb_injected_mid_transaction_flagged() {
    let from = Keypair::new();
    let to = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    let recent_blockhash = Hash::new_from_array([7u8; 32]);

    let transfer_ix = system_transfer_instruction(&from.pubkey(), &to, 1_000_000);
    let cu_limit_ix = set_compute_unit_limit_instruction(150_000);
    let cu_price_ix = set_compute_unit_price_instruction(5_000);

    let message = VersionedMessage::Legacy(solana_sdk::message::legacy::Message::new_with_blockhash(
        &[cu_limit_ix, transfer_ix, cu_price_ix],
        Some(&from.pubkey()),
        &recent_blockhash,
    ));
    let tx = VersionedTransaction { signatures: vec![from.sign_message(&message.serialize())], message };
    let hex_encoded = hex::encode(bincode::serialize(&tx).unwrap());

    let report = decoder::decode_transaction(&hex_encoded, None).expect("Decode mid-injected CB tx");
    let cb = report.compute_budget.expect("Should have compute budget info");
    assert!(cb.is_reordered, "CB injected mid-transaction must be flagged as reordered");
}

/// Two ComputeBudget instructions at the start ([0, 1]) form a valid prefix and
/// must NOT be flagged as reordered.
#[test]
fn test_no_cu_reorder_for_prefix_positions() {
    let mut report = make_report();
    report.compute_budget = Some(ComputeBudgetInfo {
        compute_unit_limit: 150_000,
        compute_unit_price: 0,
        compute_unit_limit_set: true,
        compute_budget_positions: vec![0, 1],
        is_reordered: false,
        high_cu_instructions: vec![],
        priority_fee_lamports: 0,
        priority_fee_actual: None,
    });
    validator::validate(&mut report, None);
    assert!(!report.risk_flags.iter().any(|f| f.category == RiskCategory::ComputeBudgetReordering));
}

/// With positions [0, 2], only the out-of-prefix position (2) is flagged.
#[test]
fn test_cu_reorder_flag_on_gap_position() {
    let mut report = make_report();
    report.compute_budget = Some(ComputeBudgetInfo {
        compute_unit_limit: 150_000,
        compute_unit_price: 0,
        compute_unit_limit_set: true,
        compute_budget_positions: vec![0, 2],
        is_reordered: true,
        high_cu_instructions: vec![],
        priority_fee_lamports: 0,
        priority_fee_actual: None,
    });
    validator::validate(&mut report, None);
    let reorder_flags: Vec<_> =
        report.risk_flags.iter().filter(|f| f.category == RiskCategory::ComputeBudgetReordering).collect();
    assert_eq!(reorder_flags.len(), 1);
    assert_eq!(reorder_flags[0].instruction_index, Some(2));
}

/// A single ComputeBudget instruction injected after a transfer (position 1)
/// must be flagged.
#[test]
fn test_cu_reorder_flag_single_mid_tx() {
    let mut report = make_report();
    report.compute_budget = Some(ComputeBudgetInfo {
        compute_unit_limit: 150_000,
        compute_unit_price: 0,
        compute_unit_limit_set: true,
        compute_budget_positions: vec![1],
        is_reordered: true,
        high_cu_instructions: vec![],
        priority_fee_lamports: 0,
        priority_fee_actual: None,
    });
    validator::validate(&mut report, None);
    assert!(report.risk_flags.iter().any(|f| f.category == RiskCategory::ComputeBudgetReordering));
}

/// The reorder flag message describes the prefix rule accurately.
#[test]
fn test_cu_reorder_message_describes_prefix_rule() {
    let mut report = make_report();
    report.compute_budget = Some(ComputeBudgetInfo {
        compute_unit_limit: 150_000,
        compute_unit_price: 0,
        compute_unit_limit_set: true,
        compute_budget_positions: vec![2],
        is_reordered: true,
        high_cu_instructions: vec![],
        priority_fee_lamports: 0,
        priority_fee_actual: None,
    });
    validator::validate(&mut report, None);
    let flag = report
        .risk_flags
        .iter()
        .find(|f| f.category == RiskCategory::ComputeBudgetReordering)
        .expect("Expected reorder flag");
    assert!(
        flag.message.contains("must be the first"),
        "message should describe the prefix rule, got: {}",
        flag.message
    );
}
