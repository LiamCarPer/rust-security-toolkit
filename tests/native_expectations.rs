//! Integration tests for the native program "expectations" feature (sat
//! `--expectations` export as the native analog of an Anchor IDL).
//!
//! Builds synthetic transactions against the committed fixture
//! `tests/fixtures/native_expectations.json` (a Mango-style program) and
//! asserts the decoder's discriminator matching, account-name annotation, and
//! the validator's native tier-1/tier-2 checks (PDA well-formedness, PDA seed
//! cross-check, missing signer, writable role, account count).

use rust_security_toolkit::decoder;
use rust_security_toolkit::types::*;
use rust_security_toolkit::validator;
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    message::{VersionedMessage, legacy},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use std::str::FromStr;

/// The deterministic program id the fixture's `program_id` field must equal
/// (base58 of `Pubkey::new_from_array([1u8; 32])`).
fn fixture_program_id() -> Pubkey {
    Pubkey::new_from_array([1u8; 32])
}

/// Load and parse the committed native expectations fixture.
fn load_doc() -> ExpectationsDoc {
    let json = std::fs::read_to_string("tests/fixtures/native_expectations.json").expect("read expectations fixture");
    serde_json::from_str(&json).expect("parse expectations fixture")
}

/// Serialize a transaction (hex-encoded) from raw instructions.
fn build_tx_hex(instructions: &[Instruction]) -> String {
    let payer = Keypair::new();
    let recent_blockhash = Hash::new_from_array([7u8; 32]);
    let message = VersionedMessage::Legacy(legacy::Message::new_with_blockhash(
        instructions,
        Some(&payer.pubkey()),
        &recent_blockhash,
    ));
    let tx = VersionedTransaction { signatures: vec![payer.sign_message(&message.serialize())], message };
    hex::encode(bincode::serialize(&tx).unwrap())
}

/// Build a single-instruction transaction (hex-encoded).
fn build_tx(program_id: Pubkey, metas: Vec<AccountMeta>, data: Vec<u8>) -> String {
    build_tx_hex(&[Instruction { program_id, accounts: metas, data }])
}

/// Decode + validate a hex transaction under the schema, returning the report.
fn decode_and_validate(tx_hex: &str, schema: &ProgramSchema) -> TransactionReport {
    let (_, mut report) = decoder::decode_input(tx_hex.as_bytes(), Some(schema)).expect("decode with expectations");
    validator::validate(&mut report, Some(schema));
    report
}

/// Risk flags of one category.
fn native_flags<'a>(report: &'a TransactionReport, cat: &RiskCategory) -> Vec<&'a RiskFlag> {
    report.risk_flags.iter().filter(|f| f.category == *cat).collect()
}

/// No native-expectations flags of any category fired.
fn assert_no_native_flags(report: &TransactionReport) {
    for cat in [
        RiskCategory::MissingSigner,
        RiskCategory::PdaSeedMismatch,
        RiskCategory::WritableMismatch,
        RiskCategory::NativeAccountMismatch,
        RiskCategory::PdaWellFormedness,
    ] {
        assert!(native_flags(report, &cat).is_empty(), "unexpected native flag: {:?}", cat);
    }
}

/// WithdrawMsrm account metas: [mango_group readonly, owner (signer per
/// `owner_is_signer`, readonly like the real Mango shape), vault (writable
/// per `vault_is_writable`)].
fn msrm_metas(owner_is_signer: bool, vault_is_writable: bool) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new_readonly(Pubkey::new_unique(), false),
        AccountMeta::new_readonly(Pubkey::new_unique(), owner_is_signer),
        if vault_is_writable {
            AccountMeta::new(Pubkey::new_unique(), false)
        } else {
            AccountMeta::new_readonly(Pubkey::new_unique(), false)
        },
    ]
}

// ── WithdrawMsrm: signer / writable roles ───────────────────────────────────

#[test]
fn withdraw_msrm_correct_signers_no_flags() {
    let doc = load_doc();
    // The fixture's program_id must be the base58 of the deterministic pubkey.
    assert_eq!(
        fixture_program_id().to_string(),
        doc.program_id.as_deref().expect("fixture program_id"),
        "fixture program_id must equal Pubkey::new_from_array([1u8; 32]) as base58"
    );
    let schema = ProgramSchema::Native(doc);

    let tx_hex = build_tx(fixture_program_id(), msrm_metas(true, true), vec![0x24]);
    let report = decode_and_validate(&tx_hex, &schema);

    assert_eq!(report.instructions[0].instruction_name.as_deref(), Some("WithdrawMsrm"));
    assert_eq!(report.instructions[0].accounts[0].name.as_deref(), Some("mango_group_ai"));
    assert_eq!(report.instructions[0].accounts[1].name.as_deref(), Some("owner_ai"));
    assert_eq!(report.instructions[0].accounts[2].name.as_deref(), Some("vault_ai"));
    assert_no_native_flags(&report);
}

#[test]
fn withdraw_msrm_missing_signer_critical() {
    let schema = ProgramSchema::Native(load_doc());

    let tx_hex = build_tx(fixture_program_id(), msrm_metas(false, true), vec![0x24]);
    let report = decode_and_validate(&tx_hex, &schema);

    let missing = native_flags(&report, &RiskCategory::MissingSigner);
    assert_eq!(missing.len(), 1, "exactly one MissingSigner flag");
    assert_eq!(missing[0].severity, RiskSeverity::Critical, "missing signer is exit-code-relevant");
    assert!(missing[0].message.contains("owner_ai"), "message: {}", missing[0].message);
}

#[test]
fn withdraw_msrm_writable_mismatch_warning() {
    let schema = ProgramSchema::Native(load_doc());

    let tx_hex = build_tx(fixture_program_id(), msrm_metas(true, false), vec![0x24]);
    let report = decode_and_validate(&tx_hex, &schema);

    let writable = native_flags(&report, &RiskCategory::WritableMismatch);
    assert_eq!(writable.len(), 1, "exactly one WritableMismatch flag");
    assert_eq!(writable[0].severity, RiskSeverity::Warning);
    assert!(writable[0].message.contains("vault_ai"), "message: {}", writable[0].message);
    // The signer still signs; only the writable role is wrong.
    assert!(native_flags(&report, &RiskCategory::MissingSigner).is_empty());
}

// ── withdraw_escrow: PDA seed cross-check (tier 2) ───────────────────────────

/// The doc's program_id is the fixture's [1u8; 32] gate; these tests run a
/// *different* deterministic program id, so they build a local doc and
/// override `program_id` to match the tx (as the prompt dictates).
fn escrow_schema(program_id: &Pubkey) -> ProgramSchema {
    let mut doc = load_doc();
    doc.program_id = Some(program_id.to_string());
    ProgramSchema::Native(doc)
}

fn escrow_metas(escrow: Pubkey) -> Vec<AccountMeta> {
    // authority is a readonly signer (real Mango shape); the writable-header
    // derivation handles readonly signers since 98020e5.
    vec![AccountMeta::new(escrow, false), AccountMeta::new_readonly(Pubkey::new_unique(), true)]
}

#[test]
fn withdraw_escrow_pda_mismatch_critical() {
    let program_id = Pubkey::new_from_array([2u8; 32]);
    let schema = escrow_schema(&program_id);

    let escrow = Pubkey::new_unique(); // NOT the derived PDA.
    let (expected, bump) = Pubkey::find_program_address(&[b"escrow"], &program_id);

    let tx_hex = build_tx(program_id, escrow_metas(escrow), vec![0x25]);
    let report = decode_and_validate(&tx_hex, &schema);

    let mismatches = native_flags(&report, &RiskCategory::PdaSeedMismatch);
    assert_eq!(mismatches.len(), 1, "exactly one PdaSeedMismatch flag");
    assert_eq!(mismatches[0].severity, RiskSeverity::Critical);

    // pda_info lands on the escrow AccountInfo with the derived address + bump.
    let escrow_info =
        report.accounts.iter().find(|a| a.pubkey == escrow.to_string()).expect("escrow account present in report");
    let pda = escrow_info.pda_info.as_ref().expect("pda_info populated");
    assert_eq!(pda.expected_address.as_deref(), Some(expected.to_string().as_str()));
    assert_eq!(pda.bump, Some(bump));
}

#[test]
fn withdraw_escrow_pda_match_no_flags() {
    let program_id = Pubkey::new_from_array([2u8; 32]);
    let schema = escrow_schema(&program_id);

    let (escrow, bump) = Pubkey::find_program_address(&[b"escrow"], &program_id);

    let tx_hex = build_tx(program_id, escrow_metas(escrow), vec![0x25]);
    let report = decode_and_validate(&tx_hex, &schema);

    assert!(native_flags(&report, &RiskCategory::PdaSeedMismatch).is_empty(), "matching PDA must not flag");
    let escrow_info =
        report.accounts.iter().find(|a| a.pubkey == escrow.to_string()).expect("escrow account present in report");
    let pda = escrow_info.pda_info.as_ref().expect("pda_info still populated on match");
    assert_eq!(pda.expected_address.as_deref(), Some(escrow.to_string().as_str()));
    assert_eq!(pda.bump, Some(bump));
}

// ── withdraw_dynamic: runtime-value seeds cannot be verified statically ──────

#[test]
fn withdraw_dynamic_cannot_verify_warning() {
    let program_id = Pubkey::new_from_array([2u8; 32]);
    let schema = escrow_schema(&program_id);

    let escrow = Pubkey::find_program_address(&[b"escrow"], &program_id).0;
    let metas = vec![AccountMeta::new_readonly(escrow, false)];

    let tx_hex = build_tx(program_id, metas, vec![0x26]);
    let report = decode_and_validate(&tx_hex, &schema);

    let mismatches = native_flags(&report, &RiskCategory::PdaSeedMismatch);
    assert_eq!(mismatches.len(), 1, "exactly one PdaSeedMismatch flag");
    assert_eq!(mismatches[0].severity, RiskSeverity::Warning);
    assert!(mismatches[0].message.contains("runtime values"), "message: {}", mismatches[0].message);
    assert!(!report.risk_flags.iter().any(|f| f.severity == RiskSeverity::Critical), "no Critical flags");
}

// ── Discriminator matching and program_id gating ─────────────────────────────

#[test]
fn unknown_discriminator_no_match() {
    let schema = ProgramSchema::Native(load_doc());

    let tx_hex = build_tx(fixture_program_id(), msrm_metas(true, true), vec![0x99]);
    let report = decode_and_validate(&tx_hex, &schema);

    assert_eq!(report.instructions[0].instruction_name, None, "0x99 matches no declared discriminator");
    assert_eq!(report.instructions[0].accounts[0].name, None, "no annotation without a match");
    assert_no_native_flags(&report);
}

#[test]
fn program_id_gate_blocks_other_program() {
    let schema = ProgramSchema::Native(load_doc());
    let other_program = Pubkey::new_from_array([9u8; 32]);

    let tx_hex = build_tx(other_program, msrm_metas(true, true), vec![0x24]);
    let report = decode_and_validate(&tx_hex, &schema);

    assert_eq!(report.instructions[0].instruction_name, None, "doc program_id gate must block other programs");
    assert_no_native_flags(&report);
}

#[test]
fn mango_style_1byte_tag_round_trip() {
    let schema = ProgramSchema::Native(load_doc());

    let tx_hex = build_tx(fixture_program_id(), msrm_metas(true, true), vec![0x24, 1, 2, 3]);
    let (bytes, mut report) =
        decoder::decode_input(tx_hex.as_bytes(), Some(&schema)).expect("decode_input hex round trip");
    assert!(!bytes.is_empty(), "round trip must return the raw bytes");
    validator::validate(&mut report, Some(&schema));

    assert_eq!(report.instructions[0].instruction_name.as_deref(), Some("WithdrawMsrm"));
    assert_eq!(report.instructions[0].accounts[1].name.as_deref(), Some("owner_ai"));
    assert_no_native_flags(&report);
}

// ── Account count and tier-1 well-formedness ─────────────────────────────────

#[test]
fn account_count_mismatch_warning() {
    let schema = ProgramSchema::Native(load_doc());

    let mut metas = msrm_metas(true, true);
    metas.push(AccountMeta::new_readonly(Pubkey::new_unique(), false));
    let tx_hex = build_tx(fixture_program_id(), metas, vec![0x24]);
    let report = decode_and_validate(&tx_hex, &schema);

    let count = native_flags(&report, &RiskCategory::NativeAccountMismatch);
    assert_eq!(count.len(), 1, "exactly one NativeAccountMismatch flag");
    assert_eq!(count[0].severity, RiskSeverity::Warning);
}

#[test]
fn tier1_empty_pda_seeds_warning() {
    // Local doc: append an instruction declaring a PDA with an empty seeds
    // array and no dynamic seeds (discriminator 27, distinct from 24/25/26).
    let mut doc = load_doc();
    doc.instructions.push(ExpectationInstruction {
        name: "withdraw_empty".to_string(),
        discriminator_hex: Some("27".to_string()),
        handler: "withdraw_empty".to_string(),
        accounts: vec![ExpectationAccount {
            name: "empty_pda".to_string(),
            index: 0,
            is_signer_expected: false,
            is_writable_expected: false,
            pda: Some(ExpectationPda { seeds: Vec::new(), dynamic_seed_count: 0 }),
        }],
    });
    let schema = ProgramSchema::Native(doc);

    let metas = vec![AccountMeta::new_readonly(Pubkey::new_unique(), false)];
    let tx_hex = build_tx(fixture_program_id(), metas, vec![0x27]);
    let report = decode_and_validate(&tx_hex, &schema);

    let wellformed = native_flags(&report, &RiskCategory::PdaWellFormedness);
    assert_eq!(wellformed.len(), 1, "exactly one PdaWellFormedness flag");
    assert_eq!(wellformed[0].severity, RiskSeverity::Warning);
    assert!(wellformed[0].message.contains("withdraw_empty"), "message: {}", wellformed[0].message);
    assert!(wellformed[0].message.contains("empty_pda"), "message: {}", wellformed[0].message);
}

// ── Cross-program transactions ───────────────────────────────────────────────

#[test]
fn cross_program_instruction_not_named() {
    let schema = ProgramSchema::Native(load_doc());

    // System transfer (known program, data tag 2 = Transfer).
    let payer = Keypair::new();
    let mut system_data = vec![0u8; 12];
    system_data[0..4].copy_from_slice(&2u32.to_le_bytes());
    system_data[4..12].copy_from_slice(&1_000_000u64.to_le_bytes());
    let system_ix = Instruction {
        program_id: Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap(),
        accounts: vec![AccountMeta::new(payer.pubkey(), true), AccountMeta::new(Pubkey::new_unique(), false)],
        data: system_data,
    };

    // Mango WithdrawMsrm alongside it.
    let mango_ix = Instruction { program_id: fixture_program_id(), accounts: msrm_metas(true, true), data: vec![0x24] };

    let tx_hex = build_tx_hex(&[system_ix, mango_ix]);
    let report = decode_and_validate(&tx_hex, &schema);

    assert_eq!(report.instructions.len(), 2);
    assert_eq!(report.instructions[0].program_name, "System Program");
    assert_eq!(report.instructions[0].instruction_name.as_deref(), Some("Transfer"));
    assert_eq!(report.instructions[1].instruction_name.as_deref(), Some("WithdrawMsrm"));
    assert!(native_flags(&report, &RiskCategory::MissingSigner).is_empty());
}
