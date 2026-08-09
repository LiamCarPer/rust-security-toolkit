//! End-to-end cross-tool test: `rts` tx-report → `sat` correlation.
//!
//! Builds a transaction whose `transfer_tokens` instruction carries a
//! NON-signer authority (while the IDL declares isSigner=true), emits the
//! report with `rts --output-tx-report`, feeds it to `sat analyze src`, and
//! asserts sat reports the signer mismatch as a Critical finding.
//!
//! Requires the sat binary. Run with:
//!   SAT_BIN=/path/to/sat cargo test --test e2e_sat -- --ignored

use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    message::{VersionedMessage, legacy},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use std::io::Write;
use std::process::Command;

fn write_file(path: &std::path::Path, contents: &str) {
    let mut f = std::fs::File::create(path).expect("create temp file");
    f.write_all(contents.as_bytes()).expect("write temp file");
}

const IDL_JSON: &str = r#"{
  "version": "0.1.0",
  "name": "e2e_program",
  "instructions": [
    {
      "name": "transfer_tokens",
      "accounts": [
        {"name": "from", "isMut": true, "isSigner": false},
        {"name": "authority", "isMut": false, "isSigner": true}
      ],
      "args": []
    }
  ],
  "accounts": [],
  "types": []
}"#;

const PROGRAM_SOURCE: &str = r#"use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct TransferTokens<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(signer)]
    pub authority: AccountInfo<'info>,
}
"#;

#[test]
#[ignore]
fn e2e_sat_correlation_finds_signer_mismatch() {
    let sat_bin = std::env::var("SAT_BIN").expect("SAT_BIN env var must point at the sat binary");
    let rts_bin = std::env::var("CARGO_BIN_EXE_rts").expect("CARGO_BIN_EXE_rts must be set");

    // ── Build a transaction: authority is NOT a signer in the message ────────
    let program_id = Pubkey::new_from_array([1u8; 32]);
    let payer = Keypair::new();
    let from = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let recent_blockhash = Hash::new_from_array([7u8; 32]);

    let discriminator = rust_security_toolkit::anchor_decoder::compute_anchor_discriminator("transfer_tokens");
    let ix = Instruction {
        program_id,
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(from, false),
            solana_sdk::instruction::AccountMeta::new_readonly(authority, false),
        ],
        data: discriminator.to_vec(),
    };
    let message =
        VersionedMessage::Legacy(legacy::Message::new_with_blockhash(&[ix], Some(&payer.pubkey()), &recent_blockhash));
    let tx = VersionedTransaction { signatures: vec![payer.sign_message(&message.serialize())], message };
    let tx_hex = hex::encode(bincode::serialize(&tx).unwrap());

    // ── Write fixtures to a temp dir ─────────────────────────────────────────
    let dir = std::env::temp_dir().join(format!("rts_e2e_sat_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("create temp dir");
    write_file(&dir.join("tx.hex"), &tx_hex);
    write_file(&dir.join("idl.json"), IDL_JSON);
    write_file(&dir.join("src/program.rs"), PROGRAM_SOURCE);

    // ── 1. rts: produce the tx-report ────────────────────────────────────────
    let report_path = dir.join("report.json");
    let rts_out = Command::new(&rts_bin)
        .arg("--idl")
        .arg(dir.join("idl.json"))
        .arg("--output-tx-report")
        .arg(&report_path)
        .arg(&tx_hex)
        .output()
        .expect("run rts");
    // The tx intentionally carries a non-signer authority, so rts itself
    // flags it Critical (exit 2); the report must still be written.
    assert_eq!(
        rts_out.status.code(),
        Some(2),
        "rts must exit 2 on the missing signer: {}",
        String::from_utf8_lossy(&rts_out.stderr)
    );
    assert!(report_path.exists(), "rts did not write the tx-report");

    // ── 2. sat: correlate against the declared constraints ──────────────────
    let sat_out = Command::new(&sat_bin)
        .arg("analyze")
        .arg("src")
        .arg(dir.join("src"))
        .arg("--tx-report")
        .arg(&report_path)
        .output()
        .expect("run sat");
    let stdout = String::from_utf8_lossy(&sat_out.stdout);

    assert!(sat_out.status.success(), "sat failed: {}\n{}", String::from_utf8_lossy(&sat_out.stderr), stdout);
    assert!(stdout.contains("Tx-Report Mismatch"), "sat did not report a Tx-Report Mismatch:\n{}", stdout);
    assert!(
        stdout.contains("authority") && stdout.contains("is_signer = false"),
        "sat mismatch does not mention the authority signer issue:\n{}",
        stdout
    );
    assert!(!stdout.contains("Failed to parse tx-report"), "sat could not parse the rts report:\n{}", stdout);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Native cross-tool loop: sat exports expectations from native source,
/// rts validates a synthetic Mango-style tx against them and writes the
/// tx-report, sat correlates the report against the same source.
///
/// The fixture authority is guarded by `if !authority.is_signer` in the
/// source, but the transaction builds it as a NON-signer, so both rts
/// (expectations signer role) and sat (source signer guard) must flag it.
#[test]
#[ignore]
fn e2e_sat_native_correlation_finds_signer_mismatch() {
    let sat_bin = std::env::var("SAT_BIN").expect("SAT_BIN env var must point at the sat binary");
    let rts_bin = std::env::var("CARGO_BIN_EXE_rts").expect("CARGO_BIN_EXE_rts must be set");

    const NATIVE_SOURCE: &str = r#"use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    match instruction_data[0] {
        0 => process_transfer(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_transfer(accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let from = next_account_info(accounts_iter)?;
    let authority = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut data = vault.data.borrow_mut();
    data[0] = 1;

    Ok(())
}
"#;

    let program_id = Pubkey::new_from_array([1u8; 32]);
    let payer = Keypair::new();
    let from = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let vault = Pubkey::new_unique();
    let recent_blockhash = Hash::new_from_array([7u8; 32]);

    // Tag 0 = process_transfer; authority deliberately NOT a signer.
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(from, false),
            AccountMeta::new_readonly(authority, false),
            AccountMeta::new(vault, false),
        ],
        data: vec![0x00],
    };
    let message =
        VersionedMessage::Legacy(legacy::Message::new_with_blockhash(&[ix], Some(&payer.pubkey()), &recent_blockhash));
    let tx = VersionedTransaction { signatures: vec![payer.sign_message(&message.serialize())], message };
    let tx_hex = hex::encode(bincode::serialize(&tx).unwrap());

    let dir = std::env::temp_dir().join(format!("rts_e2e_sat_native_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("create temp dir");
    write_file(&dir.join("tx.hex"), &tx_hex);
    write_file(&dir.join("src/program.rs"), NATIVE_SOURCE);

    // ── 1. sat: export the native expectations from source ──────────────────
    let expectations_path = dir.join("expectations.json");
    let report_path = dir.join("report.json");

    let sat_export = Command::new(&sat_bin)
        .arg("analyze")
        .arg("src")
        .arg(dir.join("src"))
        .arg("--expectations")
        .arg(&expectations_path)
        .output()
        .expect("run sat (export)");
    assert!(sat_export.status.success(), "sat export failed: {}", String::from_utf8_lossy(&sat_export.stderr));
    assert!(expectations_path.exists(), "sat did not export expectations");

    // ── 2. rts: validate the tx against the export, write the report ────────
    let rts_out = Command::new(&rts_bin)
        .arg("--expectations")
        .arg(&expectations_path)
        .arg("--output-tx-report")
        .arg(&report_path)
        .arg(&tx_hex)
        .output()
        .expect("run rts");
    // Exit 2 expected: rts flags the missing signer itself.
    assert_eq!(
        rts_out.status.code(),
        Some(2),
        "rts must exit 2 on the missing signer: {}",
        String::from_utf8_lossy(&rts_out.stderr)
    );
    assert!(report_path.exists(), "rts did not write the tx-report");

    // ── 3. sat: correlate the report against the same source ────────────────
    let sat_out = Command::new(&sat_bin)
        .arg("analyze")
        .arg("src")
        .arg(dir.join("src"))
        .arg("--tx-report")
        .arg(&report_path)
        .output()
        .expect("run sat (correlate)");
    let stdout = String::from_utf8_lossy(&sat_out.stdout);

    assert!(sat_out.status.success(), "sat failed: {}\n{}", String::from_utf8_lossy(&sat_out.stderr), stdout);
    assert!(stdout.contains("Tx-Report Mismatch"), "sat did not report a Tx-Report Mismatch:\n{}", stdout);
    assert!(
        stdout.contains("authority") && stdout.contains("is_signer = false"),
        "sat mismatch does not mention the authority signer issue:\n{}",
        stdout
    );
    assert!(!stdout.contains("Failed to parse tx-report"), "sat could not parse the rts report:\n{}", stdout);

    let _ = std::fs::remove_dir_all(&dir);
}
