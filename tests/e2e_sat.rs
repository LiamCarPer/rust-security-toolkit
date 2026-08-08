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
    instruction::Instruction,
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
    assert!(rts_out.status.success(), "rts failed: {}", String::from_utf8_lossy(&rts_out.stderr));

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
