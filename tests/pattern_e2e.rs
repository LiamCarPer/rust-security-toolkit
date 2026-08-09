use rust_security_toolkit::decoder;
use rust_security_toolkit::patterns;
use rust_security_toolkit::sim_crossref;
use rust_security_toolkit::types::{RiskCategory, RiskFlag, RiskSeverity, SimulationResult, TransactionReport};
use rust_security_toolkit::validator;
use solana_sdk::hash::Hash;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::message::{VersionedMessage, legacy};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature};
use solana_sdk::signer::Signer;
use solana_sdk::transaction::VersionedTransaction;
use std::str::FromStr;

const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";

fn blockhash() -> Hash {
    Hash::new_from_array([7u8; 32])
}

fn system_program() -> Pubkey {
    Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap()
}

fn token_program() -> Pubkey {
    Pubkey::from_str(TOKEN_PROGRAM_ID).unwrap()
}

fn compute_budget_program() -> Pubkey {
    Pubkey::from_str(COMPUTE_BUDGET_PROGRAM_ID).unwrap()
}

fn token_approve_data(amount: u64) -> Vec<u8> {
    let mut data = vec![4u8];
    data.extend_from_slice(&amount.to_le_bytes());
    data
}

fn token_transfer_data(amount: u64) -> Vec<u8> {
    let mut data = vec![3u8];
    data.extend_from_slice(&amount.to_le_bytes());
    data
}

fn token_set_authority_data(new_authority: &Pubkey) -> Vec<u8> {
    let mut data = vec![6u8, 0, 1];
    data.extend_from_slice(&new_authority.to_bytes());
    data
}

fn token_mint_to_checked_data(amount: u64, decimals: u8) -> Vec<u8> {
    let mut data = vec![14u8];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    data
}

fn system_transfer_data(lamports: u64) -> Vec<u8> {
    let mut data = vec![2u8, 0, 0, 0];
    data.extend_from_slice(&lamports.to_le_bytes());
    data
}

fn system_transfer(from: &Keypair, to: &Pubkey, lamports: u64) -> Instruction {
    Instruction {
        program_id: system_program(),
        accounts: vec![AccountMeta::new(from.pubkey(), true), AccountMeta::new(*to, false)],
        data: system_transfer_data(lamports),
    }
}

fn set_compute_unit_limit_instruction(limit: u32) -> Instruction {
    let mut data = vec![2u8];
    data.extend_from_slice(&limit.to_le_bytes());
    Instruction { program_id: compute_budget_program(), accounts: vec![], data }
}

fn set_compute_unit_price_instruction(price: u64) -> Instruction {
    let mut data = vec![3u8];
    data.extend_from_slice(&price.to_le_bytes());
    Instruction { program_id: compute_budget_program(), accounts: vec![], data }
}

fn build_tx(instructions: Vec<Instruction>, payer: &Keypair, extra_signers: &[&Keypair]) -> Vec<u8> {
    let message = VersionedMessage::Legacy(legacy::Message::new_with_blockhash(
        &instructions,
        Some(&payer.pubkey()),
        &blockhash(),
    ));
    let msg_bytes = message.serialize();
    let required = message.header().num_required_signatures as usize;
    let keys = message.static_account_keys();
    let mut signatures: Vec<Signature> = Vec::with_capacity(required);
    for key in keys.iter().take(required) {
        if key == &payer.pubkey() {
            signatures.push(payer.sign_message(&msg_bytes));
        } else if let Some(kp) = extra_signers.iter().find(|kp| kp.pubkey() == *key) {
            signatures.push(kp.sign_message(&msg_bytes));
        } else {
            panic!("no signer supplied for required signer {}", key);
        }
    }
    let tx = VersionedTransaction { signatures, message };
    bincode::serialize(&tx).unwrap()
}

fn decode_report(instructions: Vec<Instruction>, payer: &Keypair, extra_signers: &[&Keypair]) -> TransactionReport {
    let bytes = build_tx(instructions, payer, extra_signers);
    let (_, mut report) = decoder::decode_input(&bytes, None).expect("decode_input should succeed");
    validator::validate(&mut report, None);
    report
}

fn decode_and_validate(instructions: Vec<Instruction>, payer: &Keypair) -> TransactionReport {
    let mut report = decode_report(instructions, payer, &[]);
    report.risk_flags.extend(patterns::detect_patterns(&report));
    report
}

fn pattern_flags(report: &TransactionReport) -> Vec<&RiskFlag> {
    report.risk_flags.iter().filter(|f| f.category == RiskCategory::PatternDetection).collect()
}

#[test]
fn approve_then_transfer_e2e() {
    let payer = Keypair::new();
    let source = Pubkey::new_unique();
    let recipient = Pubkey::new_unique();
    let delegate = Keypair::new();

    let approve = Instruction {
        program_id: token_program(),
        accounts: vec![
            AccountMeta::new(source, false),
            AccountMeta::new(delegate.pubkey(), true),
            AccountMeta::new_readonly(payer.pubkey(), true),
        ],
        data: token_approve_data(1_000),
    };
    let transfer = Instruction {
        program_id: token_program(),
        accounts: vec![
            AccountMeta::new(source, false),
            AccountMeta::new(recipient, false),
            AccountMeta::new_readonly(delegate.pubkey(), true),
        ],
        data: token_transfer_data(500),
    };

    let mut report = decode_report(vec![approve, transfer], &payer, &[&delegate]);
    report.risk_flags.extend(patterns::detect_patterns(&report));

    let warnings: Vec<_> = pattern_flags(&report).into_iter().filter(|f| f.severity == RiskSeverity::Warning).collect();
    assert_eq!(warnings.len(), 1, "flags: {:?}", report.risk_flags);
    assert_eq!(warnings[0].instruction_index, Some(1));
    assert!(warnings[0].message.contains("#0"));
    assert!(warnings[0].message.contains("#1"));
    assert!(warnings[0].message.contains("authorizes delegate"));
}

#[test]
fn approve_without_spend_not_flagged_e2e() {
    let payer = Keypair::new();
    let source = Pubkey::new_unique();
    let delegate = Keypair::new();

    let approve = Instruction {
        program_id: token_program(),
        accounts: vec![
            AccountMeta::new(source, false),
            AccountMeta::new(delegate.pubkey(), false),
            AccountMeta::new_readonly(payer.pubkey(), true),
        ],
        data: token_approve_data(1_000),
    };

    let report = decode_and_validate(vec![approve], &payer);

    assert_eq!(pattern_flags(&report).len(), 0, "flags: {:?}", report.risk_flags);
}

#[test]
fn nonsigner_transfer_authority_e2e() {
    let payer = Keypair::new();
    let source = Pubkey::new_unique();
    let recipient = Pubkey::new_unique();
    let authority = Pubkey::new_unique();

    let transfer = Instruction {
        program_id: token_program(),
        accounts: vec![
            AccountMeta::new(source, false),
            AccountMeta::new(recipient, false),
            AccountMeta::new_readonly(authority, false),
        ],
        data: token_transfer_data(500),
    };

    let report = decode_and_validate(vec![transfer], &payer);

    let warnings: Vec<_> = pattern_flags(&report).into_iter().filter(|f| f.severity == RiskSeverity::Warning).collect();
    assert_eq!(warnings.len(), 1, "flags: {:?}", report.risk_flags);
    assert_eq!(warnings[0].instruction_index, Some(0));
    assert!(warnings[0].message.contains("does not sign"));
}

#[test]
fn fee_payer_as_recipient_e2e() {
    let payer = Keypair::new();
    let from = Keypair::new();
    let to = payer.pubkey();

    let transfer = Instruction {
        program_id: system_program(),
        accounts: vec![AccountMeta::new(from.pubkey(), true), AccountMeta::new(to, false)],
        data: system_transfer_data(1_000_000),
    };

    let mut report = decode_report(vec![transfer], &payer, &[&from]);
    report.risk_flags.extend(patterns::detect_patterns(&report));

    let infos: Vec<_> = pattern_flags(&report).into_iter().filter(|f| f.severity == RiskSeverity::Info).collect();
    assert_eq!(infos.len(), 1, "flags: {:?}", report.risk_flags);
    assert!(infos[0].message.contains("fee payer"));
}

#[test]
fn mint_authority_takeover_e2e() {
    let payer = Keypair::new();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let new_authority = Keypair::new();

    let set_authority = Instruction {
        program_id: token_program(),
        accounts: vec![AccountMeta::new(mint, false), AccountMeta::new_readonly(payer.pubkey(), true)],
        data: token_set_authority_data(&new_authority.pubkey()),
    };
    let mint_to = Instruction {
        program_id: token_program(),
        accounts: vec![
            AccountMeta::new(mint, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(new_authority.pubkey(), true),
        ],
        data: token_mint_to_checked_data(1_000, 9),
    };

    let mut report = decode_report(vec![set_authority, mint_to], &payer, &[&new_authority]);
    report.risk_flags.extend(patterns::detect_patterns(&report));

    let warnings: Vec<_> = pattern_flags(&report).into_iter().filter(|f| f.severity == RiskSeverity::Warning).collect();
    assert_eq!(warnings.len(), 1, "flags: {:?}", report.risk_flags);
    assert_eq!(warnings[0].instruction_index, Some(0));
    assert!(warnings[0].message.contains("takeover"));
    assert!(warnings[0].message.contains("#1"));
}

#[test]
fn repeated_destination_e2e() {
    let payer = Keypair::new();
    let from_a = Keypair::new();
    let from_b = Keypair::new();
    let recipient = Pubkey::new_unique();

    let ix_a = system_transfer(&from_a, &recipient, 1_000_000);
    let ix_b = system_transfer(&from_b, &recipient, 2_000_000);

    let mut report = decode_report(vec![ix_a, ix_b], &payer, &[&from_a, &from_b]);
    report.risk_flags.extend(patterns::detect_patterns(&report));

    let infos: Vec<_> = pattern_flags(&report).into_iter().filter(|f| f.severity == RiskSeverity::Info).collect();
    assert_eq!(infos.len(), 1, "flags: {:?}", report.risk_flags);
    assert_eq!(infos[0].instruction_index, Some(0));
    assert!(infos[0].message.contains("receives funds in multiple"));
}

#[test]
fn priority_fee_actual_crossref_e2e() {
    let payer = Keypair::new();
    let recipient = Pubkey::new_unique();

    let price = set_compute_unit_price_instruction(5_000);
    let limit = set_compute_unit_limit_instruction(200_000);
    let transfer = system_transfer(&payer, &recipient, 1_000_000);

    let mut report = decode_report(vec![price, limit, transfer], &payer, &[]);
    report.simulation = Some(SimulationResult {
        success: true,
        error: None,
        logs: vec![
            format!("Program {} invoke [1]", COMPUTE_BUDGET_PROGRAM_ID),
            format!("Program {} invoke [2]", COMPUTE_BUDGET_PROGRAM_ID),
            format!("Program {} invoke [3]", SYSTEM_PROGRAM_ID),
            format!("Program {} success", SYSTEM_PROGRAM_ID),
        ],
        units_consumed: 120_000,
        return_data: None,
        error_code: None,
        error_instruction_index: None,
        instruction_cu: Vec::new(),
    });

    let flags = sim_crossref::cross_reference(&mut report);
    assert!(flags.is_empty(), "unexpected flags: {:?}", flags);
    let cb = report.compute_budget.as_ref().expect("compute budget present");
    assert_eq!(cb.priority_fee_actual, Some(600));
    assert!(!report.risk_flags.iter().any(|f| f.message.contains("program invocations")));
    assert!(!report.risk_flags.iter().any(|f| f.message.contains("declared limit")));
}

#[test]
fn cu_exceeded_crossref_e2e() {
    let payer = Keypair::new();
    let recipient = Pubkey::new_unique();

    let price = set_compute_unit_price_instruction(5_000);
    let limit = set_compute_unit_limit_instruction(200_000);
    let transfer = system_transfer(&payer, &recipient, 1_000_000);

    let mut report = decode_report(vec![price, limit, transfer], &payer, &[]);
    report.simulation = Some(SimulationResult {
        success: true,
        error: None,
        logs: vec![
            format!("Program {} invoke [1]", COMPUTE_BUDGET_PROGRAM_ID),
            format!("Program {} invoke [2]", COMPUTE_BUDGET_PROGRAM_ID),
            format!("Program {} invoke [3]", SYSTEM_PROGRAM_ID),
            format!("Program {} success", SYSTEM_PROGRAM_ID),
        ],
        units_consumed: 250_000,
        return_data: None,
        error_code: None,
        error_instruction_index: None,
        instruction_cu: Vec::new(),
    });

    let flags = sim_crossref::cross_reference(&mut report);
    assert_eq!(flags.len(), 1, "flags: {:?}", flags);
    assert_eq!(flags[0].category, RiskCategory::SimulationMismatch);
    assert_eq!(flags[0].severity, RiskSeverity::Warning);
    assert!(flags[0].message.contains("declared limit"));
}

#[test]
fn clean_offline_transaction_has_no_flags_e2e() {
    let payer = Keypair::new();
    let recipient = Pubkey::new_unique();

    let limit = set_compute_unit_limit_instruction(200_000);
    let transfer = system_transfer(&payer, &recipient, 1_000_000);

    let mut report = decode_report(vec![limit, transfer], &payer, &[]);
    report.risk_flags.extend(patterns::detect_patterns(&report));
    let cross_flags = sim_crossref::cross_reference(&mut report);
    report.risk_flags.extend(cross_flags);

    assert!(report.risk_flags.is_empty(), "flags: {:?}", report.risk_flags);
}
