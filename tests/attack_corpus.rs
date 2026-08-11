use base64::Engine;
use rust_security_toolkit::decoder;
use rust_security_toolkit::inner_instructions;
use rust_security_toolkit::patterns;
use rust_security_toolkit::signature_verify;
use rust_security_toolkit::types::{
    FetchedTxLoadedAddresses, FetchedTxMeta, RiskCategory, RiskFlag, RiskSeverity, TxMetaInnerInstructions,
    TxMetaRawInnerInstruction,
};
use rust_security_toolkit::validator;
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::RpcBlockConfig;
use solana_sdk::hash::Hash;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::message::{VersionedMessage, legacy};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature};
use solana_sdk::signer::Signer;
use solana_sdk::transaction::VersionedTransaction;
use solana_transaction_status_client_types::{
    EncodedTransaction, TransactionBinaryEncoding, TransactionDetails, UiInnerInstructions, UiInstruction,
    UiLoadedAddresses, UiTransactionEncoding, UiTransactionError, UiTransactionStatusMeta,
};
use std::str::FromStr;
use std::time::Duration;

const MAINNET_RPC: &str = "https://api.mainnet-beta.solana.com";
const FIXTURE_DIR: &str = "tests/fixtures/mainnet_attacks";
const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const MAX_FIXTURES: usize = 10;
const MIN_FIXTURES: usize = 3;

#[derive(Debug, Serialize, Deserialize)]
struct ManifestEntry {
    file: String,
    signature: String,
    source: String,
    expected_categories: Vec<String>,
    expected_min_flags: usize,
    notes: String,
    #[serde(default)]
    failed: bool,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Clone)]
struct Candidate {
    base64: String,
    signature: String,
    rules: Vec<String>,
    notes: String,
    source: &'static str,
    failed: bool,
    error: Option<String>,
    meta: FetchedTxMeta,
}

#[test]
#[ignore]
fn fetch_attack_corpus() {
    std::fs::create_dir_all(FIXTURE_DIR).expect("failed to create attack fixture directory");
    clean_fixture_dir();

    let rpc = RpcClient::new_with_timeout(MAINNET_RPC.to_string(), Duration::from_secs(120));
    let Some(latest_slot) = with_retries("get_slot", || rpc.get_slot().map_err(|e| e.to_string())) else {
        eprintln!("RPC unavailable: no mainnet attack corpus fetched.");
        return;
    };
    eprintln!("latest slot: {}", latest_slot);

    let mut candidates: Vec<Candidate> = Vec::new();
    let mut scanned = 0usize;

    for offset in (10..=80).step_by(10) {
        if candidates.len() >= MAX_FIXTURES {
            break;
        }
        scanned += 1;
        scan_block(&rpc, latest_slot.saturating_sub(offset), &mut candidates);
    }

    if candidates.len() < MIN_FIXTURES {
        eprintln!("only {} candidate(s) in latest-80; extending scan to latest-200", candidates.len());
        for offset in (90..=200).step_by(5) {
            if candidates.len() >= MAX_FIXTURES {
                break;
            }
            scanned += 1;
            scan_block(&rpc, latest_slot.saturating_sub(offset), &mut candidates);
        }
    }

    eprintln!("scanned {} blocks, collected {} candidates", scanned, candidates.len());

    let mut chosen = vec![false; candidates.len()];
    let mut selected: Vec<Candidate> = Vec::new();
    for rule in [
        "mint_authority_takeover",
        "approve_then_transfer",
        "nonsigner_transfer_authority",
        "fee_payer_recipient",
        "repeated_destination",
    ] {
        if selected.len() >= MAX_FIXTURES {
            break;
        }
        if let Some(pos) =
            candidates.iter().enumerate().position(|(i, c)| !chosen[i] && c.rules.iter().any(|r| r.as_str() == rule))
        {
            chosen[pos] = true;
            selected.push(candidates[pos].clone());
        }
    }
    for (i, candidate) in candidates.iter().enumerate() {
        if selected.len() >= MAX_FIXTURES {
            break;
        }
        if !chosen[i] {
            chosen[i] = true;
            selected.push(candidate.clone());
        }
    }

    if selected.is_empty() {
        eprintln!("no real mainnet attack-shaped transactions found; saving synthetic fallback fixtures");
        selected = build_synthetic_fixtures();
    }

    let manifest: Vec<ManifestEntry> = selected
        .iter()
        .enumerate()
        .map(|(idx, candidate)| {
            let file = format!("{idx:02}.b64");
            let bytes = base64::engine::general_purpose::STANDARD.decode(&candidate.base64).expect("fixture base64");
            let (_, mut report) = decoder::decode_input(&bytes, None).expect("fixture decode");
            inner_instructions::annotate_report(&mut report, candidate.meta.clone());
            validator::validate(&mut report, None);
            let flags = patterns::detect_patterns(&report);
            let pattern_fired = flags.iter().any(|f| rule_name(f).is_some());
            let (expected_categories, expected_min_flags) = if candidate.failed && !pattern_fired {
                (Vec::new(), 0)
            } else {
                (vec!["pattern_detection".to_string()], flags.len())
            };
            ManifestEntry {
                file,
                signature: candidate.signature.clone(),
                source: candidate.source.to_string(),
                expected_categories,
                expected_min_flags,
                notes: candidate.notes.clone(),
                failed: candidate.failed,
                error: candidate.error.clone(),
            }
        })
        .collect();

    for (entry, candidate) in manifest.iter().zip(&selected) {
        std::fs::write(format!("{}/{}", FIXTURE_DIR, entry.file), format!("{}\n", candidate.base64))
            .expect("write fixture");
        eprintln!("saved {} sig={} source={} notes={}", entry.file, entry.signature, entry.source, entry.notes);
    }
    let manifest_json = serde_json::to_string_pretty(&manifest).expect("serialize manifest");
    std::fs::write(format!("{FIXTURE_DIR}/manifest.json"), manifest_json).expect("write manifest");
    eprintln!(
        "saved {} attack fixtures ({} mainnet, {} synthetic) to {}",
        selected.len(),
        selected.iter().filter(|c| c.source == "mainnet").count(),
        selected.iter().filter(|c| c.source == "synthetic").count(),
        FIXTURE_DIR
    );
}

#[test]
#[ignore]
fn persist_synthetic_fixtures() {
    std::fs::create_dir_all(FIXTURE_DIR).expect("failed to create attack fixture directory");
    for (idx, candidate) in build_synthetic_fixtures().iter().enumerate() {
        let file = format!("{:02}.b64", idx + 6);
        std::fs::write(format!("{FIXTURE_DIR}/{file}"), format!("{}\n", candidate.base64)).expect("write fixture");
        eprintln!("wrote synthetic {file} sig={}", candidate.signature);
    }
}

fn clean_fixture_dir() {
    if let Ok(entries) = std::fs::read_dir(FIXTURE_DIR) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let is_b64 = path.extension().map(|e| e == "b64").unwrap_or(false);
            let is_manifest = path.file_name().map(|f| f == "manifest.json").unwrap_or(false);
            if is_b64 || is_manifest {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

fn with_retries<T>(label: &str, mut call: impl FnMut() -> Result<T, String>) -> Option<T> {
    for attempt in 0..3 {
        match call() {
            Ok(value) => return Some(value),
            Err(e) => {
                eprintln!("  {} attempt {} failed: {}", label, attempt + 1, e);
                std::thread::sleep(Duration::from_millis(1_000 * (attempt as u64 + 1)));
            }
        }
    }
    None
}

fn scan_block(rpc: &RpcClient, slot: u64, candidates: &mut Vec<Candidate>) {
    let Some(block) = with_retries(&format!("get_block({slot})"), || {
        rpc.get_block_with_config(
            slot,
            RpcBlockConfig {
                encoding: Some(UiTransactionEncoding::Base64),
                transaction_details: Some(TransactionDetails::Full),
                max_supported_transaction_version: Some(0),
                ..Default::default()
            },
        )
        .map_err(|e| e.to_string())
    }) else {
        eprintln!("  get_block({slot}) failed after retries; skipping slot");
        return;
    };

    let token_invoke =
        [format!("Program {TOKEN_PROGRAM_ID} invoke"), format!("Program {TOKEN_2022_PROGRAM_ID} invoke")];
    let mut with_meta = 0usize;
    let mut with_logs = 0usize;
    let mut err_txs = 0usize;
    let mut err_with_logs = 0usize;
    let mut token_logs = 0usize;
    let mut decoded_ok = 0usize;
    let mut flagged = 0usize;
    let mut kept = 0usize;
    let mut kept_failed = 0usize;
    let total_txs = block.transactions.as_ref().map_or(0, Vec::len);

    for tx_with_meta in block.transactions.unwrap_or_default() {
        if candidates.len() >= MAX_FIXTURES {
            return;
        }
        let Some(meta) = tx_with_meta.meta else { continue };
        with_meta += 1;
        let UiTransactionStatusMeta { err, log_messages, inner_instructions, loaded_addresses, .. } = meta;
        let logs: Vec<String> = log_messages.unwrap_or_else(Vec::new);
        if err.is_some() {
            err_txs += 1;
            if !logs.is_empty() {
                err_with_logs += 1;
            }
        }
        if !logs.is_empty() {
            with_logs += 1;
        }
        if !logs.is_empty() && !logs.iter().any(|line| token_invoke.iter().any(|prog| line.contains(prog))) {
            continue;
        }
        token_logs += 1;
        let Some(b64) = encoded_base64(&tx_with_meta.transaction) else { continue };
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&b64) else { continue };
        decoded_ok += 1;
        if token_logs <= 5
            && let Ok((_, report)) = decoder::decode_input(&bytes, None)
        {
            let names: Vec<String> =
                report.instructions.iter().map(|i| i.instruction_name.clone().unwrap_or_default()).collect();
            let pat = patterns::detect_patterns(&report);
            eprintln!("  debug slot {slot} names={names:?} flags={} fee_payer={}", pat.len(), report.fee_payer);
        }
        let inner_groups: Vec<UiInnerInstructions> = Option::from(inner_instructions).unwrap_or_default();
        let loaded: Option<UiLoadedAddresses> = Option::from(loaded_addresses);
        let fetched_meta = build_fetched_meta(&inner_groups, loaded.as_ref());
        let Some(candidate) = classify(&bytes, "mainnet", &fetched_meta) else {
            if let Some(tx_err) = err.as_ref()
                && kept_failed < 2
                && let Some(candidate) = failed_candidate(&bytes, &fetched_meta, tx_err)
            {
                kept_failed += 1;
                kept += 1;
                eprintln!(
                    "  slot {} kept failed tx #{}: {} error={}",
                    slot, kept, candidate.signature, candidate.notes
                );
                candidates.push(candidate);
            }
            continue;
        };
        flagged += 1;
        kept += 1;
        eprintln!("  slot {} kept tx #{}: {} rules={:?}", slot, kept, candidate.signature, candidate.rules);
        candidates.push(candidate);
    }
    eprintln!(
        "  slot {slot}: txs={total_txs} meta={with_meta} logs={with_logs} err={err_txs} err_logs={err_with_logs} token={token_logs} decoded={decoded_ok} flagged={flagged} kept={kept} kept_failed={kept_failed}"
    );
}

fn encoded_base64(enc: &EncodedTransaction) -> Option<String> {
    match enc {
        EncodedTransaction::Binary(blob, TransactionBinaryEncoding::Base64) => Some(blob.clone()),
        EncodedTransaction::Binary(blob, TransactionBinaryEncoding::Base58) => {
            let bytes = bs58::decode(blob).into_vec().ok()?;
            Some(base64::engine::general_purpose::STANDARD.encode(bytes))
        }
        EncodedTransaction::LegacyBinary(blob) => {
            let bytes = bs58::decode(blob).into_vec().ok()?;
            Some(base64::engine::general_purpose::STANDARD.encode(bytes))
        }
        EncodedTransaction::Json(_) | EncodedTransaction::Accounts(_) => None,
    }
}

fn classify(bytes: &[u8], source: &'static str, meta: &FetchedTxMeta) -> Option<Candidate> {
    let (_, mut report) = decoder::decode_input(bytes, None).ok()?;
    inner_instructions::annotate_report(&mut report, meta.clone());
    validator::validate(&mut report, None);
    let flags = patterns::detect_patterns(&report);
    if !flags.iter().any(|f| f.severity == RiskSeverity::Warning) {
        return None;
    }
    let signature = report.signatures.first().cloned()?;
    let mut rules = Vec::new();
    let mut note_parts = Vec::new();
    for flag in &flags {
        let Some(rule) = rule_name(flag) else { continue };
        if !rules.contains(&rule.to_string()) {
            rules.push(rule.to_string());
            note_parts.push(format!("{}({})", rule, severity_str(&flag.severity)));
        }
    }
    if rules.is_empty() {
        return None;
    }
    Some(Candidate {
        base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        signature,
        rules,
        notes: note_parts.join("; "),
        source,
        failed: false,
        error: None,
        meta: meta.clone(),
    })
}

fn empty_meta() -> FetchedTxMeta {
    FetchedTxMeta {
        inner_instructions: Vec::new(),
        loaded_addresses: None,
        error: None,
        units_consumed: None,
        pre_balances: Vec::new(),
        post_balances: Vec::new(),
        pre_token_balances: Vec::new(),
        post_token_balances: Vec::new(),
    }
}

fn build_fetched_meta(inner_groups: &[UiInnerInstructions], loaded: Option<&UiLoadedAddresses>) -> FetchedTxMeta {
    FetchedTxMeta {
        inner_instructions: inner_groups
            .iter()
            .map(|group| TxMetaInnerInstructions {
                index: group.index,
                instructions: group
                    .instructions
                    .iter()
                    .filter_map(|instruction| match instruction {
                        UiInstruction::Compiled(compiled) => Some(TxMetaRawInnerInstruction {
                            program_id_index: compiled.program_id_index,
                            accounts: compiled.accounts.clone(),
                            data: compiled.data.clone(),
                        }),
                        UiInstruction::Parsed(_) => None,
                    })
                    .collect(),
            })
            .collect(),
        loaded_addresses: loaded.map(|addresses| FetchedTxLoadedAddresses {
            writable: addresses.writable.clone(),
            readonly: addresses.readonly.clone(),
        }),
        error: None,
        units_consumed: None,
        pre_balances: Vec::new(),
        post_balances: Vec::new(),
        pre_token_balances: Vec::new(),
        post_token_balances: Vec::new(),
    }
}

fn failed_candidate(bytes: &[u8], meta: &FetchedTxMeta, err: &UiTransactionError) -> Option<Candidate> {
    let (_, mut report) = decoder::decode_input(bytes, None).ok()?;
    inner_instructions::annotate_report(&mut report, meta.clone());
    validator::validate(&mut report, None);
    patterns::detect_patterns(&report);
    let signature = report.signatures.first().cloned()?;
    let error = compact_error(err);
    Some(Candidate {
        base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        signature,
        rules: vec!["failed".to_string()],
        notes: error.clone(),
        source: "mainnet",
        failed: true,
        error: Some(error),
        meta: meta.clone(),
    })
}

fn compact_error(err: &UiTransactionError) -> String {
    let value = serde_json::to_value(err).unwrap_or(serde_json::Value::Null);
    let rendered = match value.as_object().and_then(|obj| obj.get("InstructionError")).and_then(|v| v.as_array()) {
        Some(pair) if pair.len() >= 2 => format!("InstructionError({},{})", pair[0], pair[1]),
        _ => value.to_string(),
    };
    if rendered.len() <= 80 {
        rendered
    } else {
        let mut truncated: String = rendered.chars().take(77).collect();
        truncated.push_str("...");
        truncated
    }
}

fn rule_name(flag: &RiskFlag) -> Option<&'static str> {
    if flag.message.contains("authorizes delegate") {
        Some("approve_then_transfer")
    } else if flag.message.contains("does not sign") {
        Some("nonsigner_transfer_authority")
    } else if flag.message.contains("recipient of instruction") {
        Some("fee_payer_recipient")
    } else if flag.message.contains("receives funds in multiple") {
        Some("repeated_destination")
    } else if flag.message.contains("takeover") {
        Some("mint_authority_takeover")
    } else {
        None
    }
}

fn severity_str(severity: &RiskSeverity) -> &'static str {
    match severity {
        RiskSeverity::Critical => "Critical",
        RiskSeverity::Warning => "Warning",
        RiskSeverity::Info => "Info",
    }
}

fn build_synthetic_fixtures() -> Vec<Candidate> {
    let payer = Keypair::new();
    let delegate = Keypair::new();
    let new_authority = Keypair::new();
    let source = Pubkey::new_unique();
    let recipient = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let nonsigner = Pubkey::new_unique();
    let token = Pubkey::from_str(TOKEN_PROGRAM_ID).expect("token program id");

    let approve = Instruction {
        program_id: token,
        accounts: vec![
            AccountMeta::new(source, false),
            AccountMeta::new(delegate.pubkey(), true),
            AccountMeta::new_readonly(payer.pubkey(), true),
        ],
        data: token_data(4, 1_000),
    };
    let transfer = Instruction {
        program_id: token,
        accounts: vec![
            AccountMeta::new(source, false),
            AccountMeta::new(recipient, false),
            AccountMeta::new_readonly(delegate.pubkey(), true),
        ],
        data: token_data(3, 500),
    };
    let approve_checked = Instruction {
        program_id: token,
        accounts: vec![
            AccountMeta::new(source, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(delegate.pubkey(), true),
            AccountMeta::new_readonly(payer.pubkey(), true),
        ],
        data: checked_data(13, 2_000, 9),
    };
    let transfer_checked = Instruction {
        program_id: token,
        accounts: vec![
            AccountMeta::new(source, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(recipient, false),
            AccountMeta::new_readonly(delegate.pubkey(), true),
        ],
        data: checked_data(12, 800, 9),
    };
    let set_authority = Instruction {
        program_id: token,
        accounts: vec![AccountMeta::new(mint, false), AccountMeta::new_readonly(payer.pubkey(), true)],
        data: set_authority_data(&new_authority.pubkey()),
    };
    let mint_to_checked = Instruction {
        program_id: token,
        accounts: vec![
            AccountMeta::new(mint, false),
            AccountMeta::new(recipient, false),
            AccountMeta::new_readonly(new_authority.pubkey(), true),
        ],
        data: checked_data(14, 10_000, 9),
    };
    let nonsigner_transfer = Instruction {
        program_id: token,
        accounts: vec![
            AccountMeta::new(source, false),
            AccountMeta::new(recipient, false),
            AccountMeta::new_readonly(nonsigner, false),
        ],
        data: token_data(3, 500),
    };
    let nonsigner_transfer_to_payer = Instruction {
        program_id: token,
        accounts: vec![
            AccountMeta::new(source, false),
            AccountMeta::new(payer.pubkey(), false),
            AccountMeta::new_readonly(nonsigner, false),
        ],
        data: token_data(3, 500),
    };
    let sweep_a = Instruction {
        program_id: token,
        accounts: vec![
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new(recipient, false),
            AccountMeta::new_readonly(nonsigner, false),
        ],
        data: token_data(3, 500),
    };
    let sweep_b = Instruction {
        program_id: token,
        accounts: vec![
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new(recipient, false),
            AccountMeta::new_readonly(nonsigner, false),
        ],
        data: token_data(3, 700),
    };

    let builders: Vec<(&str, Vec<Instruction>, &Keypair, Vec<&Keypair>)> = vec![
        ("approve_then_transfer", vec![approve, transfer], &payer, vec![&delegate]),
        ("approve_then_transfer_checked", vec![approve_checked, transfer_checked], &payer, vec![&delegate]),
        ("mint_authority_takeover", vec![set_authority, mint_to_checked], &payer, vec![&new_authority]),
        ("nonsigner_transfer_authority", vec![nonsigner_transfer], &payer, vec![]),
        ("fee_payer_recipient", vec![nonsigner_transfer_to_payer], &payer, vec![]),
        ("repeated_destination", vec![sweep_a, sweep_b], &payer, vec![]),
    ];

    builders
        .into_iter()
        .map(|(_, instructions, payer, extra)| {
            let bytes = build_legacy(&instructions, payer, &extra);
            classify(&bytes, "synthetic", &empty_meta()).expect("synthetic fixture must classify as attack-shaped")
        })
        .collect()
}

fn token_data(tag: u8, amount: u64) -> Vec<u8> {
    let mut data = vec![tag];
    data.extend_from_slice(&amount.to_le_bytes());
    data
}

fn checked_data(tag: u8, amount: u64, decimals: u8) -> Vec<u8> {
    let mut data = token_data(tag, amount);
    data.push(decimals);
    data
}

fn set_authority_data(new_authority: &Pubkey) -> Vec<u8> {
    let mut data = vec![6u8, 0, 1];
    data.extend_from_slice(&new_authority.to_bytes());
    data
}

fn build_legacy(instructions: &[Instruction], payer: &Keypair, extra_signers: &[&Keypair]) -> Vec<u8> {
    let message = VersionedMessage::Legacy(legacy::Message::new_with_blockhash(
        instructions,
        Some(&payer.pubkey()),
        &Hash::new_from_array([7u8; 32]),
    ));
    let message_bytes = message.serialize();
    let required = message.header().num_required_signatures as usize;
    let keys = message.static_account_keys();
    let mut signatures: Vec<Signature> = Vec::with_capacity(required);
    for key in keys.iter().take(required) {
        if key == &payer.pubkey() {
            signatures.push(payer.sign_message(&message_bytes));
        } else if let Some(kp) = extra_signers.iter().find(|kp| kp.pubkey() == *key) {
            signatures.push(kp.sign_message(&message_bytes));
        } else {
            panic!("no signer supplied for required signer {key}");
        }
    }
    bincode::serialize(&VersionedTransaction { signatures, message }).expect("serialize transaction")
}

fn load_manifest() -> Option<Vec<ManifestEntry>> {
    let path = format!("{FIXTURE_DIR}/manifest.json");
    match std::fs::read_to_string(&path) {
        Ok(json) => Some(serde_json::from_str(&json).unwrap_or_else(|e| panic!("{}: invalid manifest: {}", path, e))),
        Err(_) => {
            eprintln!(
                "no manifest at {path}; run `cargo test --test attack_corpus fetch_attack_corpus -- --ignored` first"
            );
            None
        }
    }
}

fn read_fixture(file: &str) -> String {
    let path = format!("{}/{}", FIXTURE_DIR, file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: unreadable: {}", path, e))
}

fn parse_category(s: &str) -> RiskCategory {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .unwrap_or_else(|e| panic!("invalid category string '{}': {}", s, e))
}

fn severity_rank(severity: &RiskSeverity) -> u8 {
    match severity {
        RiskSeverity::Critical => 2,
        RiskSeverity::Warning => 1,
        RiskSeverity::Info => 0,
    }
}

#[test]
fn manifest_is_valid_json() {
    let Some(manifest) = load_manifest() else {
        return;
    };
    assert!(!manifest.is_empty(), "manifest must contain at least one entry");
    for entry in &manifest {
        let path = format!("{}/{}", FIXTURE_DIR, entry.file);
        assert!(std::path::Path::new(&path).exists(), "{}: fixture file missing", path);
        let content = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: unreadable: {}", path, e));
        assert!(!content.trim().is_empty(), "{}: fixture file is empty", path);
        assert!(!entry.signature.is_empty(), "{}: empty signature", entry.file);
        assert!(
            entry.source == "mainnet" || entry.source == "synthetic",
            "{}: invalid source '{}'",
            entry.file,
            entry.source
        );
        if entry.failed {
            assert!(entry.error.is_some(), "{}: failed entry missing error", entry.file);
        }
        if entry.expected_min_flags == 0 {
            assert!(
                entry.expected_categories.is_empty(),
                "{}: zero expected flags but categories declared",
                entry.file
            );
        } else {
            assert!(!entry.expected_categories.is_empty(), "{}: expected_categories empty", entry.file);
        }
        for category in &entry.expected_categories {
            parse_category(category);
        }
    }
}

#[test]
fn fixtures_are_real_mainnet_txs() {
    let Some(manifest) = load_manifest() else {
        return;
    };
    for entry in &manifest {
        if entry.source != "mainnet" {
            continue;
        }
        let b64 = read_fixture(&entry.file);
        let (_, report) = decoder::decode_input(b64.trim().as_bytes(), None)
            .unwrap_or_else(|e| panic!("{}: decode failed: {}", entry.file, e));
        assert_eq!(report.status, "DECODED SUCCESSFULLY", "{}", entry.file);
        assert_eq!(
            report.signatures.first(),
            Some(&entry.signature),
            "{}: manifest signature does not match fixture",
            entry.file
        );
        assert!(!report.accounts.is_empty(), "{}: no accounts", entry.file);
        assert!(!report.instructions.is_empty(), "{}: no instructions", entry.file);
    }
}

#[test]
fn corpus_triggers_expected_flags() {
    let Some(manifest) = load_manifest() else {
        return;
    };
    for entry in &manifest {
        let b64 = read_fixture(&entry.file);
        let (_, mut report) = decoder::decode_input(b64.trim().as_bytes(), None)
            .unwrap_or_else(|e| panic!("{}: decode failed: {}", entry.file, e));
        inner_instructions::annotate_report(&mut report, empty_meta());
        validator::validate(&mut report, None);
        let flags = patterns::detect_patterns(&report);
        report.risk_flags.extend(flags);
        assert!(
            report.risk_flags.len() >= entry.expected_min_flags,
            "{}: expected at least {} flags, got {}",
            entry.file,
            entry.expected_min_flags,
            report.risk_flags.len()
        );
        for category in &entry.expected_categories {
            let expected = parse_category(category);
            assert!(
                report.risk_flags.iter().any(|f| f.category == expected),
                "{}: missing category {} in {:?}",
                entry.file,
                category,
                report.risk_flags
            );
        }
        for flag in &report.risk_flags {
            assert!(
                severity_rank(&flag.severity) >= severity_rank(&RiskSeverity::Info),
                "{}: flag below Info severity: {}",
                entry.file,
                flag.message
            );
        }
    }
}

#[test]
fn real_fixtures_exercise_full_pipeline() {
    let Some(manifest) = load_manifest() else {
        return;
    };
    for entry in &manifest {
        if entry.source != "mainnet" {
            continue;
        }
        let b64 = read_fixture(&entry.file);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .unwrap_or_else(|e| panic!("{}: invalid base64: {}", entry.file, e));
        let (_, mut report) =
            decoder::decode_input(&bytes, None).unwrap_or_else(|e| panic!("{}: decode failed: {}", entry.file, e));
        inner_instructions::annotate_report(&mut report, empty_meta());
        validator::validate(&mut report, None);
        patterns::detect_patterns(&report);
        let tx: VersionedTransaction = bincode::deserialize(&bytes)
            .unwrap_or_else(|e| panic!("{}: not a versioned transaction: {}", entry.file, e));
        let checks = signature_verify::verify_transaction(&tx);
        report.signature_verification = checks;
        let sig_flags = signature_verify::verify_report(&mut report);
        let mismatches = sig_flags.iter().filter(|f| f.category == RiskCategory::SignatureMismatch).count();
        assert_eq!(mismatches, 0, "{}: real mainnet signatures must verify", entry.file);
        assert!(!report.fee_payer.is_empty(), "{}: missing fee payer", entry.file);
        assert!(!report.instructions.is_empty(), "{}: no instructions", entry.file);
        assert_eq!(report.status, "DECODED SUCCESSFULLY", "{}", entry.file);
    }
}

#[test]
fn corpus_signatures_verify_or_tamper_flagged() {
    let Some(manifest) = load_manifest() else {
        return;
    };
    for entry in &manifest {
        let b64 = read_fixture(&entry.file);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .unwrap_or_else(|e| panic!("{}: invalid base64: {}", entry.file, e));
        let tx: VersionedTransaction = bincode::deserialize(&bytes)
            .unwrap_or_else(|e| panic!("{}: not a versioned transaction: {}", entry.file, e));
        let required = tx.message.header().num_required_signatures as usize;
        let checks = signature_verify::verify_transaction(&tx);
        assert_eq!(checks.len(), required, "{}: signature check count mismatch", entry.file);
        let all_verified = checks.iter().all(|c| c.verified);
        let mut report = decoder::decode_input(&bytes, None).expect("fixture decode").1;
        report.signature_verification = checks;
        let sig_flags = signature_verify::verify_report(&mut report);
        let has_mismatch = sig_flags.iter().any(|f| f.category == RiskCategory::SignatureMismatch);
        assert!(all_verified || has_mismatch, "{}: signatures neither all verified nor mismatch-flagged", entry.file);
    }
}

#[test]
fn failed_fixtures_decode_and_verify() {
    let Some(manifest) = load_manifest() else {
        return;
    };
    for entry in &manifest {
        if !entry.failed {
            continue;
        }
        let b64 = read_fixture(&entry.file);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .unwrap_or_else(|e| panic!("{}: invalid base64: {}", entry.file, e));
        let (_, mut report) =
            decoder::decode_input(&bytes, None).unwrap_or_else(|e| panic!("{}: decode failed: {}", entry.file, e));
        assert_eq!(report.status, "DECODED SUCCESSFULLY", "{}", entry.file);
        assert_eq!(
            report.signatures.first(),
            Some(&entry.signature),
            "{}: manifest signature does not match fixture",
            entry.file
        );
        inner_instructions::annotate_report(&mut report, empty_meta());
        validator::validate(&mut report, None);
        patterns::detect_patterns(&report);
        let tx: VersionedTransaction = bincode::deserialize(&bytes)
            .unwrap_or_else(|e| panic!("{}: not a versioned transaction: {}", entry.file, e));
        let checks = signature_verify::verify_transaction(&tx);
        assert_eq!(
            checks.len(),
            tx.message.header().num_required_signatures as usize,
            "{}: signature check count mismatch",
            entry.file
        );
        assert!(checks.iter().all(|c| c.verified), "{}: failed fixture signatures must verify", entry.file);
    }
}
