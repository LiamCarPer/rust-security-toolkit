//! Local replay + mutation validation via the `rts-replay` companion binary.
//!
//! `rts-replay` is a standalone crate (see `replay/`) built on LiteSVM. It is
//! deliberately *not* a dependency of this crate: litesvm requires newer
//! solana-* versions than the versions this crate is exact-pinned to, so the
//! two cannot coexist in one dependency graph. The JSON protocol below is the
//! entire interface; `PROTOCOL_VERSION` guards compatibility.
use std::collections::BTreeSet;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use crate::poc;
use crate::types::TransactionReport;

pub const PROTOCOL_VERSION: &str = "1.0";
const REPLAY_TIMEOUT: Duration = Duration::from_secs(120);

const NATIVE_PROGRAMS: &[&str] = &[
    crate::types::SYSTEM_PROGRAM_ID,
    crate::types::COMPUTE_BUDGET_PROGRAM_ID,
    crate::types::ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
    crate::types::STAKE_PROGRAM_ID,
    crate::types::VOTE_PROGRAM_ID,
    "Config1111111111111111111111111111111111111",
    "BPFLoader1111111111111111111111111111111111",
    "BPFLoader2111111111111111111111111111111111",
    "BPFLoaderUpgradeab1e11111111111111111111111",
    "LoaderV411111111111111111111111111111111111",
    "Ed25519SigVerify111111111111111111111111111",
    "KeccakSecp256k11111111111111111111111111111",
    "Secp256r1SigVerify1111111111111111111111111",
    "ZkE1Gama1Proof11111111111111111111111111111",
    "Feature111111111111111111111111111111111111",
    "NativeLoader1111111111111111111111111111111",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayRequest {
    pub protocol_version: String,
    pub rpc_url: String,
    pub tx_hex: String,
    #[serde(default)]
    pub accounts: Vec<String>,
    #[serde(default)]
    pub programs: Vec<ProgramInput>,
    #[serde(default)]
    pub mutations: Vec<MutationInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramInput {
    pub program_id: String,
    pub elf_hex: String,
    #[serde(default)]
    pub loader: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationInput {
    pub label: String,
    pub tx_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolDelta {
    pub pubkey: String,
    pub pre: u64,
    pub post: u64,
    pub delta: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outcome {
    pub success: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub logs: Vec<String>,
    #[serde(default)]
    pub compute_units: u64,
    #[serde(default)]
    pub fee: u64,
    #[serde(default)]
    pub sol_deltas: Vec<SolDelta>,
    #[serde(default)]
    pub data_changed: Vec<String>,
    #[serde(default)]
    pub return_data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationOutcome {
    pub label: String,
    pub outcome: Outcome,
    #[serde(default)]
    pub delta: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayReport {
    pub protocol_version: String,
    pub original: Outcome,
    #[serde(default)]
    pub mutations: Vec<MutationOutcome>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

pub fn binary() -> String {
    std::env::var("RTS_REPLAY").unwrap_or_else(|_| "rts-replay".to_string())
}

pub fn is_available(binary: &str) -> bool {
    std::process::Command::new(binary).arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok()
}

pub fn collect_accounts(report: &TransactionReport) -> Vec<String> {
    let program_ids: BTreeSet<&str> = report.instructions.iter().map(|ix| ix.program_id.as_str()).collect();
    let mut accounts: BTreeSet<String> = BTreeSet::new();
    for account in &report.accounts {
        if !program_ids.contains(account.pubkey.as_str()) {
            accounts.insert(account.pubkey.clone());
        }
    }
    for alt in &report.address_lookup_tables {
        for resolved in &alt.resolved_accounts {
            if !resolved.pubkey.contains('<') {
                accounts.insert(resolved.pubkey.clone());
            }
        }
    }
    accounts.into_iter().collect()
}

pub async fn collect_programs(report: &TransactionReport, rpc_url: &str) -> (Vec<ProgramInput>, Vec<String>) {
    let mut warnings = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut programs = Vec::new();
    for program_id in report.instructions.iter().map(|ix| ix.program_id.clone()) {
        if NATIVE_PROGRAMS.contains(&program_id.as_str()) || !seen.insert(program_id.clone()) {
            continue;
        }
        match crate::bytecode::fetch_program_elf(rpc_url, &program_id).await {
            Ok(Some((elf, loader, _authority))) => {
                programs.push(ProgramInput { program_id, elf_hex: hex::encode(elf), loader })
            }
            Ok(None) => warnings.push(format!("replay: no ELF found for program {}", program_id)),
            Err(e) => warnings.push(format!("replay: failed to fetch program {}: {}", program_id, e)),
        }
    }
    (programs, warnings)
}

fn read_amount(data: &[u8]) -> Option<u64> {
    if data.len() >= 12 && u32::from_le_bytes(data[0..4].try_into().ok()?) == 2 {
        return Some(u64::from_le_bytes(data[4..12].try_into().ok()?));
    }
    if data.len() >= 9 && matches!(data[0], 3 | 12) {
        return Some(u64::from_le_bytes(data[1..9].try_into().ok()?));
    }
    None
}

pub fn build_mutations(tx: &solana_sdk::transaction::VersionedTransaction) -> Vec<MutationInput> {
    let template = poc::from_transaction(tx);
    let mut mutations = Vec::new();
    for (index, instruction) in template.instructions.iter().enumerate() {
        let Ok(data) = hex::decode(&instruction.data_hex) else { continue };
        let Some(amount) = read_amount(&data) else { continue };
        let candidates: [(u64, &str); 2] = [(amount.saturating_mul(2), "2x"), (amount / 2, "half")];
        for (value, label) in candidates {
            if value == amount {
                continue;
            }
            let mut mutated = template.clone();
            if mutated.set_instruction_amount(index, value).is_err() {
                continue;
            }
            let Ok(tx) = poc::to_transaction(&mutated) else { continue };
            let Ok(bytes) = bincode::serialize(&tx) else { continue };
            mutations.push(MutationInput {
                label: format!("ix{index} amount {label} ({amount} -> {value})"),
                tx_hex: hex::encode(bytes),
            });
        }
        if amount > 0 {
            let mut mutated = template.clone();
            if mutated.set_instruction_amount(index, 0).is_ok()
                && let Ok(tx) = poc::to_transaction(&mutated)
                && let Ok(bytes) = bincode::serialize(&tx)
            {
                mutations.push(MutationInput {
                    label: format!("ix{index} amount zeroed ({amount} -> 0)"),
                    tx_hex: hex::encode(bytes),
                });
            }
        }
    }
    mutations
}

pub async fn run(request: &ReplayRequest) -> Result<ReplayReport> {
    let binary = binary();
    let mut child = tokio::process::Command::new(&binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "failed to run '{}' (build it with: cargo build --release --manifest-path replay/Cargo.toml)",
                binary
            )
        })?;

    let payload = serde_json::to_vec(request).context("failed to serialize replay request")?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&payload).await.context("failed to write replay request")?;
        drop(stdin);
    }

    let output = tokio::time::timeout(REPLAY_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| anyhow::anyhow!("rts-replay timed out after {}s", REPLAY_TIMEOUT.as_secs()))?
        .context("failed to wait for rts-replay")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("rts-replay exited with {}: {}", output.status, stderr.lines().next().unwrap_or(""));
    }
    let report: ReplayReport = serde_json::from_slice(&output.stdout).context("failed to parse replay report")?;
    if report.protocol_version != PROTOCOL_VERSION {
        anyhow::bail!("rts-replay protocol mismatch: {} vs {}", report.protocol_version, PROTOCOL_VERSION);
    }
    Ok(report)
}

pub fn render_terminal(report: &ReplayReport, known: Option<&crate::known_addresses::KnownAddresses>) {
    use colored::*;
    let status = if report.original.success {
        "SUCCEEDED".green()
    } else {
        format!("FAILED: {}", report.original.error.as_deref().unwrap_or("unknown")).red()
    };
    println!("[+] Replay (LiteSVM, sigVerify off): {}", status);
    println!("    CU consumed: {} — fee: {} lamports", report.original.compute_units, report.original.fee);
    for delta in &report.original.sol_deltas {
        println!("    SOL {}: {:+} lamports", display_key(&delta.pubkey, known), delta.delta);
    }
    if !report.mutations.is_empty() {
        println!("[+] Mutation generalization ({} tested):", report.mutations.len());
        for mutation in &report.mutations {
            let outcome = if mutation.outcome.success { "ok".green() } else { "fail".red() };
            let changed =
                if mutation.delta.is_empty() { "no effect change".dimmed() } else { "EFFECT CHANGED".yellow().bold() };
            println!("    {} — {} ({})", mutation.label, outcome, changed);
            for delta in &mutation.delta {
                println!("      • {}", delta);
            }
        }
    }
    for warning in &report.warnings {
        println!("    warning: {}", warning.yellow());
    }
}

pub fn render_markdown(report: &ReplayReport) -> String {
    let mut out = String::new();
    out.push_str("## Local Replay (LiteSVM, signature verification disabled)\n\n");
    out.push_str(&format!(
        "- original: {} (CU {}, fee {})\n",
        if report.original.success { "succeeded" } else { "failed" },
        report.original.compute_units,
        report.original.fee
    ));
    if let Some(ref error) = report.original.error {
        out.push_str(&format!("- error: {}\n", error.replace('|', "\\|")));
    }
    for delta in &report.original.sol_deltas {
        out.push_str(&format!("- SOL `{}`: {:+}\n", delta.pubkey, delta.delta));
    }
    if !report.mutations.is_empty() {
        out.push_str("\n### Mutation generalization\n\n");
        out.push_str("| Mutation | Executes | Effect changed |\n|---|---|---|\n");
        for mutation in &report.mutations {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                mutation.label.replace('|', "\\|"),
                if mutation.outcome.success { "yes" } else { "no" },
                if mutation.delta.is_empty() { "no" } else { "yes" }
            ));
        }
        out.push('\n');
    }
    out
}

fn display_key(key: &str, known: Option<&crate::known_addresses::KnownAddresses>) -> String {
    match known.and_then(|k| k.name(key)).or_else(|| crate::labels::label(key)) {
        Some(name) => name.to_string(),
        None => {
            if key.len() > 12 {
                format!("{}…{}", &key[..6], &key[key.len() - 4..])
            } else {
                key.to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::hash::Hash;
    use solana_sdk::instruction::{AccountMeta, Instruction};
    use solana_sdk::message::{VersionedMessage, legacy};
    use solana_sdk::pubkey::Pubkey;
    use solana_sdk::signature::{Keypair, Signature};
    use solana_sdk::signer::Signer;

    fn transfer_tx(lamports: u64) -> solana_sdk::transaction::VersionedTransaction {
        let payer = Keypair::new();
        let recipient = Pubkey::new_unique();
        let instruction = Instruction {
            program_id: Pubkey::from_str_const(crate::types::SYSTEM_PROGRAM_ID),
            accounts: vec![AccountMeta::new(payer.pubkey(), true), AccountMeta::new(recipient, false)],
            data: {
                let mut data = 2u32.to_le_bytes().to_vec();
                data.extend_from_slice(&lamports.to_le_bytes());
                data
            },
        };
        let message = VersionedMessage::Legacy(legacy::Message::new_with_blockhash(
            &[instruction],
            Some(&payer.pubkey()),
            &Hash::new_from_array([7u8; 32]),
        ));
        solana_sdk::transaction::VersionedTransaction { signatures: vec![Signature::default()], message }
    }

    #[test]
    fn read_amount_parses_system_and_token_transfers() {
        let mut system = 2u32.to_le_bytes().to_vec();
        system.extend_from_slice(&1_000u64.to_le_bytes());
        assert_eq!(read_amount(&system), Some(1_000));

        let mut token = vec![3u8];
        token.extend_from_slice(&500u64.to_le_bytes());
        assert_eq!(read_amount(&token), Some(500));
        assert_eq!(read_amount(&[9u8, 1, 2, 3]), None);
    }

    #[test]
    fn build_mutations_produces_amount_variants() {
        let tx = transfer_tx(1_000_000);
        let mutations = build_mutations(&tx);
        assert!(mutations.len() >= 2, "mutations: {:?}", mutations);
        let labels: Vec<&str> = mutations.iter().map(|m| m.label.as_str()).collect();
        assert!(labels.iter().any(|l| l.contains("2x")));
        assert!(labels.iter().any(|l| l.contains("half")));
        assert!(labels.iter().any(|l| l.contains("zeroed")));
        for mutation in &mutations {
            let bytes = hex::decode(&mutation.tx_hex).expect("hex");
            assert!(bincode::deserialize::<solana_sdk::transaction::VersionedTransaction>(&bytes).is_ok());
        }
    }

    #[test]
    fn mutated_amount_round_trips_in_transaction_bytes() {
        let tx = transfer_tx(1_000_000);
        let mutations = build_mutations(&tx);
        let doubled = mutations.iter().find(|m| m.label.contains("2x")).expect("2x mutation");
        let bytes = hex::decode(&doubled.tx_hex).expect("hex");
        let rebuilt: solana_sdk::transaction::VersionedTransaction = bincode::deserialize(&bytes).expect("tx");
        let data = rebuilt.message.instructions().first().expect("instruction").data.clone();
        assert_eq!(read_amount(&data), Some(2_000_000));
    }

    #[test]
    fn collect_accounts_excludes_program_ids_and_alt_placeholders() {
        let report = TransactionReport {
            status: "S".into(),
            fee_payer: "Payer".into(),
            signatures: Vec::new(),
            recent_blockhash: String::new(),
            message_version: None,
            accounts: vec![
                crate::types::AccountInfo {
                    index: 0,
                    pubkey: crate::types::SYSTEM_PROGRAM_ID.to_string(),
                    is_signer: false,
                    is_writable: false,
                    role: None,
                    pda_info: None,
                },
                crate::types::AccountInfo {
                    index: 1,
                    pubkey: "UserAccount111111111111111111111111111111111".to_string(),
                    is_signer: false,
                    is_writable: true,
                    role: None,
                    pda_info: None,
                },
            ],
            instructions: vec![crate::types::DecodedInstruction {
                index: 0,
                program_id: crate::types::SYSTEM_PROGRAM_ID.to_string(),
                program_name: "System".into(),
                instruction_name: None,
                accounts: Vec::new(),
                data: serde_json::Value::Null,
                raw_data_hex: String::new(),
                token_amount: None,
            }],
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
            logs: Vec::new(),
            events: Vec::new(),
            program_analyses: Vec::new(),
        };
        let accounts = collect_accounts(&report);
        assert_eq!(accounts, vec!["UserAccount111111111111111111111111111111111".to_string()]);
    }
}
