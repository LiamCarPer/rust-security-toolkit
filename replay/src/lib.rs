//! Replay-based validation service for `rts`.
//!
//! Executes a decoded transaction (and caller-supplied mutations of it) in a
//! local LiteSVM with signature verification disabled, so transactions whose
//! signers' keys are unknown can still be reproduced and generalized against
//! current chain state. The service is a standalone process: the JSON protocol
//! below is the only interface, which keeps LiteSVM's dependency tree entirely
//! out of the pinned `rts` crate graph.
use std::collections::HashMap;
use std::str::FromStr;

use base64::Engine;
use serde::{Deserialize, Serialize};
use solana_account::Account;
use solana_address::Address;
use solana_transaction::versioned::VersionedTransaction;

pub const PROTOCOL_VERSION: &str = "1.0";

pub const BPF_LOADER_UPGRADEABLE: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
pub const BPF_LOADER: &str = "BPFLoader2111111111111111111111111111111111";
pub const BPF_LOADER_DEPRECATED: &str = "BPFLoader1111111111111111111111111111111111";

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

pub fn run_request(request: &ReplayRequest) -> anyhow::Result<ReplayReport> {
    let mut warnings = Vec::new();
    let mut svm = litesvm::LiteSVM::new().with_sigverify(false);
    let _ = svm;

    for program in &request.programs {
        let program_id = parse_address(&program.program_id)?;
        let elf = hex::decode(&program.elf_hex).map_err(|e| anyhow::anyhow!("bad program elf hex: {}", e))?;
        let loader = match program.loader.as_str() {
            "deprecated" => Address::from_str(BPF_LOADER_DEPRECATED).unwrap(),
            "bpf-loader-2" => Address::from_str(BPF_LOADER).unwrap(),
            _ => Address::from_str(BPF_LOADER_UPGRADEABLE).unwrap(),
        };
        if let Err(e) = svm.add_program_with_loader(program_id, &elf, loader) {
            warnings.push(format!("could not load program {}: {:?} (native program?)", program.program_id, e));
        }
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let mut pre_lamports: HashMap<Address, u64> = HashMap::new();
    let mut pre_data: HashMap<Address, Vec<u8>> = HashMap::new();
    for account_key in &request.accounts {
        let address = parse_address(account_key)?;
        match fetch_account(&client, &request.rpc_url, account_key)? {
            Some(account) => {
                pre_lamports.insert(address, account.lamports);
                pre_data.insert(address, account.data.clone());
                svm.set_account(address, account)
                    .map_err(|e| anyhow::anyhow!("failed to set account {}: {:?}", account_key, e))?;
            }
            None => warnings.push(format!("account {} not found on chain; left unset", account_key)),
        }
    }

    let original_tx = deserialize_tx(&request.tx_hex)?;
    let original = execute(&svm, &original_tx, &pre_lamports, &pre_data);

    let mut mutations = Vec::new();
    for mutation in &request.mutations {
        let mutated_tx = match deserialize_tx(&mutation.tx_hex) {
            Ok(tx) => tx,
            Err(e) => {
                warnings.push(format!("mutation '{}' undecodable: {}", mutation.label, e));
                continue;
            }
        };
        let outcome = execute(&svm, &mutated_tx, &pre_lamports, &pre_data);
        let delta = diff_outcomes(&original, &outcome);
        mutations.push(MutationOutcome { label: mutation.label.clone(), outcome, delta });
    }

    Ok(ReplayReport {
        protocol_version: PROTOCOL_VERSION.to_string(),
        original,
        mutations,
        warnings,
    })
}

pub fn execute(
    svm: &litesvm::LiteSVM,
    tx: &VersionedTransaction,
    pre_lamports: &HashMap<Address, u64>,
    pre_data: &HashMap<Address, Vec<u8>>,
) -> Outcome {
    match svm.simulate_transaction(tx.clone()) {
        Ok(info) => {
            let mut sol_deltas = Vec::new();
            let mut data_changed = Vec::new();
            for (address, account) in &info.post_accounts {
                let account: Account = account.clone().into();
                let post = account.lamports;
                if let Some(pre) = pre_lamports.get(address) {
                    if *pre != post {
                        sol_deltas.push(SolDelta {
                            pubkey: address.to_string(),
                            pre: *pre,
                            post,
                            delta: post as i64 - *pre as i64,
                        });
                    }
                }
                if let Some(pre) = pre_data.get(address)
                    && *pre != account.data
                {
                    data_changed.push(address.to_string());
                }
            }
            Outcome {
                success: true,
                error: None,
                logs: info.meta.logs.clone(),
                compute_units: info.meta.compute_units_consumed,
                fee: info.meta.fee,
                sol_deltas,
                data_changed,
                return_data: Some(base64::engine::general_purpose::STANDARD.encode(info.meta.return_data.data.clone())),
            }
        }
        Err(failed) => Outcome {
            success: false,
            error: Some(failed.err.to_string()),
            logs: failed.meta.logs.clone(),
            compute_units: failed.meta.compute_units_consumed,
            fee: failed.meta.fee,
            sol_deltas: Vec::new(),
            data_changed: Vec::new(),
            return_data: None,
        },
    }
}

pub fn diff_outcomes(original: &Outcome, mutated: &Outcome) -> Vec<String> {
    let mut deltas = Vec::new();
    if original.success != mutated.success {
        deltas.push(format!("success changed {} -> {}", original.success, mutated.success));
    }
    if original.error != mutated.error {
        deltas.push(format!(
            "error changed {:?} -> {:?}",
            original.error, mutated.error
        ));
    }
    if original.compute_units != mutated.compute_units {
        deltas.push(format!(
            "compute units changed {} -> {}",
            original.compute_units, mutated.compute_units
        ));
    }
    let mut by_key: HashMap<&str, i64> = HashMap::new();
    for entry in &original.sol_deltas {
        by_key.insert(entry.pubkey.as_str(), entry.delta);
    }
    for entry in &mutated.sol_deltas {
        let before = by_key.remove(entry.pubkey.as_str()).unwrap_or(0);
        if before != entry.delta {
            deltas.push(format!("SOL delta for {} changed {} -> {}", entry.pubkey, before, entry.delta));
        }
    }
    for (pubkey, before) in by_key {
        deltas.push(format!("SOL delta for {} changed {} -> 0", pubkey, before));
    }
    let mut original_changed: Vec<&str> = original.data_changed.iter().map(String::as_str).collect();
    original_changed.sort_unstable();
    let mut mutated_changed: Vec<&str> = mutated.data_changed.iter().map(String::as_str).collect();
    mutated_changed.sort_unstable();
    if original_changed != mutated_changed {
        deltas.push("account data changes differ".to_string());
    }
    deltas
}

fn deserialize_tx(tx_hex: &str) -> anyhow::Result<VersionedTransaction> {
    let bytes = hex::decode(tx_hex).map_err(|e| anyhow::anyhow!("bad tx hex: {}", e))?;
    bincode::deserialize::<VersionedTransaction>(&bytes).map_err(|e| anyhow::anyhow!("bad tx bytes: {}", e))
}

pub fn parse_address(value: &str) -> anyhow::Result<Address> {
    Address::from_str(value).map_err(|e| anyhow::anyhow!("bad address '{}': {}", value, e))
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    result: Option<RpcResult>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    message: String,
}

#[derive(Debug, Deserialize)]
struct RpcResult {
    value: Option<RpcAccount>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RpcAccount {
    lamports: u64,
    owner: String,
    executable: bool,
    #[serde(default)]
    rent_epoch: u64,
    data: serde_json::Value,
}

fn fetch_account(
    client: &reqwest::blocking::Client,
    rpc_url: &str,
    pubkey: &str,
) -> anyhow::Result<Option<Account>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [pubkey, {"encoding": "base64", "commitment": "confirmed"}]
    });
    let response: RpcResponse = client
        .post(rpc_url)
        .json(&body)
        .send()
        .map_err(|e| anyhow::anyhow!("getAccountInfo failed: {}", e))?
        .json()
        .map_err(|e| anyhow::anyhow!("getAccountInfo response parse failed: {}", e))?;
    if let Some(error) = response.error {
        anyhow::bail!("RPC error: {}", error.message);
    }
    let Some(account) = response.result.and_then(|r| r.value) else {
        return Ok(None);
    };
    let encoded = account
        .data
        .as_array()
        .and_then(|parts| parts.first())
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow::anyhow!("unexpected account data shape for {}", pubkey))?;
    let data = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| anyhow::anyhow!("account data base64 decode failed: {}", e))?;
    Ok(Some(Account {
        lamports: account.lamports,
        data,
        owner: parse_address(&account.owner)?,
        executable: account.executable,
        rent_epoch: account.rent_epoch,
    }))
}
