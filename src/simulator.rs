use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::types::{
    ADDRESS_LOOKUP_TABLE_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, COMPUTE_BUDGET_PROGRAM_ID, RiskCategory, RiskFlag,
    RiskSeverity, SYSTEM_PROGRAM_ID, SimulationResult, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, TransactionReport,
};

const BPF_LOADER_UPGRADEABLE: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
const BPF_LOADER: &str = "BPFLoader2111111111111111111111111111111111";
const VERIFIED_BUILD_REGISTRY: &str = "https://verify.osec.io";

#[derive(Debug, Deserialize)]
struct RpcSimulateResponse {
    result: Option<RpcSimulateValue>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcSimulateValue {
    value: RpcSimulateInner,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RpcSimulateInner {
    err: Option<serde_json::Value>,
    logs: Option<Vec<String>>,
    units_consumed: Option<u64>,
    return_data: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    message: String,
}

#[derive(Serialize)]
struct RpcRequest {
    jsonrpc: String,
    id: u32,
    method: String,
    params: (String, RpcSimulateConfig),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RpcSimulateConfig {
    encoding: String,
    sig_verify: bool,
    replace_recent_blockhash: bool,
    commitment: String,
}

/// Extract a structured error code and failing instruction index from a
/// `simulateTransaction` `err` value. Recognized shapes:
/// - `{"InstructionError": [idx, "Code"]}` → ("Code", idx)
/// - `{"InstructionError": [idx, {"Custom": n}]}` → ("Custom(n)", idx)
/// - `{"InsufficientFundsForFee": {}}` → ("InsufficientFundsForFee", None)
/// - anything else → (None, None)
pub fn parse_simulation_error(err: &serde_json::Value) -> (Option<String>, Option<u8>) {
    let obj = match err.as_object() {
        Some(o) => o,
        None => return (None, None),
    };

    if let Some(ix_err) = obj.get("InstructionError") {
        let arr = match ix_err.as_array() {
            Some(a) => a,
            None => return (Some("InstructionError".to_string()), None),
        };
        let instruction_index = arr.first().and_then(|v| v.as_u64()).map(|i| i as u8);
        let code = match arr.get(1) {
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            Some(serde_json::Value::Object(m)) => {
                if let Some(custom) = m.get("Custom") {
                    Some(custom.as_u64().map(|n| format!("Custom({})", n)).unwrap_or_else(|| "Custom".to_string()))
                } else {
                    m.keys().next().cloned()
                }
            }
            _ => None,
        };
        return (code, instruction_index);
    }

    (obj.keys().next().cloned(), None)
}

/// Simulate a transaction against an RPC endpoint.
pub async fn simulate_transaction(rpc_url: &str, raw_tx_base64: &str) -> Result<SimulationResult> {
    let client = reqwest::Client::new();

    let request = RpcRequest {
        jsonrpc: "2.0".to_string(),
        id: 1,
        method: "simulateTransaction".to_string(),
        params: (
            raw_tx_base64.to_string(),
            RpcSimulateConfig {
                encoding: "base64".to_string(),
                sig_verify: false,
                replace_recent_blockhash: true,
                commitment: "confirmed".to_string(),
            },
        ),
    };

    let response = client
        .post(rpc_url)
        .json(&request)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .context("Failed to send simulateTransaction RPC request")?;

    let body: RpcSimulateResponse =
        response.json().await.context("Failed to parse simulateTransaction RPC response")?;

    if let Some(err) = body.error {
        return Ok(SimulationResult {
            success: false,
            error: Some(format!("RPC error: {}", err.message)),
            logs: Vec::new(),
            units_consumed: 0,
            return_data: None,
            error_code: None,
            error_instruction_index: None,
        });
    }

    let value = match body.result {
        Some(v) => v.value,
        None => {
            return Ok(SimulationResult {
                success: false,
                error: Some("No result returned from simulation".to_string()),
                logs: Vec::new(),
                units_consumed: 0,
                return_data: None,
                error_code: None,
                error_instruction_index: None,
            });
        }
    };

    let success = value.err.is_none();
    let (error_code, error_instruction_index) = value.err.as_ref().map(parse_simulation_error).unwrap_or((None, None));
    let error = value.err.map(|e| e.to_string());
    let logs = value.logs.unwrap_or_default();
    let units_consumed = value.units_consumed.unwrap_or(0);

    let return_data = value
        .return_data
        .and_then(|rd| rd.get("data").and_then(|d| d.get(0)).and_then(|d| d.as_str()).map(String::from));

    Ok(SimulationResult { success, error, logs, units_consumed, return_data, error_code, error_instruction_index })
}

// ── Address Lookup Table Resolution ─────────────────────────────────────────

#[derive(Serialize)]
struct GetAltRequest {
    jsonrpc: String,
    id: u32,
    method: String,
    params: (String, GetAltConfig),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GetAltConfig {
    encoding: String,
}

#[derive(Debug, Deserialize)]
struct GetAltResponse {
    result: Option<GetAltResult>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct GetAltResult {
    value: Option<GetAltValue>,
}

#[derive(Debug, Deserialize)]
struct GetAltValue {
    data: GetAltData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetAltData {
    addresses: Vec<String>,
}

/// Resolve the address lookup tables referenced by a v0 transaction via RPC,
/// replacing `<alt_index_N>` placeholders with the actual on-chain pubkeys.
///
/// Findings are returned as `AltIntegrity` risk flags:
/// - table not found on chain (likely closed) → Warning
/// - RPC/parse failure → Info (resolution skipped, placeholders retained)
/// - a referenced table index out of bounds → Warning
///
/// Tables are fetched once per unique table address.
pub async fn resolve_address_lookup_tables(rpc_url: &str, report: &mut TransactionReport) -> Vec<RiskFlag> {
    let mut flags = Vec::new();
    if report.address_lookup_tables.is_empty() {
        return flags;
    }

    let client = reqwest::Client::new();
    let mut cache: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

    for alt in &mut report.address_lookup_tables {
        let table_address = alt.table_address.clone();

        let addresses = if let Some(addrs) = cache.get(&table_address) {
            addrs.clone()
        } else {
            match fetch_lookup_table_addresses(&client, rpc_url, &table_address).await {
                Ok(Some(addrs)) => {
                    cache.insert(table_address.clone(), addrs.clone());
                    addrs
                }
                Ok(None) => {
                    flags.push(RiskFlag {
                        severity: RiskSeverity::Warning,
                        category: RiskCategory::AltIntegrity,
                        instruction_index: None,
                        message: format!(
                            "ALT Integrity: lookup table '{}' was not found on chain. \
                             The table may be closed.",
                            table_address
                        ),
                        details: "The referenced address lookup table no longer exists on-chain. \
                                  Transactions using a closed table fail with an invalid lookup error."
                            .to_string(),
                    });
                    continue;
                }
                Err(e) => {
                    flags.push(RiskFlag {
                        severity: RiskSeverity::Info,
                        category: RiskCategory::AltIntegrity,
                        instruction_index: None,
                        message: format!("Could not resolve address lookup table '{}'", table_address),
                        details: format!("RPC error: {}", e),
                    });
                    continue;
                }
            }
        };

        let mut out_of_bounds: Vec<u8> = Vec::new();
        for resolved in &mut alt.resolved_accounts {
            match resolved.table_index {
                Some(idx) => match addresses.get(idx as usize) {
                    Some(pk) => resolved.pubkey = pk.clone(),
                    None => out_of_bounds.push(idx),
                },
                None => { /* no table index recorded — keep the placeholder */ }
            }
        }
        alt.resolved = true;

        for idx in out_of_bounds {
            flags.push(RiskFlag {
                severity: RiskSeverity::Warning,
                category: RiskCategory::AltIntegrity,
                instruction_index: None,
                message: format!(
                    "ALT Integrity: lookup table '{}' has no account at index {} ({} addresses on chain)",
                    table_address,
                    idx,
                    addresses.len()
                ),
                details: "The transaction references an address beyond the table's on-chain length. \
                          The table may have been modified between transaction creation and execution."
                    .to_string(),
            });
        }
    }

    flags
}

/// Fetch the address list of a lookup table via `getAddressLookupTable`.
/// Returns Ok(None) when the table does not exist on chain.
async fn fetch_lookup_table_addresses(
    client: &reqwest::Client,
    rpc_url: &str,
    table_address: &str,
) -> Result<Option<Vec<String>>> {
    let request = GetAltRequest {
        jsonrpc: "2.0".to_string(),
        id: 1,
        method: "getAddressLookupTable".to_string(),
        params: (table_address.to_string(), GetAltConfig { encoding: "jsonParsed".to_string() }),
    };

    let response = client
        .post(rpc_url)
        .json(&request)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .context("Failed to send getAddressLookupTable RPC request")?;

    let body: GetAltResponse = response.json().await.context("Failed to parse getAddressLookupTable RPC response")?;

    if let Some(err) = body.error {
        anyhow::bail!("RPC error: {}", err.message);
    }

    match body.result {
        Some(result) => match result.value {
            Some(value) => Ok(Some(value.data.addresses)),
            None => Ok(None),
        },
        None => Ok(None),
    }
}

// ── Dynamic Program Verification ─────────────────────────────────────────────

#[derive(Serialize)]
struct GetAccountInfoRequest {
    jsonrpc: String,
    id: u32,
    method: String,
    params: (String, GetAccountInfoConfig),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GetAccountInfoConfig {
    encoding: String,
    commitment: String,
}

#[derive(Debug, Deserialize)]
struct GetAccountInfoResponse {
    result: Option<AccountInfoResult>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct AccountInfoResult {
    value: Option<AccountData>,
}

#[derive(Debug, Deserialize)]
struct AccountData {
    owner: String,
    executable: bool,
}

#[derive(Debug, Deserialize)]
struct VerifiedBuildStatus {
    is_verified: bool,
}

/// Verify all program accounts referenced in the transaction.
pub async fn verify_programs(rpc_url: &str, report: &TransactionReport) -> Vec<RiskFlag> {
    verify_programs_inner(rpc_url, VERIFIED_BUILD_REGISTRY, report).await
}

/// Verify programs with an explicit verified build registry URL (for testing).
#[allow(dead_code)]
pub async fn verify_programs_with_registry(
    rpc_url: &str,
    registry_url: &str,
    report: &TransactionReport,
) -> Vec<RiskFlag> {
    verify_programs_inner(rpc_url, registry_url, report).await
}

async fn verify_programs_inner(rpc_url: &str, registry_url: &str, report: &TransactionReport) -> Vec<RiskFlag> {
    let mut flags = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for ix in &report.instructions {
        let program_id = &ix.program_id;
        if !seen.insert(program_id.clone()) {
            continue;
        }

        // Well-known protocol programs are trusted: their bytecode is public and
        // independently audited. This is a trust list for protocol-level programs,
        // not a vulnerability blacklist — everything else is verified dynamically.
        if matches!(
            program_id.as_str(),
            SYSTEM_PROGRAM_ID
                | COMPUTE_BUDGET_PROGRAM_ID
                | ADDRESS_LOOKUP_TABLE_PROGRAM_ID
                | TOKEN_PROGRAM_ID
                | TOKEN_2022_PROGRAM_ID
                | ASSOCIATED_TOKEN_PROGRAM_ID
        ) {
            continue;
        }

        let owner = match check_program_owner(rpc_url, program_id).await {
            Ok(o) => o,
            Err(e) => {
                flags.push(RiskFlag {
                    severity: RiskSeverity::Info,
                    category: RiskCategory::ProgramOwnership,
                    instruction_index: Some(ix.index),
                    message: format!("Could not verify program ownership for '{}'", program_id),
                    details: format!("RPC error: {}", e),
                });
                continue;
            }
        };

        match owner {
            ProgramOwner::Upgradeable => {
                // Check verified build registry for upgradeable programs
                match check_verified_build(registry_url, program_id).await {
                    Ok(true) => { /* verified, no flag needed */ }
                    Ok(false) => {
                        flags.push(RiskFlag {
                            severity: RiskSeverity::Warning,
                            category: RiskCategory::VerifiedBuild,
                            instruction_index: Some(ix.index),
                            message: format!(
                                "Program '{}' is upgradeable (BPFLoaderUpgradeable) but not found in the Solana Verified Build Registry",
                                program_id
                            ),
                            details: "The deployed bytecode could not be matched to a public source repository. \
                                      Verify the program build independently.".to_string(),
                        });
                    }
                    Err(e) => {
                        flags.push(RiskFlag {
                            severity: RiskSeverity::Info,
                            category: RiskCategory::VerifiedBuild,
                            instruction_index: Some(ix.index),
                            message: format!("Could not query verified build registry for '{}'", program_id),
                            details: format!("Registry error: {}", e),
                        });
                    }
                }
            }
            ProgramOwner::Frozen => {
                // Frozen (immutable) programs are lower risk
            }
            ProgramOwner::Unknown(owner_pubkey) => {
                flags.push(RiskFlag {
                    severity: RiskSeverity::Warning,
                    category: RiskCategory::ProgramOwnership,
                    instruction_index: Some(ix.index),
                    message: format!(
                        "Program '{}' is owned by '{}' (not a known BPF loader). \
                         This may not be a valid on-chain program.",
                        program_id, owner_pubkey
                    ),
                    details: "The program account owner is neither BPFLoaderUpgradeable nor BPFLoader. \
                              Verify this is an executable program account."
                        .to_string(),
                });
            }
        }
    }

    flags
}

enum ProgramOwner {
    Upgradeable,
    Frozen,
    Unknown(String),
}

/// Check the on-chain owner of a program account via RPC getAccountInfo.
async fn check_program_owner(rpc_url: &str, program_id: &str) -> Result<ProgramOwner> {
    let client = reqwest::Client::new();

    let request = GetAccountInfoRequest {
        jsonrpc: "2.0".to_string(),
        id: 1,
        method: "getAccountInfo".to_string(),
        params: (
            program_id.to_string(),
            GetAccountInfoConfig { encoding: "jsonParsed".to_string(), commitment: "confirmed".to_string() },
        ),
    };

    let response = client
        .post(rpc_url)
        .json(&request)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .context("Failed to send getAccountInfo RPC request")?;

    let body: GetAccountInfoResponse = response.json().await.context("Failed to parse getAccountInfo RPC response")?;

    if let Some(err) = body.error {
        anyhow::bail!("RPC error: {}", err.message);
    }

    let account_data = match body.result.and_then(|r| r.value) {
        Some(data) => data,
        None => {
            return Ok(ProgramOwner::Unknown("account not found".to_string()));
        }
    };

    if !account_data.executable {
        return Ok(ProgramOwner::Unknown(format!("account not executable, owner={}", account_data.owner)));
    }

    match account_data.owner.as_str() {
        BPF_LOADER_UPGRADEABLE => Ok(ProgramOwner::Upgradeable),
        BPF_LOADER => Ok(ProgramOwner::Frozen),
        other => Ok(ProgramOwner::Unknown(other.to_string())),
    }
}

/// Query the Solana Verified Build Registry for a program.
async fn check_verified_build(registry_url: &str, program_id: &str) -> Result<bool> {
    let client = reqwest::Client::new();
    let url = format!("{}/status/{}", registry_url, program_id);

    let response = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .context("Failed to query verified build registry")?;

    if !response.status().is_success() {
        if response.status().as_u16() == 404 {
            return Ok(false);
        }
        anyhow::bail!("Registry returned HTTP {}", response.status());
    }

    let status: VerifiedBuildStatus = response.json().await.context("Failed to parse registry response")?;
    Ok(status.is_verified)
}
