use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::types::{RiskCategory, RiskFlag, RiskSeverity, SimulationResult, TransactionReport};

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

    let response =
        client.post(rpc_url).json(&request).send().await.context("Failed to send simulateTransaction RPC request")?;

    let body: RpcSimulateResponse =
        response.json().await.context("Failed to parse simulateTransaction RPC response")?;

    if let Some(err) = body.error {
        return Ok(SimulationResult {
            success: false,
            error: Some(format!("RPC error: {}", err.message)),
            logs: Vec::new(),
            units_consumed: 0,
            return_data: None,
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
            });
        }
    };

    let success = value.err.is_none();
    let error = value.err.map(|e| e.to_string());
    let logs = value.logs.unwrap_or_default();
    let units_consumed = value.units_consumed.unwrap_or(0);

    let return_data = value
        .return_data
        .and_then(|rd| rd.get("data").and_then(|d| d.get(0)).and_then(|d| d.as_str()).map(String::from));

    Ok(SimulationResult { success, error, logs, units_consumed, return_data })
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

        // Skip well-known system programs
        if program_id == "11111111111111111111111111111111"
            || program_id == "ComputeBudget111111111111111111111111111111"
            || program_id == "AddressLookupTab1e1111111111111111111111111"
        {
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

    let response =
        client.post(rpc_url).json(&request).send().await.context("Failed to send getAccountInfo RPC request")?;

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
