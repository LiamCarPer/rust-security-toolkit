use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::types::{
    ADDRESS_LOOKUP_TABLE_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, COMPUTE_BUDGET_PROGRAM_ID, DecodedInstruction,
    RiskCategory, RiskFlag, RiskSeverity, SYSTEM_PROGRAM_ID, SimulationResult, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID,
    TokenAmount, TransactionReport,
};

const BPF_LOADER_UPGRADEABLE: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
const BPF_LOADER: &str = "BPFLoader2111111111111111111111111111111111";
pub const VERIFIED_BUILD_REGISTRY: &str = "https://verify.osec.io";

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
    #[serde(default)]
    data: Option<serde_json::Value>,
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

                // Report who can upgrade the program (best-effort).
                if let Some(authority) = check_upgrade_authority(rpc_url, program_id).await {
                    let (message, details) = match authority {
                        Some(auth) => (
                            format!("Program '{}' is upgradeable; upgrade authority: '{}'", program_id, auth),
                            "The program can be upgraded at any time by this authority. Verify the \
                             authority is a trusted entity (e.g. a DAO, multisig, or timelock)."
                                .to_string(),
                        ),
                        None => (
                            format!("Program '{}' is upgradeable with no upgrade authority (immutable)", program_id),
                            "The program data account declares no upgrade authority, so the deployed \
                             bytecode can never be upgraded."
                                .to_string(),
                        ),
                    };
                    flags.push(RiskFlag {
                        severity: RiskSeverity::Info,
                        category: RiskCategory::ProgramOwnership,
                        instruction_index: Some(ix.index),
                        message,
                        details,
                    });
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

/// Fetch the upgrade authority of an upgradeable program (best-effort).
///
/// Returns `Some(Some(auth))` when the program data account declares an
/// authority, `Some(None)` when it is immutable (no authority), and `None`
/// when the layout is not a standard upgradeable program or the fetch fails.
/// Failures are silent: the ownership check already succeeded, and this is
/// enrichment information.
async fn check_upgrade_authority(rpc_url: &str, program_id: &str) -> Option<Option<String>> {
    use solana_loader_v3_interface::state::UpgradeableLoaderState;

    let client = reqwest::Client::new();

    // The program account's data points at the program data account.
    let program_data_address = match fetch_account_data(&client, rpc_url, program_id).await {
        Ok(Some(data)) => match bincode::deserialize::<UpgradeableLoaderState>(&data) {
            Ok(UpgradeableLoaderState::Program { programdata_address }) => programdata_address,
            Ok(UpgradeableLoaderState::ProgramData { upgrade_authority_address, .. }) => {
                // Unusual: the queried account is itself a program data account.
                return Some(upgrade_authority_address.map(|p| p.to_string()));
            }
            _ => return None,
        },
        _ => return None,
    };

    match fetch_account_data(&client, rpc_url, &program_data_address.to_string()).await {
        Ok(Some(data)) => match bincode::deserialize::<UpgradeableLoaderState>(&data) {
            Ok(UpgradeableLoaderState::ProgramData { upgrade_authority_address, .. }) => {
                Some(upgrade_authority_address.map(|p| p.to_string()))
            }
            _ => None,
        },
        _ => None,
    }
}

/// Fetch an account's raw data (base64) via getAccountInfo.
async fn fetch_account_data(client: &reqwest::Client, rpc_url: &str, address: &str) -> Result<Option<Vec<u8>>> {
    let request = GetAccountInfoRequest {
        jsonrpc: "2.0".to_string(),
        id: 1,
        method: "getAccountInfo".to_string(),
        params: (
            address.to_string(),
            GetAccountInfoConfig { encoding: "base64".to_string(), commitment: "confirmed".to_string() },
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

    match body.result.and_then(|r| r.value) {
        Some(account) => match account.data {
            Some(serde_json::Value::Array(items)) => items
                .first()
                .and_then(|d| d.as_str())
                .and_then(|b64| {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.decode(b64).ok()
                })
                .map(Some)
                .ok_or_else(|| anyhow::anyhow!("account data is not base64-encoded")),
            _ => Ok(None),
        },
        None => Ok(None),
    }
}

// ── Token Amount Resolution ──────────────────────────────────────────────────

/// jsonParsed getAccountInfo response — `result.value.data` holds the parsed
/// JSON payload (mint `decimals` or token account `tokenAmount`).
#[derive(Debug, Deserialize)]
struct GetAccountInfoParsedResponse {
    result: Option<GetAccountInfoParsedResult>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct GetAccountInfoParsedResult {
    value: Option<GetAccountInfoParsedValue>,
}

#[derive(Debug, Deserialize)]
struct GetAccountInfoParsedValue {
    data: Option<serde_json::Value>,
}

/// Annotate token transfer/mint/burn instructions with human-readable amounts.
/// Checked variants carry decimals inline (offline resolution); unchecked
/// variants resolve decimals via RPC `getAccountInfo` (jsonParsed) when an
/// endpoint is provided. Resolution is silent: failures leave
/// `token_amount` unset rather than failing or emitting risk flags.
pub async fn resolve_token_amounts(rpc_url: Option<&str>, report: &mut TransactionReport) {
    let client = reqwest::Client::new();
    let mut decimals_cache: HashMap<String, Option<u8>> = HashMap::new();

    for ix in &mut report.instructions {
        if ix.program_id != TOKEN_PROGRAM_ID && ix.program_id != TOKEN_2022_PROGRAM_ID {
            continue;
        }
        let Some(name) = ix.instruction_name.clone() else { continue };
        if !matches!(
            name.as_str(),
            "Transfer"
                | "TransferChecked"
                | "Approve"
                | "ApproveChecked"
                | "MintTo"
                | "MintToChecked"
                | "Burn"
                | "BurnChecked"
                | "AmountToUiAmount"
        ) {
            continue;
        }
        // Skip instructions without an `amount` payload entirely.
        let Some(amount) = ix.data.get("amount").and_then(serde_json::Value::as_u64) else { continue };

        // Checked variants carry decimals inline — resolved offline, no RPC.
        if resolve_inline_decimals(ix).is_some() {
            continue;
        }

        // Unchecked variants need decimals from the mint, or from the source
        // token account for Transfer/Approve, via jsonParsed getAccountInfo.
        let Some(rpc_url) = rpc_url else { continue };
        let Some(position) = mint_source_position(&name) else { continue };
        let Some(pubkey) = ix.accounts.get(position).map(|a| a.pubkey.as_str()) else { continue };

        let is_mint = !matches!(name.as_str(), "Transfer" | "Approve");
        if let Some(decimals) = fetch_parsed_decimals(&client, rpc_url, pubkey, is_mint, &mut decimals_cache).await {
            ix.token_amount = Some(TokenAmount { raw: amount, decimals, human: format_ui_amount(amount, decimals) });
        }
    }
}

/// Resolve amount + decimals purely from instruction data (checked variants
/// carry both fields inline). Sets `token_amount` and returns the decimals,
/// or None when either field is missing or `token_amount` is left unset.
fn resolve_inline_decimals(ix: &mut DecodedInstruction) -> Option<u8> {
    let amount = ix.data.get("amount").and_then(serde_json::Value::as_u64)?;
    let decimals = ix.data.get("decimals").and_then(serde_json::Value::as_u64)? as u8;
    ix.token_amount = Some(TokenAmount { raw: amount, decimals, human: format_ui_amount(amount, decimals) });
    Some(decimals)
}

/// Positional lookup of the mint (or source token account for unchecked
/// Transfer/Approve) within `instruction.accounts`.
/// Returns Some(0) for MintTo/MintToChecked/AmountToUiAmount,
/// Some(1) for Burn/BurnChecked, Some(0) for Transfer/Approve
/// (source account fallback), None otherwise.
fn mint_source_position(instruction_name: &str) -> Option<usize> {
    match instruction_name {
        "MintTo" | "MintToChecked" | "AmountToUiAmount" | "Transfer" | "Approve" => Some(0),
        "Burn" | "BurnChecked" => Some(1),
        _ => None,
    }
}

/// Resolve an account's decimals via jsonParsed getAccountInfo, caching by
/// pubkey so each unique account costs exactly one RPC call. Any fetch or
/// parse failure is cached as None and skipped silently.
async fn fetch_parsed_decimals(
    client: &reqwest::Client,
    rpc_url: &str,
    pubkey: &str,
    is_mint: bool,
    cache: &mut HashMap<String, Option<u8>>,
) -> Option<u8> {
    if let Some(&cached) = cache.get(pubkey) {
        return cached;
    }
    let decimals = fetch_parsed_decimals_uncached(client, rpc_url, pubkey, is_mint).await;
    cache.insert(pubkey.to_string(), decimals);
    decimals
}

async fn fetch_parsed_decimals_uncached(
    client: &reqwest::Client,
    rpc_url: &str,
    pubkey: &str,
    is_mint: bool,
) -> Option<u8> {
    let request = GetAccountInfoRequest {
        jsonrpc: "2.0".to_string(),
        id: 1,
        method: "getAccountInfo".to_string(),
        params: (
            pubkey.to_string(),
            GetAccountInfoConfig { encoding: "jsonParsed".to_string(), commitment: "confirmed".to_string() },
        ),
    };

    let response = client.post(rpc_url).json(&request).timeout(std::time::Duration::from_secs(30)).send().await.ok()?;
    let body: GetAccountInfoParsedResponse = response.json().await.ok()?;
    if body.error.is_some() {
        return None;
    }
    let data = body.result?.value?.data?;
    if is_mint { decimals_from_data(&data) } else { decimals_from_token_amount(&data) }
}

/// Extract a mint's decimals from jsonParsed getAccountInfo account data
/// (`parsed.info.decimals`).
fn decimals_from_data(data: &serde_json::Value) -> Option<u8> {
    data.get("parsed")?.get("info")?.get("decimals")?.as_u64().map(|d| d as u8)
}

/// Extract a token account's decimals from jsonParsed getAccountInfo account
/// data (`parsed.info.tokenAmount.decimals`).
fn decimals_from_token_amount(data: &serde_json::Value) -> Option<u8> {
    data.get("parsed")?.get("info")?.get("tokenAmount")?.get("decimals")?.as_u64().map(|d| d as u8)
}

/// Format raw units with `decimals` decimal places, trimming trailing zeros.
/// Examples: (1_500_000, 6) -> "1.5"; (1_000_000, 6) -> "1"; (123_456, 2) -> "1234.56";
/// (1, 6) -> "0.000001"; (0, 6) -> "0"; (99, 0) -> "99".
fn format_ui_amount(raw: u64, decimals: u8) -> String {
    // 10^19 overflows u64 — such mints don't exist in practice.
    if decimals == 0 || decimals >= 19 {
        return raw.to_string();
    }
    let div = 10u64.pow(decimals as u32);
    let int_part = raw / div;
    let frac = raw % div;
    if frac == 0 {
        return int_part.to_string();
    }
    let frac_str = format!("{:0width$}", frac, width = decimals as usize);
    format!("{}.{}", int_part, frac_str.trim_end_matches('0'))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_ui_amount_cases() {
        assert_eq!(format_ui_amount(1_500_000, 6), "1.5");
        assert_eq!(format_ui_amount(1_000_000, 6), "1");
        assert_eq!(format_ui_amount(123_456, 2), "1234.56");
        assert_eq!(format_ui_amount(1, 6), "0.000001");
        assert_eq!(format_ui_amount(0, 6), "0");
        assert_eq!(format_ui_amount(99, 0), "99");
    }

    #[test]
    fn format_ui_amount_guards_large_decimals() {
        // 10^19 overflows u64; fall back to the raw integer rendering.
        assert_eq!(format_ui_amount(1_000_000, 19), "1000000");
        assert_eq!(format_ui_amount(7, 255), "7");
    }

    #[test]
    fn mint_source_position_table() {
        assert_eq!(mint_source_position("MintTo"), Some(0));
        assert_eq!(mint_source_position("MintToChecked"), Some(0));
        assert_eq!(mint_source_position("AmountToUiAmount"), Some(0));
        assert_eq!(mint_source_position("Burn"), Some(1));
        assert_eq!(mint_source_position("BurnChecked"), Some(1));
        assert_eq!(mint_source_position("Transfer"), Some(0));
        assert_eq!(mint_source_position("Approve"), Some(0));
        // Checked transfer/approve carry decimals inline; no positional lookup.
        assert_eq!(mint_source_position("TransferChecked"), None);
        assert_eq!(mint_source_position("ApproveChecked"), None);
        assert_eq!(mint_source_position("InitializeMint"), None);
        assert_eq!(mint_source_position(""), None);
    }

    #[test]
    fn decimals_from_data_reads_mint_decimals() {
        let data = serde_json::json!({ "parsed": { "info": { "decimals": 9 } } });
        assert_eq!(decimals_from_data(&data), Some(9));
        assert_eq!(decimals_from_token_amount(&data), None);
    }

    #[test]
    fn decimals_from_token_amount_reads_account_decimals() {
        let data = serde_json::json!({
            "parsed": { "info": { "tokenAmount": { "decimals": 6, "amount": "1500000" } } }
        });
        assert_eq!(decimals_from_token_amount(&data), Some(6));
        assert_eq!(decimals_from_data(&data), None);
    }

    #[test]
    fn resolve_inline_decimals_sets_token_amount_offline() {
        let mut ix = DecodedInstruction {
            index: 0,
            program_id: TOKEN_PROGRAM_ID.to_string(),
            program_name: "SPL Token".to_string(),
            instruction_name: Some("TransferChecked".to_string()),
            accounts: Vec::new(),
            data: serde_json::json!({ "amount": 1_500_000u64, "decimals": 6u64 }),
            raw_data_hex: "00".to_string(),
            token_amount: None,
        };

        assert_eq!(resolve_inline_decimals(&mut ix), Some(6));
        let token_amount = ix.token_amount.expect("token_amount should be set");
        assert_eq!(token_amount.raw, 1_500_000);
        assert_eq!(token_amount.decimals, 6);
        assert_eq!(token_amount.human, "1.5");
    }

    #[test]
    fn resolve_inline_decimals_leaves_unset_without_decimals() {
        let mut ix = DecodedInstruction {
            index: 0,
            program_id: TOKEN_2022_PROGRAM_ID.to_string(),
            program_name: "Token-2022".to_string(),
            instruction_name: Some("Transfer".to_string()),
            accounts: Vec::new(),
            data: serde_json::json!({ "amount": 5u64 }),
            raw_data_hex: "03".to_string(),
            token_amount: None,
        };

        // Unchecked variant without inline decimals — nothing to resolve offline.
        assert_eq!(resolve_inline_decimals(&mut ix), None);
        assert!(ix.token_amount.is_none());
    }
}
