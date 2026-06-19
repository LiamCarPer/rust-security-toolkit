use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::types::SimulationResult;

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
