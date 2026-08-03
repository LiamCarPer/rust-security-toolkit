use httpmock::prelude::*;
use rust_security_toolkit::simulator;
use serde_json::json;

/// Dummy base64 string — the RPC is mocked, nothing is decoded client-side.
const DUMMY_TX: &str = "dHhieXRlcw==";

/// Successful simulation: err null, logs, CU consumed, return data decoded.
#[tokio::test]
async fn test_simulate_success() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "simulateTransaction"}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "value": {
                    "err": null,
                    "logs": ["Program log: hello"],
                    "unitsConsumed": 98500,
                    "returnData": {
                        "data": ["aGVsbG8=", "base64"],
                        "programId": "11111111111111111111111111111111"
                    }
                }
            }
        }));
    });

    let result = simulator::simulate_transaction(&server.url(""), DUMMY_TX).await.expect("expected Ok");

    assert!(result.success);
    assert!(result.error.is_none());
    assert_eq!(result.units_consumed, 98500);
    assert_eq!(result.logs, vec!["Program log: hello"]);
    assert_eq!(result.return_data.as_deref(), Some("aGVsbG8="));
}

/// Program-level error (Custom 42): success false, error preserved, logs kept.
#[tokio::test]
async fn test_simulate_program_error() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "simulateTransaction"}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "value": {
                    "err": {"InstructionError": [0, {"Custom": 42}]},
                    "logs": ["Program log: fail"],
                    "unitsConsumed": 1000,
                    "returnData": null
                }
            }
        }));
    });

    let result = simulator::simulate_transaction(&server.url(""), DUMMY_TX).await.expect("expected Ok");

    assert!(!result.success);
    let error = result.error.expect("expected an error");
    assert!(error.contains("InstructionError"), "error should mention InstructionError, got: {}", error);
    assert_eq!(result.logs, vec!["Program log: fail"]);
}

/// Compute unit exhaustion: error mentions ProgramFailedToComplete, logs preserved.
#[tokio::test]
async fn test_simulate_cu_exhaustion() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "simulateTransaction"}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "value": {
                    "err": {"InstructionError": [0, "ProgramFailedToComplete"]},
                    "logs": [
                        "Program log: ...",
                        "Program failed to complete: consumed 200000 of 200000 compute units"
                    ],
                    "unitsConsumed": 200000,
                    "returnData": null
                }
            }
        }));
    });

    let result = simulator::simulate_transaction(&server.url(""), DUMMY_TX).await.expect("expected Ok");

    assert!(!result.success);
    let error = result.error.expect("expected an error");
    assert!(
        error.contains("ProgramFailedToComplete") || error.contains("InstructionError"),
        "error should mention the CU exhaustion, got: {}",
        error
    );
    assert!(
        result.logs.contains(&"Program failed to complete: consumed 200000 of 200000 compute units".to_string()),
        "CU exhaustion log line should be preserved, got: {:?}",
        result.logs
    );
}

/// RPC-level error object: mapped to "RPC error: {message}".
#[tokio::test]
async fn test_simulate_rpc_error() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "simulateTransaction"}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32602, "message": "Invalid params"}
        }));
    });

    let result = simulator::simulate_transaction(&server.url(""), DUMMY_TX).await.expect("expected Ok");

    assert!(!result.success);
    assert_eq!(result.error.as_deref(), Some("RPC error: Invalid params"));
}

/// No `result` key in the response: "No result returned from simulation".
#[tokio::test]
async fn test_simulate_missing_result() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "simulateTransaction"}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0",
            "id": 1
        }));
    });

    let result = simulator::simulate_transaction(&server.url(""), DUMMY_TX).await.expect("expected Ok");

    assert!(!result.success);
    let error = result.error.expect("expected an error");
    assert!(error.contains("No result returned"), "unexpected error: {}", error);
}

/// Non-JSON HTTP error body: the call surfaces as Err.
#[tokio::test]
async fn test_simulate_http_error() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "simulateTransaction"}).to_string());
        then.status(500).body("boom");
    });

    let result = simulator::simulate_transaction(&server.url(""), DUMMY_TX).await;
    assert!(result.is_err(), "expected Err for HTTP 500, got: {:?}", result);
}
