use httpmock::prelude::*;
use rust_security_toolkit::simulator::{BlockhashStatus, blockhash_flag, blockhash_freshness, get_latest_blockhash};
use rust_security_toolkit::types::{RiskCategory, RiskSeverity};

fn mock_server(body: serde_json::Value) -> httpmock::MockServer {
    let server = httpmock::MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/");
        then.status(200).json_body(body);
    });
    server
}

#[tokio::test]
async fn get_latest_blockhash_parses_both_fields() {
    let server = mock_server(serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "result": { "value": { "blockHeight": 1000, "lastValidBlockHeight": 1150 } }
    }));
    let (height, last_valid) = get_latest_blockhash(&server.url("/")).await.expect("parse");
    assert_eq!(height, 1000);
    assert_eq!(last_valid, 1150);
}

#[tokio::test]
async fn get_latest_blockhash_rpc_error_bails() {
    let server = mock_server(serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "error": { "code": -32601, "message": "method not found" }
    }));
    let err = get_latest_blockhash(&server.url("/")).await;
    assert!(err.is_err());
}

#[tokio::test]
async fn get_latest_blockhash_null_result_bails() {
    let server = mock_server(serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": null }));
    assert!(get_latest_blockhash(&server.url("/")).await.is_err());
}

#[tokio::test]
async fn get_latest_blockhash_null_value_bails() {
    let server = mock_server(serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "result": { "value": null }
    }));
    assert!(get_latest_blockhash(&server.url("/")).await.is_err());
}

#[tokio::test]
async fn get_latest_blockhash_malformed_value_bails() {
    let server = mock_server(serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "result": { "value": { "blockHeight": "not-a-number" } }
    }));
    assert!(get_latest_blockhash(&server.url("/")).await.is_err());
}

#[test]
fn freshness_fresh_beyond_boundary() {
    assert!(matches!(blockhash_freshness(1000, 1150), BlockhashStatus::Fresh));
}

#[test]
fn freshness_expiring_at_exact_boundary() {
    assert!(matches!(blockhash_freshness(1100, 1150), BlockhashStatus::Expiring(50)));
}

#[test]
fn freshness_expired_when_current_past_last_valid() {
    assert!(matches!(blockhash_freshness(1200, 1150), BlockhashStatus::Expired));
}

#[test]
fn flag_expired_maps_to_warning() {
    let flag = blockhash_flag(BlockhashStatus::Expired).expect("expired maps to a flag");
    assert_eq!(flag.severity, RiskSeverity::Warning);
    assert_eq!(flag.category, RiskCategory::BlockhashExpired);
}

#[test]
fn flag_expiring_maps_to_info() {
    let flag = blockhash_flag(BlockhashStatus::Expiring(10)).expect("expiring maps to a flag");
    assert_eq!(flag.severity, RiskSeverity::Info);
    assert!(flag.message.contains("10 blocks remaining"));
}

#[test]
fn flag_fresh_maps_to_none() {
    assert!(blockhash_flag(BlockhashStatus::Fresh).is_none());
}
