use httpmock::prelude::*;
use rust_security_toolkit::simulator;
use rust_security_toolkit::types::*;
use serde_json::json;

fn make_report_with_program(program_id: &str) -> TransactionReport {
    TransactionReport {
        status: "DECODED SUCCESSFULLY".into(),
        fee_payer: "11111111111111111111111111111111".into(),
        signatures: vec![],
        recent_blockhash: "11111111111111111111111111111111".into(),
        message_version: None,
        accounts: vec![],
        instructions: vec![DecodedInstruction {
            index: 0,
            program_id: program_id.into(),
            program_name: "Test Program".into(),
            instruction_name: Some("test_ix".into()),
            accounts: vec![],
            data: serde_json::Value::Null,
            raw_data_hex: String::new(),
        }],
        address_lookup_tables: vec![],
        compute_budget: None,
        risk_flags: vec![],
        simulation: None,
        warnings: vec![],
    }
}

/// Upgradeable program (BPFLoaderUpgradeable owner) → no ownership flag.
#[tokio::test]
async fn test_upgradeable_program_no_flag() {
    let server = MockServer::start();
    let program_id = "MyProg111111111111111111111111111111111111";

    // Mock getAccountInfo → BPFLoaderUpgradeable owner
    server.mock(|when, then| {
        when.method(POST)
            .path("/")
            .json_body_partial(json!({"method": "getAccountInfo", "params": [program_id]}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "value": {
                    "owner": "BPFLoaderUpgradeab1e11111111111111111111111",
                    "executable": true
                }
            }
        }));
    });

    // Mock verified build registry → verified
    server.mock(|when, then| {
        when.method(GET).path(format!("/status/{}", program_id));
        then.status(200).json_body(json!({"is_verified": true}));
    });

    let report = make_report_with_program(program_id);
    let flags = simulator::verify_programs_with_registry(&server.url(""), &server.url(""), &report).await;

    assert!(flags.is_empty(), "Expected no flags for verified upgradeable program");
}

/// Upgradeable but unverified → VerifiedBuild warning.
#[tokio::test]
async fn test_upgradeable_unverified_warning() {
    let server = MockServer::start();
    let program_id = "MyProg2222222222222222222222222222222222222";

    server.mock(|when, then| {
        when.method(POST)
            .path("/")
            .json_body_partial(json!({"method": "getAccountInfo", "params": [program_id]}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "value": {
                "owner": "BPFLoaderUpgradeab1e11111111111111111111111",
                "executable": true
            }}
        }));
    });

    // Registry returns 404 → not verified
    server.mock(|when, then| {
        when.method(GET).path(format!("/status/{}", program_id));
        then.status(404);
    });

    let report = make_report_with_program(program_id);
    let flags = simulator::verify_programs_with_registry(&server.url(""), &server.url(""), &report).await;

    assert_eq!(flags.len(), 1);
    assert_eq!(flags[0].category, RiskCategory::VerifiedBuild);
    assert_eq!(flags[0].severity, RiskSeverity::Warning);
    assert!(flags[0].message.contains("MyProg2"));
}

/// Frozen BPFLoader program → no flags.
#[tokio::test]
async fn test_frozen_program_no_flag() {
    let server = MockServer::start();
    let program_id = "FrozenPrg1111111111111111111111111111111111";

    server.mock(|when, then| {
        when.method(POST)
            .path("/")
            .json_body_partial(json!({"method": "getAccountInfo", "params": [program_id]}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "value": {
                "owner": "BPFLoader2111111111111111111111111111111111",
                "executable": true
            }}
        }));
    });

    let report = make_report_with_program(program_id);
    let flags = simulator::verify_programs(&server.url(""), &report).await;
    assert!(flags.is_empty(), "Frozen programs should produce no flags");
}

/// Unknown owner → ProgramOwnership warning.
#[tokio::test]
async fn test_unknown_owner_warning() {
    let server = MockServer::start();
    let program_id = "WeirdProg1111111111111111111111111111111111";

    server.mock(|when, then| {
        when.method(POST)
            .path("/")
            .json_body_partial(json!({"method": "getAccountInfo", "params": [program_id]}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "value": {
                "owner": "SomeUnknownLoader11111111111111111111111",
                "executable": true
            }}
        }));
    });

    let report = make_report_with_program(program_id);
    let flags = simulator::verify_programs(&server.url(""), &report).await;

    assert_eq!(flags.len(), 1);
    assert_eq!(flags[0].category, RiskCategory::ProgramOwnership);
    assert_eq!(flags[0].severity, RiskSeverity::Warning);
    assert!(flags[0].message.contains("SomeUnknownLoader"));
}

/// Account not found → Info flag.
#[tokio::test]
async fn test_account_not_found_info() {
    let server = MockServer::start();
    let program_id = "GhostProg1111111111111111111111111111111111";

    server.mock(|when, then| {
        when.method(POST)
            .path("/")
            .json_body_partial(json!({"method": "getAccountInfo", "params": [program_id]}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "value": null }
        }));
    });

    let report = make_report_with_program(program_id);
    let flags = simulator::verify_programs_with_registry(&server.url(""), &server.url(""), &report).await;

    assert_eq!(flags.len(), 1);
    assert_eq!(flags[0].category, RiskCategory::ProgramOwnership);
    assert_eq!(flags[0].severity, RiskSeverity::Warning);
}

/// Not executable → Info flag.
#[tokio::test]
async fn test_not_executable_info() {
    let server = MockServer::start();
    let program_id = "NotAProg11111111111111111111111111111111111";

    server.mock(|when, then| {
        when.method(POST)
            .path("/")
            .json_body_partial(json!({"method": "getAccountInfo", "params": [program_id]}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "value": {
                "owner": "BPFLoaderUpgradeab1e11111111111111111111111",
                "executable": false
            }}
        }));
    });

    let report = make_report_with_program(program_id);
    let flags = simulator::verify_programs(&server.url(""), &report).await;

    assert_eq!(flags.len(), 1);
    assert!(flags[0].message.contains("not executable"));
}

/// RPC error → Info flag, doesn't crash.
#[tokio::test]
async fn test_rpc_error_graceful() {
    let server = MockServer::start();
    let program_id = "ErrProg111111111111111111111111111111111111";

    server.mock(|when, then| {
        when.method(POST)
            .path("/")
            .json_body_partial(json!({"method": "getAccountInfo", "params": [program_id]}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0", "id": 1,
            "error": { "code": -32000, "message": "Something went wrong" }
        }));
    });

    let report = make_report_with_program(program_id);
    let flags = simulator::verify_programs(&server.url(""), &report).await;

    assert_eq!(flags.len(), 1);
    assert_eq!(flags[0].severity, RiskSeverity::Info);
    assert!(flags[0].details.contains("Something went wrong"));
}

/// Built-in system programs are skipped (no RPC call).
#[tokio::test]
async fn test_system_programs_skipped() {
    let server = MockServer::start();

    // No mocks needed — system programs should be skipped before any RPC call
    let mut report = make_report_with_program("11111111111111111111111111111111");
    report.instructions.push(DecodedInstruction {
        index: 1,
        program_id: "ComputeBudget111111111111111111111111111111".into(),
        program_name: "Compute Budget".into(),
        instruction_name: Some("SetComputeUnitLimit".into()),
        accounts: vec![],
        data: serde_json::Value::Null,
        raw_data_hex: String::new(),
    });

    let flags = simulator::verify_programs(&server.url(""), &report).await;
    assert!(flags.is_empty(), "System programs should be skipped without RPC");
}
