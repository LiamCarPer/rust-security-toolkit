use httpmock::prelude::*;
use rust_security_toolkit::simulator;
use rust_security_toolkit::types::*;
use serde_json::json;
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_sdk::pubkey::Pubkey;

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
            token_amount: None,
        }],
        address_lookup_tables: vec![],
        compute_budget: None,
        risk_flags: vec![],
        simulation: None,
        warnings: vec![],
        signature_verification: vec![],
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
        token_amount: None,
    });

    let flags = simulator::verify_programs(&server.url(""), &report).await;
    assert!(flags.is_empty(), "System programs should be skipped without RPC");
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Mock getAccountInfo for an upgradeable program + its program data account.
fn mock_upgradeable_program(server: &MockServer, program_id: &str, programdata: &Pubkey, authority: Option<Pubkey>) {
    let program_state =
        bincode::serialize(&UpgradeableLoaderState::Program { programdata_address: *programdata }).unwrap();
    let programdata_state =
        bincode::serialize(&UpgradeableLoaderState::ProgramData { slot: 1, upgrade_authority_address: authority })
            .unwrap();

    server.mock(|when, then| {
        when.method(POST)
            .path("/")
            .json_body_partial(json!({ "method": "getAccountInfo", "params": [program_id] }).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "value": {
                "owner": "BPFLoaderUpgradeab1e11111111111111111111111",
                "executable": true,
                "data": [base64_encode(&program_state), "base64"]
            }}
        }));
    });
    server.mock(|when, then| {
        when.method(POST)
            .path("/")
            .json_body_partial(json!({ "method": "getAccountInfo", "params": [programdata.to_string()] }).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "value": {
                "owner": "BPFLoaderUpgradeab1e11111111111111111111111",
                "executable": false,
                "data": [base64_encode(&programdata_state), "base64"]
            }}
        }));
    });
}

/// Upgradeable programs report who can upgrade them.
#[tokio::test]
async fn test_upgrade_authority_reported() {
    let server = MockServer::start();
    let program_id = "UpgProg111111111111111111111111111111111111";
    let authority = Pubkey::new_unique();
    let programdata = Pubkey::new_unique();

    mock_upgradeable_program(&server, program_id, &programdata, Some(authority));
    // Verified in the build registry so the flag list stays focused.
    server.mock(|when, then| {
        when.method(GET).path(format!("/status/{}", program_id));
        then.status(200).json_body(json!({"is_verified": true}));
    });

    let report = make_report_with_program(program_id);
    let flags = simulator::verify_programs_with_registry(&server.url(""), &server.url(""), &report).await;

    let authority_flag = flags.iter().find(|f| f.message.contains("upgrade authority")).expect("authority flag");
    assert_eq!(authority_flag.severity, RiskSeverity::Info);
    assert!(authority_flag.message.contains(&authority.to_string()), "unexpected message: {}", authority_flag.message);
}

/// Upgradeable programs without an upgrade authority are immutable.
#[tokio::test]
async fn test_upgrade_authority_immutable() {
    let server = MockServer::start();
    let program_id = "ImmProg111111111111111111111111111111111111";
    let programdata = Pubkey::new_unique();

    mock_upgradeable_program(&server, program_id, &programdata, None);
    server.mock(|when, then| {
        when.method(GET).path(format!("/status/{}", program_id));
        then.status(200).json_body(json!({"is_verified": true}));
    });

    let report = make_report_with_program(program_id);
    let flags = simulator::verify_programs_with_registry(&server.url(""), &server.url(""), &report).await;

    let authority_flag = flags.iter().find(|f| f.message.contains("upgrade authority")).expect("authority flag");
    assert!(authority_flag.message.contains("no upgrade authority"), "unexpected message: {}", authority_flag.message);
}

/// Non-upgradeable owners never reach the authority check.
#[tokio::test]
async fn test_upgrade_authority_skipped_for_unknown_owner() {
    let server = MockServer::start();
    let program_id = "WeirdProg1111111111111111111111111111111111";

    // Unknown owner; no program-data mocks needed.
    server.mock(|when, then| {
        when.method(POST)
            .path("/")
            .json_body_partial(json!({ "method": "getAccountInfo", "params": [program_id] }).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "value": { "owner": "SomeUnknownLoader11111111111111111111111", "executable": true }}
        }));
    });

    let report = make_report_with_program(program_id);
    let flags = simulator::verify_programs(&server.url(""), &report).await;

    assert!(!flags.iter().any(|f| f.message.contains("upgrade authority")));
    assert_eq!(flags.len(), 1, "only the ownership warning expected");
}

/// Known SPL token programs (Token, Token-2022, AToken) are trusted protocol
/// programs and must be skipped without RPC calls.
#[tokio::test]
async fn test_token_programs_skipped() {
    let server = MockServer::start();

    // No mocks — token programs must be skipped before any RPC call
    let mut report = make_report_with_program("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    report.instructions.push(DecodedInstruction {
        index: 1,
        program_id: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb".into(),
        program_name: "Token-2022 Program".into(),
        instruction_name: Some("Transfer".into()),
        accounts: vec![],
        data: serde_json::Value::Null,
        raw_data_hex: String::new(),
        token_amount: None,
    });
    report.instructions.push(DecodedInstruction {
        index: 2,
        program_id: "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL".into(),
        program_name: "Associated Token Program".into(),
        instruction_name: Some("Create".into()),
        accounts: vec![],
        data: serde_json::Value::Null,
        raw_data_hex: String::new(),
        token_amount: None,
    });

    let flags = simulator::verify_programs(&server.url(""), &report).await;
    assert!(flags.is_empty(), "Token programs should be skipped without RPC");
}
