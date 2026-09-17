use std::os::unix::fs::PermissionsExt;
use std::str::FromStr;

use httpmock::prelude::*;
use rust_security_toolkit::bytecode::{self, AnalyzeOptions};
use rust_security_toolkit::types::{AccountInfo, DecodedInstruction, MappedAccount, TransactionReport};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_sdk::pubkey::Pubkey;

const DISPATCH_VALUE: u64 = 0xdead_beef_cafe_babe;

fn fake_sol_azy(dir: &std::path::Path) -> String {
    let path = dir.join("fake-sol-azy.sh");
    let script = format!(
        r#"#!/bin/sh
if [ "$1" = "--help" ]; then exit 0; fi
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--out-dir" ]; then out="$arg"; fi
  prev="$arg"
done
if [ -z "$out" ]; then echo "missing out-dir" >&2; exit 1; fi
mkdir -p "$out"
cat > "$out/disassembly.out" <<'DISA'
entrypoint:
  call sol_invoke_signed_c
  call sol_sha256
  lddw r1, 0x{:x}
  call sol_log_
DISA
cat > "$out/immediate_data_table" <<'TABLE'
0x1000043e0 (+ 0x43e0): b"You win!"
0x1000043f4 (+ 0x43f4): b"Not enough data"
0x1000044a8 (+ 0x44a8): b"library/alloc/src/raw_vec.rs"
TABLE
exit 0
"#,
        DISPATCH_VALUE
    );
    std::fs::write(&path, script).expect("write fake sol-azy");
    let mut perms = std::fs::metadata(&path).expect("stat").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("chmod");
    path.to_string_lossy().to_string()
}

fn account_response(data: &[u8]) -> serde_json::Value {
    use base64::Engine;
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "value": {
                "owner": "BPFLoaderUpgradeab1e11111111111111111111111",
                "executable": true,
                "data": [base64::engine::general_purpose::STANDARD.encode(data), "base64"],
            }
        }
    })
}

fn report_with_unknown_instruction(program_id: &Pubkey) -> TransactionReport {
    let mut data = DISPATCH_VALUE.to_le_bytes().to_vec();
    data.extend_from_slice(&[1, 2, 3, 4]);
    TransactionReport {
        status: "DECODED SUCCESSFULLY".to_string(),
        fee_payer: "FeePayer111111111111111111111111111111111".to_string(),
        signatures: Vec::new(),
        recent_blockhash: String::new(),
        message_version: None,
        accounts: vec![AccountInfo {
            index: 0,
            pubkey: program_id.to_string(),
            is_signer: false,
            is_writable: false,
            role: None,
            pda_info: None,
        }],
        instructions: vec![DecodedInstruction {
            index: 0,
            program_id: program_id.to_string(),
            program_name: "Unknown Program".to_string(),
            instruction_name: None,
            accounts: vec![MappedAccount {
                name: None,
                pubkey: program_id.to_string(),
                account_index: 0,
                is_signer: false,
                is_writable: false,
            }],
            data: serde_json::Value::Null,
            raw_data_hex: hex::encode(&data),
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
    }
}

#[tokio::test]
async fn analyze_programs_full_pipeline_offline() {
    let server = MockServer::start();
    let program_id = Pubkey::from_str("mmm3XBJg5gk8XJxEKBvdgptZz6SgK4tXvn36sodowMc").unwrap();
    let programdata_id = Pubkey::new_unique();
    let authority = Pubkey::new_unique();

    let program_account =
        bincode::serialize(&UpgradeableLoaderState::Program { programdata_address: programdata_id }).unwrap();
    let mut programdata_account = bincode::serialize(&UpgradeableLoaderState::ProgramData {
        slot: 42,
        upgrade_authority_address: Some(authority),
    })
    .unwrap();
    programdata_account.extend_from_slice(b"\x7fELFfake-bytecode");

    server.mock(|when, then| {
        when.method(POST).path("/").body_contains(programdata_id.to_string());
        then.status(200).json_body(account_response(&programdata_account));
    });
    server.mock(|when, then| {
        when.method(POST).path("/").body_contains(program_id.to_string());
        then.status(200).json_body(account_response(&program_account));
    });

    let temp = std::env::temp_dir().join(format!("rts-bytecode-test-{}", std::process::id()));
    std::fs::create_dir_all(&temp).unwrap();
    let binary = fake_sol_azy(&temp);

    let mut report = report_with_unknown_instruction(&program_id);
    let options = AnalyzeOptions { binary, artifact_dir: None };
    let warnings = bytecode::analyze_programs(&server.url("/"), &mut report, &[program_id], &options).await;

    assert!(warnings.is_empty(), "warnings: {:?}", warnings);
    assert_eq!(report.program_analyses.len(), 1);
    let analysis = &report.program_analyses[0];
    assert_eq!(analysis.program_id, program_id.to_string());
    assert_eq!(analysis.loader, "upgradeable");
    assert_eq!(analysis.upgrade_authority.as_deref(), Some(authority.to_string().as_str()));
    assert_eq!(analysis.elf_size, b"\x7fELFfake-bytecode".len());
    assert!(analysis.syscalls.contains(&"sol_invoke_signed_c".to_string()));
    assert!(analysis.syscalls.contains(&"sol_log_".to_string()));
    assert_eq!(analysis.strings, vec!["You win!".to_string(), "Not enough data".to_string()]);
    assert_eq!(analysis.dispatch_candidates, vec![hex::encode(DISPATCH_VALUE.to_le_bytes())]);
    assert_eq!(analysis.matched_instructions, vec![0]);
    assert_eq!(
        report.instructions[0].instruction_name.as_deref(),
        Some(format!("dispatch:0x{}", hex::encode(DISPATCH_VALUE.to_le_bytes())).as_str())
    );

    let _ = std::fs::remove_dir_all(&temp);
}

#[tokio::test]
async fn missing_sol_azy_warns_and_skips() {
    let program_id = Pubkey::new_unique();
    let mut report = report_with_unknown_instruction(&program_id);
    let options = AnalyzeOptions { binary: "/nonexistent/sol-azy-binary".to_string(), artifact_dir: None };
    let warnings = bytecode::analyze_programs("http://127.0.0.1:1", &mut report, &[program_id], &options).await;
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("not installed"));
    assert!(report.program_analyses.is_empty());
}
