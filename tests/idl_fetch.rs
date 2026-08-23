use base64::Engine;
use flate2::Compression;
use flate2::write::ZlibEncoder;
use httpmock::prelude::*;
use rust_security_toolkit::idl_fetch::{PMP_PROGRAM_ID, derive_legacy_idl_address, fetch_idl, parse_legacy_idl_bytes};
use rust_security_toolkit::types::IdlJson;
use serde_json::json;
use solana_sdk::pubkey::Pubkey;
use std::io::Write;
use std::str::FromStr;

const LEGACY_DISCRIMINATOR: [u8; 8] = [0x18, 0x46, 0x62, 0xbf, 0x3a, 0x90, 0x7b, 0x9e];

fn zlib_compress(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).expect("zlib write");
    encoder.finish().expect("zlib finish")
}

fn minimal_idl_json() -> Vec<u8> {
    json!({
        "version": "0.29.0",
        "name": "forensics-program",
        "instructions": [
            {
                "name": "initialize",
                "accounts": [{"name": "payer", "isMut": true, "isSigner": true}],
                "args": []
            },
            {
                "name": "deposit",
                "accounts": [
                    {"name": "owner", "isMut": false, "isSigner": true},
                    {"name": "vault", "isMut": true, "isSigner": false}
                ],
                "args": [{"name": "amount", "type": "u64"}]
            }
        ]
    })
    .to_string()
    .into_bytes()
}

fn build_legacy_account(payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&LEGACY_DISCRIMINATOR);
    data.extend_from_slice(&[7u8; 32]);
    data.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    data.extend_from_slice(payload);
    data
}

fn account_response(owner: &str, data: &[u8]) -> serde_json::Value {
    let encoded = base64::engine::general_purpose::STANDARD.encode(data);
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "value": {"owner": owner, "executable": false, "lamports": 1000000, "data": [encoded, "base64"]}
        },
        "error": null
    })
}

fn null_account_response() -> serde_json::Value {
    json!({"jsonrpc": "2.0", "id": 1, "result": null, "error": null})
}

fn mock_rpc(server: &MockServer, body: serde_json::Value) {
    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "getAccountInfo"}).to_string());
        then.status(200).json_body(body);
    });
}

#[tokio::test]
async fn legacy_layout_parses() {
    let server = MockServer::start();
    let program = Pubkey::new_unique();
    let account = build_legacy_account(&zlib_compress(&minimal_idl_json()));
    mock_rpc(&server, account_response(&program.to_string(), &account));

    let idl = fetch_idl(&server.url("/"), &program).await.expect("fetch ok").expect("idl present");
    assert_eq!(idl.name, "forensics-program");
    assert_eq!(idl.version, "0.29.0");
    assert_eq!(idl.instructions.len(), 2);
    assert!(idl.find_instruction("deposit").is_some());
}

#[tokio::test]
async fn missing_account_returns_none() {
    let server = MockServer::start();
    mock_rpc(&server, null_account_response());

    let program = Pubkey::new_unique();
    let result = fetch_idl(&server.url("/"), &program).await.expect("fetch ok");
    assert!(result.is_none());
}

#[tokio::test]
async fn oversized_payload_rejected() {
    let program = Pubkey::new_unique();

    let mut claimed_huge = Vec::new();
    claimed_huge.extend_from_slice(&LEGACY_DISCRIMINATOR);
    claimed_huge.extend_from_slice(&[0u8; 32]);
    claimed_huge.extend_from_slice(&u32::MAX.to_le_bytes());
    claimed_huge.extend_from_slice(b"{}");
    let server = MockServer::start();
    mock_rpc(&server, account_response(&program.to_string(), &claimed_huge));
    let result = fetch_idl(&server.url("/"), &program).await.expect("fetch ok");
    assert!(result.is_none(), "claimed length beyond the real buffer must be rejected");

    let mut oversized_actual = Vec::new();
    oversized_actual.extend_from_slice(&LEGACY_DISCRIMINATOR);
    oversized_actual.extend_from_slice(&[0u8; 32]);
    let declared_len = 4 * 1024 * 1024 + 1;
    oversized_actual.extend_from_slice(&(declared_len as u32).to_le_bytes());
    oversized_actual.resize(oversized_actual.len() + declared_len, 0);
    assert!(parse_legacy_idl_bytes(&oversized_actual).is_none());
}

#[tokio::test]
async fn malformed_json_returns_none() {
    let server = MockServer::start();
    let program = Pubkey::new_unique();
    let account = build_legacy_account(b"{{{ not json at all");
    mock_rpc(&server, account_response(&program.to_string(), &account));

    let result = fetch_idl(&server.url("/"), &program).await.expect("fetch ok");
    assert!(result.is_none());
}

#[tokio::test]
async fn wrong_owner_or_garbage_discriminator_returns_none() {
    let program = Pubkey::new_unique();

    let impostor_owner = Pubkey::new_unique().to_string();
    let server = MockServer::start();
    let account = build_legacy_account(&zlib_compress(&minimal_idl_json()));
    mock_rpc(&server, account_response(&impostor_owner, &account));
    let result = fetch_idl(&server.url("/"), &program).await.expect("fetch ok");
    assert!(result.is_none(), "account owned by another key must be rejected");

    let server = MockServer::start();
    let mut garbage_disc = build_legacy_account(&zlib_compress(&minimal_idl_json()));
    garbage_disc[3] ^= 0xff;
    mock_rpc(&server, account_response(&program.to_string(), &garbage_disc));
    let result = fetch_idl(&server.url("/"), &program).await.expect("fetch ok");
    assert!(result.is_none(), "wrong discriminator must be rejected");
}

#[tokio::test]
async fn zero_padded_json_tail_trimmed() {
    let server = MockServer::start();
    let program = Pubkey::new_unique();

    let mut payload = minimal_idl_json();
    payload.extend(std::iter::repeat_n(0u8, 64));
    let account = build_legacy_account(&payload);
    mock_rpc(&server, account_response(&program.to_string(), &account));

    let idl = fetch_idl(&server.url("/"), &program).await.expect("fetch ok").expect("idl present");
    assert_eq!(idl.instructions.len(), 2);
}

#[tokio::test]
async fn decompression_bomb_rejected() {
    let bomb_payload = std::iter::repeat_n(0u8, 6 * 1024 * 1024).collect::<Vec<u8>>();
    let compressed = zlib_compress(&bomb_payload);
    assert!(compressed.len() < bomb_payload.len());
    assert!(parse_legacy_idl_bytes(&build_legacy_account(&compressed)).is_none());
}

#[tokio::test]
async fn metadata_layout_parses_with_conversion() {
    let server = MockServer::start();
    let program = Pubkey::from_str("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4").unwrap();

    let spec_json = json!({
        "address": program.to_string(),
        "metadata": {"name": "jupiter", "version": "1.0.0", "spec": "0.1.0"},
        "instructions": [
            {
                "name": "swap",
                "discriminator": [248, 198, 158, 132, 121, 7, 181, 116],
                "accounts": [
                    {"name": "user", "writable": true, "signer": true},
                    {"name": "pool", "writable": false, "signer": false}
                ],
                "args": []
            },
            {
                "name": "route",
                "discriminator": [1, 2, 3, 4, 5, 6, 7, 8],
                "accounts": [
                    {"name": "group", "accounts": [
                        {"name": "in", "writable": true, "signer": false},
                        {"name": "out", "writable": true, "signer": false}
                    ]}
                ],
                "args": []
            }
        ]
    })
    .to_string()
    .into_bytes();

    let mut account = Vec::new();
    account.push(2u8);
    account.extend_from_slice(program.as_ref());
    account.extend_from_slice(&[0u8; 32]);
    account.push(1u8);
    account.push(1u8);
    let mut seed = [0u8; 16];
    seed[..3].copy_from_slice(b"idl");
    account.extend_from_slice(&seed);
    account.push(1u8);
    account.push(2u8);
    account.push(1u8);
    account.push(0u8);
    let compressed = zlib_compress(&spec_json);
    account.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    account.extend_from_slice(&[0u8; 5]);
    account.extend_from_slice(&compressed);

    mock_rpc(&server, account_response(&PMP_PROGRAM_ID.to_string(), &account));

    let idl = fetch_idl(&server.url("/"), &program).await.expect("fetch ok").expect("idl present");
    assert_eq!(idl.name, "jupiter");
    assert_eq!(idl.version, "1.0.0");
    assert_eq!(idl.instructions.len(), 2);

    let swap = idl.find_instruction("swap").expect("swap instruction");
    assert!(swap.accounts[0].is_signer, "signer flag must map from spec 'signer'");
    assert!(swap.accounts[0].is_mut, "mut flag must map from spec 'writable'");
    assert!(!swap.accounts[1].is_signer && !swap.accounts[1].is_mut);

    let route = idl.find_instruction("route").expect("route instruction");
    assert_eq!(route.accounts.len(), 2, "composite account groups must flatten");
    assert!(route.accounts.iter().all(|a| a.name == "in" || a.name == "out"));
}

#[tokio::test]
async fn metadata_absent_falls_through_to_none() {
    let server = MockServer::start();
    mock_rpc(&server, null_account_response());

    let program = Pubkey::from_str("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8").unwrap();
    let derived = derive_legacy_idl_address(&program);
    assert_ne!(derived, Pubkey::default());

    let result = fetch_idl(&server.url("/"), &program).await.expect("fetch ok");
    assert!(result.is_none());
}

#[tokio::test]
async fn legacy_account_with_spec_json_converts() {
    let server = MockServer::start();
    let program = Pubkey::from_str("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4").unwrap();

    let spec_json = json!({
        "address": program.to_string(),
        "metadata": {"name": "legacy-spec", "version": "3.1.0", "spec": "0.1.0"},
        "instructions": [{
            "name": "claim",
            "discriminator": [9, 8, 7, 6, 5, 4, 3, 2],
            "accounts": [{"name": "owner", "writable": true, "signer": true}],
            "args": []
        }]
    })
    .to_string()
    .into_bytes();

    let account = build_legacy_account(&zlib_compress(&spec_json));
    mock_rpc(&server, account_response(&program.to_string(), &account));

    let idl = fetch_idl(&server.url("/"), &program).await.expect("fetch ok").expect("idl present");
    assert_eq!(idl.name, "legacy-spec");
    assert_eq!(idl.version, "3.1.0");
    assert_eq!(idl.instructions.len(), 1);
}

fn assert_valid_idl(idl: &IdlJson) {
    assert!(!idl.instructions.is_empty(), "live IDL must have non-empty instructions");
    println!("IDL: name={} version={} instructions={}", idl.name, idl.version, idl.instructions.len());
}

#[tokio::test]
#[ignore]
async fn live_mainnet_anchor_program_fetches() {
    const MAINNET_RPC: &str = "https://api.mainnet-beta.solana.com";
    const CANDIDATES: &[&str] = &[
        "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
        "R24eNo1iYnMvDooXo1cqAwtPN6uaBCMtBVY7oQjZdpz",
        "ENGNY6wZ9Ha3DiCoA1R41o73Azt2RKsu8DBnKCoE5dvd",
    ];

    let mut successes = 0;
    let mut failures = Vec::new();
    for candidate in CANDIDATES {
        let program = match Pubkey::from_str(candidate) {
            Ok(p) => p,
            Err(e) => {
                failures.push(format!("{candidate}: invalid pubkey {e}"));
                continue;
            }
        };
        match fetch_idl(MAINNET_RPC, &program).await {
            Ok(Some(idl)) => {
                assert_valid_idl(&idl);
                successes += 1;
            }
            Ok(None) => failures.push(format!("{candidate}: no on-chain IDL found")),
            Err(e) => failures.push(format!("{candidate}: error {e}")),
        }
    }

    println!("Live fetch successes: {successes}/{}", CANDIDATES.len());
    for f in &failures {
        println!("  {}", f);
    }
    assert!(successes > 0, "expected at least one live IDL fetch to succeed; tried: {failures:?}");
}
