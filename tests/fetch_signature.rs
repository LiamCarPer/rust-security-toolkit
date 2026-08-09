use base64::Engine;
use httpmock::prelude::*;
use rust_security_toolkit::simulator::fetch_transaction_by_signature;
use serde_json::json;
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    message::{VersionedMessage, legacy, v0},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use solana_system_interface::instruction::SystemInstruction;
use std::str::FromStr;

const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";
const TEST_SIGNATURE: &str = "5K1kQw7z2YdF2xK5Tt8JmNqRwVpYc4c7QhWbXzDmFgHsJkL";

fn base64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn build_legacy_tx() -> Vec<u8> {
    let payer = Keypair::new();
    let recipient = Pubkey::new_unique();
    let recent_blockhash = Hash::new_from_array([7u8; 32]);

    let mut cu_limit_data = vec![2u8];
    cu_limit_data.extend_from_slice(&300_000u32.to_le_bytes());

    let instructions = vec![
        Instruction {
            program_id: Pubkey::from_str(COMPUTE_BUDGET_PROGRAM_ID).unwrap(),
            accounts: vec![],
            data: cu_limit_data,
        },
        Instruction {
            program_id: Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap(),
            accounts: vec![AccountMeta::new(payer.pubkey(), true), AccountMeta::new_readonly(recipient, false)],
            data: bincode::serialize(&SystemInstruction::Transfer { lamports: 1_000_000 }).unwrap(),
        },
    ];

    let message = VersionedMessage::Legacy(legacy::Message::new_with_blockhash(
        &instructions,
        Some(&payer.pubkey()),
        &recent_blockhash,
    ));
    let tx = VersionedTransaction { signatures: vec![payer.sign_message(&message.serialize())], message };
    bincode::serialize(&tx).unwrap()
}

fn build_v0_static_keys_tx() -> Vec<u8> {
    let payer = Keypair::new();
    let recipient = Pubkey::new_unique();
    let recent_blockhash = Hash::new_from_array([9u8; 32]);

    let ix = Instruction {
        program_id: Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap(),
        accounts: vec![AccountMeta::new(payer.pubkey(), true), AccountMeta::new_readonly(recipient, false)],
        data: bincode::serialize(&SystemInstruction::Transfer { lamports: 1_000_000 }).unwrap(),
    };

    let msg = v0::Message::try_compile(&payer.pubkey(), &[ix], &[], recent_blockhash).unwrap();
    let tx = VersionedTransaction {
        signatures: vec![payer.sign_message(&msg.serialize())],
        message: VersionedMessage::V0(msg),
    };
    bincode::serialize(&tx).unwrap()
}

#[tokio::test]
async fn fetch_transaction_returns_exact_raw_bytes() {
    let server = MockServer::start();
    let raw = build_legacy_tx();
    let encoded = base64_encode(&raw);

    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(
            json!({
                "method": "getTransaction",
                "params": [
                    TEST_SIGNATURE,
                    {
                        "encoding": "base64",
                        "commitment": "confirmed",
                        "maxSupportedTransactionVersion": 0
                    }
                ]
            })
            .to_string(),
        );
        then.status(200).json_body(json!({
            "jsonrpc": "2.0", "id": 1,
            "result": [encoded, ["some-signature"]]
        }));
    });

    let bytes = fetch_transaction_by_signature(&server.url("/"), TEST_SIGNATURE).await.unwrap();
    assert_eq!(bytes, raw);
}

#[tokio::test]
async fn fetch_transaction_not_found_bails() {
    let server = MockServer::start();

    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "getTransaction"}).to_string());
        then.status(200).json_body(json!({"jsonrpc": "2.0", "id": 1, "result": null}));
    });

    let err = fetch_transaction_by_signature(&server.url("/"), TEST_SIGNATURE).await.unwrap_err();
    assert!(err.to_string().contains("not found"), "unexpected error: {}", err);
}

#[tokio::test]
async fn fetch_transaction_rpc_error_bails() {
    let server = MockServer::start();

    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "getTransaction"}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0", "id": 1,
            "error": {"code": -32601, "message": "method not found"}
        }));
    });

    let err = fetch_transaction_by_signature(&server.url("/"), TEST_SIGNATURE).await.unwrap_err();
    assert!(err.to_string().contains("method not found"), "unexpected error: {}", err);
}

#[tokio::test]
async fn fetch_transaction_malformed_result_bails() {
    let server = MockServer::start();

    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "getTransaction"}).to_string());
        then.status(200).json_body(json!({"jsonrpc": "2.0", "id": 1, "result": "not-an-array"}));
    });

    let err = fetch_transaction_by_signature(&server.url("/"), TEST_SIGNATURE).await.unwrap_err();
    assert!(err.to_string().contains("malformed"), "unexpected error: {}", err);
}

#[tokio::test]
async fn fetch_transaction_garbage_base64_bails() {
    let server = MockServer::start();

    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "getTransaction"}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0", "id": 1,
            "result": ["!!!not-base64!!!", ["some-signature"]]
        }));
    });

    let err = fetch_transaction_by_signature(&server.url("/"), TEST_SIGNATURE).await.unwrap_err();
    assert!(err.to_string().contains("base64"), "unexpected error: {}", err);
}

#[tokio::test]
async fn fetch_transaction_v0_static_keys_returns_raw_bytes() {
    let server = MockServer::start();
    let raw = build_v0_static_keys_tx();
    let encoded = base64_encode(&raw);

    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "getTransaction"}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0", "id": 1,
            "result": [encoded, ["some-signature"]]
        }));
    });

    let bytes = fetch_transaction_by_signature(&server.url("/"), TEST_SIGNATURE).await.unwrap();
    assert_eq!(bytes, raw);
}
