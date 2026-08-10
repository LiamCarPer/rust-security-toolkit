use base64::Engine;
use httpmock::prelude::*;
use rust_security_toolkit::simulator::{
    fetch_transaction_by_signature, fetch_transaction_with_meta, resolve_token_amounts,
};
use rust_security_toolkit::types::*;
use serde_json::json;
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    message::{VersionedMessage, legacy},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use solana_system_interface::instruction::SystemInstruction;
use std::str::FromStr;

const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TEST_SIGNATURE: &str = "5K1kQw7z2YdF2xK5Tt8JmNqRwVpYc4c7QhWbXzDmFgHsJkL";

fn base64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn build_legacy_tx() -> Vec<u8> {
    let payer = Keypair::new();
    let recipient = Pubkey::new_unique();
    let recent_blockhash = Hash::new_from_array([7u8; 32]);

    let ix = Instruction {
        program_id: Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap(),
        accounts: vec![AccountMeta::new(payer.pubkey(), true), AccountMeta::new_readonly(recipient, false)],
        data: bincode::serialize(&SystemInstruction::Transfer { lamports: 1_000_000 }).unwrap(),
    };

    let message =
        VersionedMessage::Legacy(legacy::Message::new_with_blockhash(&[ix], Some(&payer.pubkey()), &recent_blockhash));
    let tx = VersionedTransaction { signatures: vec![payer.sign_message(&message.serialize())], message };
    bincode::serialize(&tx).unwrap()
}

#[tokio::test]
async fn fetch_with_full_meta_returns_bytes_and_meta() {
    let server = MockServer::start();
    let raw = build_legacy_tx();
    let encoded = base64_encode(&raw);

    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "getTransaction"}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0", "id": 1,
            "result": {
                "slot": 123,
                "blockTime": 1786307874,
                "version": "legacy",
                "transaction": [encoded, "base64"],
                "meta": {
                    "err": null,
                    "fee": 5000,
                    "innerInstructions": [{
                        "index": 0,
                        "instructions": [{
                            "programIdIndex": 2,
                            "accounts": [1],
                            "data": "base58data"
                        }]
                    }],
                    "loadedAddresses": {"readonly": ["r1"], "writable": ["w1"]},
                    "logMessages": [],
                    "preBalances": [],
                    "postBalances": [],
                    "unitsConsumed": 1234
                }
            }
        }));
    });

    let (bytes, meta) = fetch_transaction_with_meta(&server.url("/"), TEST_SIGNATURE).await.unwrap();
    assert_eq!(bytes, raw);
    let meta = meta.expect("meta should be Some");
    assert_eq!(meta.inner_instructions.len(), 1);
    let group = &meta.inner_instructions[0];
    assert_eq!(group.index, 0);
    assert_eq!(group.instructions.len(), 1);
    let inner = &group.instructions[0];
    assert_eq!(inner.program_id_index, 2);
    assert_eq!(inner.accounts, vec![1]);
    assert_eq!(inner.data, "base58data");
    let loaded = meta.loaded_addresses.expect("loaded addresses should be parsed");
    assert_eq!(loaded.writable, vec!["w1".to_string()]);
    assert_eq!(loaded.readonly, vec!["r1".to_string()]);
    assert_eq!(meta.units_consumed, Some(1234));
}

#[tokio::test]
async fn fetch_without_meta_returns_none() {
    let server = MockServer::start();
    let raw = build_legacy_tx();
    let encoded = base64_encode(&raw);

    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "getTransaction"}).to_string());
        then.status(200).json_body(json!({"jsonrpc": "2.0", "id": 1, "result": [encoded]}));
    });

    let (bytes, meta) = fetch_transaction_with_meta(&server.url("/"), TEST_SIGNATURE).await.unwrap();
    assert_eq!(bytes, raw);
    assert!(meta.is_none());
}

#[tokio::test]
async fn fetch_with_malformed_meta_returns_none() {
    let server = MockServer::start();
    let raw = build_legacy_tx();
    let encoded = base64_encode(&raw);

    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "getTransaction"}).to_string());
        then.status(200).json_body(json!({"jsonrpc": "2.0", "id": 1, "result": [encoded, "not-a-meta-object"]}));
    });

    let (bytes, meta) = fetch_transaction_with_meta(&server.url("/"), TEST_SIGNATURE).await.unwrap();
    assert_eq!(bytes, raw);
    assert!(meta.is_none());
}

#[tokio::test]
async fn fetch_not_found_still_bails() {
    let server = MockServer::start();

    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "getTransaction"}).to_string());
        then.status(200).json_body(json!({"jsonrpc": "2.0", "id": 1, "result": null}));
    });

    let err = fetch_transaction_with_meta(&server.url("/"), TEST_SIGNATURE).await.unwrap_err();
    assert!(err.to_string().contains("not found"), "unexpected error: {}", err);
}

#[tokio::test]
async fn fetch_rpc_error_bails() {
    let server = MockServer::start();

    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "getTransaction"}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0", "id": 1,
            "error": {"code": -32601, "message": "method not found"}
        }));
    });

    let err = fetch_transaction_with_meta(&server.url("/"), TEST_SIGNATURE).await.unwrap_err();
    assert!(err.to_string().contains("method not found"), "unexpected error: {}", err);
}

#[tokio::test]
async fn resolve_token_amounts_resolves_inner_checked() {
    let mut report = TransactionReport {
        status: "OK".into(),
        fee_payer: SYSTEM_PROGRAM_ID.into(),
        signatures: vec![],
        recent_blockhash: "11111111111111111111111111111111".into(),
        message_version: None,
        accounts: vec![],
        instructions: vec![],
        address_lookup_tables: vec![],
        compute_budget: None,
        risk_flags: vec![],
        simulation: None,
        warnings: vec![],
        signature_verification: vec![],
        inner_instructions: vec![InnerInstruction {
            inner_index: 0,
            parent_instruction_index: 0,
            program_id: TOKEN_PROGRAM_ID.into(),
            program_name: "SPL Token".into(),
            instruction_name: Some("TransferChecked".into()),
            accounts: vec![],
            data: json!({"amount": 1_500_000u64, "decimals": 6u64}),
            raw_data_hex: String::new(),
            token_amount: None,
        }],
    };

    resolve_token_amounts(None, &mut report).await;

    let token_amount = report.inner_instructions[0].token_amount.as_ref().expect("token_amount should be resolved");
    assert_eq!(token_amount.raw, 1_500_000);
    assert_eq!(token_amount.decimals, 6);
    assert_eq!(token_amount.human, "1.5");
}

#[tokio::test]
async fn fetch_by_signature_wrapper_still_works() {
    let server = MockServer::start();
    let raw = build_legacy_tx();
    let encoded = base64_encode(&raw);

    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "getTransaction"}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0", "id": 1,
            "result": [encoded, {"innerInstructions": [], "loadedAddresses": {"readonly": [], "writable": []}}]
        }));
    });

    let bytes = fetch_transaction_by_signature(&server.url("/"), TEST_SIGNATURE).await.unwrap();
    assert_eq!(bytes, raw);
}
