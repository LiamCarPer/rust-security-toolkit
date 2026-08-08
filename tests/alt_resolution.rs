use httpmock::prelude::*;
use rust_security_toolkit::decoder;
use rust_security_toolkit::simulator;
use rust_security_toolkit::types::{RiskCategory, RiskSeverity};
use serde_json::json;
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    message::{AddressLookupTableAccount, VersionedMessage, v0},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use std::str::FromStr;

/// Build a v0 transaction that references one address from a lookup table.
/// Returns the serialized transaction and the table's address list.
fn build_v0_alt_tx() -> (Vec<u8>, Vec<Pubkey>) {
    let payer = Keypair::new();
    let recent_blockhash = Hash::new_from_array([9u8; 32]);
    let addresses = vec![Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique()];
    let alt = AddressLookupTableAccount { key: Pubkey::new_unique(), addresses: addresses.clone() };

    let to = Pubkey::new_unique();
    let mut data = vec![0u8; 12];
    data[0..4].copy_from_slice(&2u32.to_le_bytes());
    data[4..12].copy_from_slice(&1_000_000u64.to_le_bytes());
    let mut ix = Instruction {
        program_id: Pubkey::from_str("11111111111111111111111111111111").unwrap(),
        accounts: vec![AccountMeta::new(payer.pubkey(), true), AccountMeta::new_readonly(to, false)],
        data,
    };
    // Reference one of the table's addresses so try_compile keeps the table
    // (unused tables are dropped).
    ix.accounts.push(AccountMeta::new_readonly(addresses[1], false));

    let msg = v0::Message::try_compile(&payer.pubkey(), &[ix], &[alt], recent_blockhash).unwrap();
    let tx = VersionedTransaction {
        signatures: vec![payer.sign_message(&msg.serialize())],
        message: VersionedMessage::V0(msg),
    };
    (bincode::serialize(&tx).unwrap(), addresses)
}

/// Mock a successful `getAddressLookupTable` response returning `addresses`.
fn mock_table(server: &MockServer, addresses: &[Pubkey], table_key: &str) {
    let addr_strings: Vec<String> = addresses.iter().map(|p| p.to_string()).collect();
    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "getAddressLookupTable"}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "value": {
                "key": table_key,
                "data": { "addresses": addr_strings },
                "slot": 123
            }}
        }));
    });
}

/// Placeholders are used offline; `--rpc` resolution replaces them with the
/// real on-chain pubkeys.
#[tokio::test]
async fn test_alt_resolution_success() {
    let server = MockServer::start();
    let (raw, addresses) = build_v0_alt_tx();
    let mut report = decoder::decode_raw_bytes(&raw, None).expect("Decode v0 ALT tx");
    assert_eq!(report.address_lookup_tables.len(), 1);
    assert!(!report.address_lookup_tables[0].resolved, "offline decode must be unresolved");
    assert!(
        report.address_lookup_tables[0].resolved_accounts[0].pubkey.starts_with("<alt_index_"),
        "offline decode must use placeholders"
    );

    let table_key = report.address_lookup_tables[0].table_address.clone();
    mock_table(&server, &addresses, &table_key);

    let flags = simulator::resolve_address_lookup_tables(&server.url(""), &mut report).await;
    assert!(flags.is_empty(), "expected no flags, got: {:?}", flags);

    let alt = &report.address_lookup_tables[0];
    assert!(alt.resolved);
    assert_eq!(alt.resolved_accounts.len(), 1);
    assert_eq!(alt.resolved_accounts[0].pubkey, addresses[1].to_string());
    assert_eq!(alt.resolved_accounts[0].table_index, Some(1));
}

/// A table that no longer exists on chain produces a Warning — the transaction
/// would fail with an invalid lookup error at execution time.
#[tokio::test]
async fn test_alt_resolution_table_not_found() {
    let server = MockServer::start();
    let (raw, _addresses) = build_v0_alt_tx();
    let mut report = decoder::decode_raw_bytes(&raw, None).expect("Decode v0 ALT tx");
    let table_key = report.address_lookup_tables[0].table_address.clone();

    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "getAddressLookupTable"}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "value": null }
        }));
    });

    let flags = simulator::resolve_address_lookup_tables(&server.url(""), &mut report).await;
    assert_eq!(flags.len(), 1);
    assert_eq!(flags[0].category, RiskCategory::AltIntegrity);
    assert_eq!(flags[0].severity, RiskSeverity::Warning);
    assert!(flags[0].message.contains(&table_key), "unexpected message: {}", flags[0].message);
    assert!(!report.address_lookup_tables[0].resolved);
    assert!(report.address_lookup_tables[0].resolved_accounts[0].pubkey.starts_with("<alt_index_"));
}

/// RPC failures degrade to Info and keep the placeholders.
#[tokio::test]
async fn test_alt_resolution_rpc_error() {
    let server = MockServer::start();
    let (raw, _addresses) = build_v0_alt_tx();
    let mut report = decoder::decode_raw_bytes(&raw, None).expect("Decode v0 ALT tx");

    server.mock(|when, then| {
        when.method(POST).path("/").json_body_partial(json!({"method": "getAddressLookupTable"}).to_string());
        then.status(200).json_body(json!({
            "jsonrpc": "2.0", "id": 1,
            "error": { "code": -32000, "message": "Something went wrong" }
        }));
    });

    let flags = simulator::resolve_address_lookup_tables(&server.url(""), &mut report).await;
    assert_eq!(flags.len(), 1);
    assert_eq!(flags[0].severity, RiskSeverity::Info);
    assert!(flags[0].details.contains("Something went wrong"));
    assert!(!report.address_lookup_tables[0].resolved);
}

/// A table that is shorter than the index the transaction references is a
/// Warning: the table was modified between creation and execution.
#[tokio::test]
async fn test_alt_resolution_index_out_of_bounds() {
    let server = MockServer::start();
    let (raw, addresses) = build_v0_alt_tx();
    let mut report = decoder::decode_raw_bytes(&raw, None).expect("Decode v0 ALT tx");
    let table_key = report.address_lookup_tables[0].table_address.clone();

    // The tx references index 1; return a table with only one entry.
    mock_table(&server, &addresses[..1], &table_key);

    let flags = simulator::resolve_address_lookup_tables(&server.url(""), &mut report).await;
    assert_eq!(flags.len(), 1);
    assert_eq!(flags[0].category, RiskCategory::AltIntegrity);
    assert_eq!(flags[0].severity, RiskSeverity::Warning);
    assert!(flags[0].message.contains("index 1"), "unexpected message: {}", flags[0].message);
    assert!(report.address_lookup_tables[0].resolved);
    assert!(report.address_lookup_tables[0].resolved_accounts[0].pubkey.starts_with("<alt_index_"));
}

/// Transactions without address table lookups are skipped without RPC calls.
#[tokio::test]
async fn test_alt_resolution_no_lookups_skipped() {
    let server = MockServer::start();
    // No mocks — any RPC call would 404 and produce an Info flag.
    let from = Keypair::new();
    let to = Pubkey::new_unique();
    let recent_blockhash = Hash::new_from_array([7u8; 32]);
    let mut data = vec![0u8; 12];
    data[0..4].copy_from_slice(&2u32.to_le_bytes());
    data[4..12].copy_from_slice(&1_000_000u64.to_le_bytes());
    let ix = Instruction {
        program_id: Pubkey::from_str("11111111111111111111111111111111").unwrap(),
        accounts: vec![AccountMeta::new(from.pubkey(), true), AccountMeta::new_readonly(to, false)],
        data,
    };
    let message = VersionedMessage::Legacy(solana_sdk::message::legacy::Message::new_with_blockhash(
        &[ix],
        Some(&from.pubkey()),
        &recent_blockhash,
    ));
    let tx = VersionedTransaction { signatures: vec![from.sign_message(&message.serialize())], message };
    let raw = bincode::serialize(&tx).unwrap();
    let mut report = decoder::decode_raw_bytes(&raw, None).expect("Decode legacy tx");
    assert!(report.address_lookup_tables.is_empty());

    let flags = simulator::resolve_address_lookup_tables(&server.url(""), &mut report).await;
    assert!(flags.is_empty());
}
