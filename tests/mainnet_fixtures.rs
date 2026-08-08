#[cfg(test)]
mod mainnet_fixture_tests {
    use base64::Engine;
    use rust_security_toolkit::decoder;
    use solana_client::rpc_client::RpcClient;
    use solana_client::rpc_config::RpcBlockConfig;
    use solana_sdk::pubkey::Pubkey;
    use solana_transaction_status_client_types::{EncodedTransaction, TransactionDetails, UiTransactionEncoding};
    use std::str::FromStr;

    const MAINNET_RPC: &str = "https://api.mainnet-beta.solana.com";
    const FIXTURE_DIR: &str = "tests/fixtures/mainnet";

    /// Fetch and save mainnet transaction fixtures.
    /// Requires network access. Run manually with:
    ///   cargo test --test mainnet_fixtures fetch_mainnet_fixtures -- --ignored
    #[test]
    #[ignore]
    fn fetch_mainnet_fixtures() {
        let rpc = RpcClient::new(MAINNET_RPC.to_string());

        std::fs::create_dir_all(FIXTURE_DIR).expect("Failed to create mainnet fixture directory");

        let latest_slot = match rpc.get_slot() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  RPC unavailable (get_slot): {}", e);
                eprintln!("  Skipping mainnet fixture fetch.");
                return;
            }
        };

        let mut saved = 0usize;

        // Fetch transactions from recent blocks. maxSupportedTransactionVersion
        // must be set: blocks containing v0 transactions fail without it.
        for offset in (10..=80).step_by(10) {
            let slot = latest_slot.saturating_sub(offset);
            let block = match rpc.get_block_with_config(
                slot,
                RpcBlockConfig {
                    encoding: Some(UiTransactionEncoding::Base64),
                    transaction_details: Some(TransactionDetails::Full),
                    max_supported_transaction_version: Some(0),
                    ..Default::default()
                },
            ) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("  get_block({}) failed: {}", slot, e);
                    continue;
                }
            };

            for tx_with_meta in block.transactions.unwrap_or_default() {
                if saved >= 30 {
                    break;
                }

                let raw_bytes = match extract_raw_bytes(&tx_with_meta.transaction) {
                    Some(bytes) => bytes,
                    None => continue,
                };

                let sig_short = hex::encode(&raw_bytes[..4]);
                let hex_str = hex::encode(&raw_bytes);
                let hex_path = format!("{}/tx_{:03}_{}.hex", FIXTURE_DIR, saved, sig_short);
                std::fs::write(&hex_path, hex_str).expect("Failed to write hex fixture");

                saved += 1;
            }
        }

        eprintln!("  Saved {} mainnet transactions to {}", saved, FIXTURE_DIR);
    }

    fn extract_raw_bytes(enc: &EncodedTransaction) -> Option<Vec<u8>> {
        match enc {
            EncodedTransaction::LegacyBinary(blob) => bs58::decode(blob).into_vec().ok(),
            EncodedTransaction::Binary(blob, encoding) => {
                use solana_transaction_status_client_types::TransactionBinaryEncoding;
                match encoding {
                    TransactionBinaryEncoding::Base58 => bs58::decode(blob).into_vec().ok(),
                    TransactionBinaryEncoding::Base64 => {
                        use base64::Engine;
                        base64::engine::general_purpose::STANDARD.decode(blob).ok()
                    }
                }
            }
            EncodedTransaction::Json(_) | EncodedTransaction::Accounts(_) => None,
        }
    }

    /// Decode every committed mainnet fixture and verify:
    ///  - all four supported encodings of the same transaction produce
    ///    identical reports (cross-encoding consistency)
    ///  - the report is fully populated (signatures, accounts, instructions)
    ///
    /// Skips gracefully when no fixtures are committed yet:
    ///   cargo test --test mainnet_fixtures fetch_mainnet_fixtures -- --ignored
    #[test]
    fn test_mainnet_fixtures_round_trip() {
        let mut paths: Vec<_> = match std::fs::read_dir(FIXTURE_DIR) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().map(|e| e == "hex").unwrap_or(false))
                .collect(),
            Err(_) => {
                eprintln!(
                    "No mainnet fixtures at {}. Run `cargo test --test mainnet_fixtures \
                     fetch_mainnet_fixtures -- --ignored` to fetch them.",
                    FIXTURE_DIR
                );
                return;
            }
        };
        paths.sort();

        for path in &paths {
            let hex_str = std::fs::read_to_string(path).expect("Failed to read fixture");
            let hex_str = hex_str.trim();
            let raw_bytes = hex::decode(hex_str).unwrap_or_else(|e| panic!("{}: invalid hex: {}", path.display(), e));

            let report_hex = decoder::decode_transaction(hex_str, None)
                .unwrap_or_else(|e| panic!("{}: hex decode failed: {}", path.display(), e));
            let report_json = serde_json::to_string(&report_hex).unwrap();

            // Re-encode the same bytes in the other supported encodings and
            // require byte-identical reports.
            let base64_str = base64::engine::general_purpose::STANDARD.encode(&raw_bytes);
            let report_base64 = decoder::decode_transaction(&base64_str, None)
                .unwrap_or_else(|e| panic!("{}: base64 decode failed: {}", path.display(), e));
            assert_eq!(
                report_json,
                serde_json::to_string(&report_base64).unwrap(),
                "{}: hex and base64 reports differ",
                path.display()
            );

            let base58_str = bs58::encode(&raw_bytes).into_string();
            let report_base58 = decoder::decode_transaction(&base58_str, None)
                .unwrap_or_else(|e| panic!("{}: base58 decode failed: {}", path.display(), e));
            assert_eq!(
                report_json,
                serde_json::to_string(&report_base58).unwrap(),
                "{}: hex and base58 reports differ",
                path.display()
            );

            // Raw binary input requires valid UTF-8; skip it otherwise.
            if let Ok(raw_str) = std::str::from_utf8(&raw_bytes) {
                let report_raw = decoder::decode_transaction(raw_str, None)
                    .unwrap_or_else(|e| panic!("{}: raw decode failed: {}", path.display(), e));
                assert_eq!(
                    report_json,
                    serde_json::to_string(&report_raw).unwrap(),
                    "{}: hex and raw reports differ",
                    path.display()
                );
            }

            // Structural invariants: every field must be fully populated.
            assert_eq!(report_hex.status, "DECODED SUCCESSFULLY", "{}", path.display());
            assert!(!report_hex.signatures.is_empty(), "{}: no signatures", path.display());
            assert!(!report_hex.accounts.is_empty(), "{}: no accounts", path.display());
            assert!(!report_hex.instructions.is_empty(), "{}: no instructions", path.display());

            for account in &report_hex.accounts {
                Pubkey::from_str(&account.pubkey)
                    .unwrap_or_else(|e| panic!("{}: invalid account pubkey {}: {}", path.display(), account.pubkey, e));
            }
            for ix in &report_hex.instructions {
                assert!(
                    report_hex.accounts.iter().any(|a| a.pubkey == ix.program_id),
                    "{}: program_id {} not in account list",
                    path.display(),
                    ix.program_id
                );
            }

            // The differential decode gate must also hold for real mainnet txs.
            let warnings = decoder::validate_decoding(&raw_bytes, &report_hex).expect("validate_decoding must succeed");
            assert!(warnings.is_empty(), "{}: validate-decoding warnings: {:?}", path.display(), warnings);
        }
    }
}
