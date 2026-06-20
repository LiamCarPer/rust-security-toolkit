#[cfg(test)]
mod mainnet_fixture_tests {
    use solana_client::rpc_client::RpcClient;
    use solana_transaction_status_client_types::EncodedTransaction;

    const MAINNET_RPC: &str = "https://api.mainnet-beta.solana.com";

    /// Fetch and save mainnet transaction fixtures.
    /// Requires network access. Run manually with:
    ///   cargo test fetch_mainnet_fixtures -- --ignored
    #[test]
    #[ignore]
    fn fetch_mainnet_fixtures() {
        let rpc = RpcClient::new(MAINNET_RPC.to_string());

        let fixture_dir = "tests/fixtures/mainnet";
        std::fs::create_dir_all(fixture_dir).expect("Failed to create mainnet fixture directory");

        let latest_slot = match rpc.get_slot() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  RPC unavailable (get_slot): {}", e);
                eprintln!("  Skipping mainnet fixture fetch.");
                return;
            }
        };

        let mut saved = 0usize;

        // Fetch transactions from recent blocks
        for offset in (10..=80).step_by(10) {
            let slot = latest_slot.saturating_sub(offset);
            let block = match rpc.get_block(slot) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let txs = block.transactions;

            for tx_with_meta in txs {
                if saved >= 30 {
                    break;
                }

                let raw_bytes = extract_raw_bytes(&tx_with_meta.transaction);
                let raw_bytes = match raw_bytes {
                    Some(bytes) => bytes,
                    None => continue,
                };

                let sig_short = hex::encode(&raw_bytes[..4]);
                let hex_str = hex::encode(&raw_bytes);

                let hex_path = format!("{}/tx_{:03}_{}.hex", fixture_dir, saved, sig_short);
                std::fs::write(&hex_path, hex_str).expect("Failed to write hex fixture");

                let b58_str = bs58::encode(&raw_bytes).into_string();
                let b58_path = format!("{}/tx_{:03}_{}.base58", fixture_dir, saved, sig_short);
                std::fs::write(&b58_path, b58_str).expect("Failed to write base58 fixture");

                use base64::Engine;
                let b64_str = base64::engine::general_purpose::STANDARD.encode(&raw_bytes);
                let b64_path = format!("{}/tx_{:03}_{}.base64", fixture_dir, saved, sig_short);
                std::fs::write(&b64_path, b64_str).expect("Failed to write base64 fixture");

                let bin_path = format!("{}/tx_{:03}_{}.bin", fixture_dir, saved, sig_short);
                std::fs::write(&bin_path, &raw_bytes).expect("Failed to write binary fixture");

                saved += 1;
            }
        }

        eprintln!("  Saved {} mainnet transactions to {}", saved, fixture_dir);
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
}
