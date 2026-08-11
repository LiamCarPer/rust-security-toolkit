use base64::Engine;
use proptest::prelude::*;
use rust_security_toolkit::anchor_decoder::decode_anchor_args;
use rust_security_toolkit::decoder;
use rust_security_toolkit::expectations_decoder::decode_instruction;
use rust_security_toolkit::expectations_decoder::match_expectation;
use rust_security_toolkit::instruction_decoder::decode_instruction_data;
use rust_security_toolkit::patterns::detect_patterns;
use rust_security_toolkit::patterns::detect_patterns_with_config;
use rust_security_toolkit::signature_verify::verify_report;
use rust_security_toolkit::signature_verify::verify_transaction;
use rust_security_toolkit::sim_crossref::cross_reference;
use rust_security_toolkit::types::ExpectationsDoc;
use rust_security_toolkit::types::FetchedTxMeta;
use rust_security_toolkit::types::IdlArg;
use rust_security_toolkit::types::PatternConfig;
use rust_security_toolkit::types::PatternRuleOverride;
use rust_security_toolkit::types::TransactionReport;
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

const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";

fn system_transfer_instruction(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = vec![0u8; 12];
    data[0..4].copy_from_slice(&2u32.to_le_bytes());
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap(),
        accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)],
        data,
    }
}

fn set_compute_unit_limit_instruction(limit: u32) -> Instruction {
    let mut data = vec![0u8; 5];
    data[0] = 1;
    data[1..5].copy_from_slice(&limit.to_le_bytes());
    Instruction { program_id: Pubkey::from_str(COMPUTE_BUDGET_PROGRAM_ID).unwrap(), accounts: vec![], data }
}

fn set_compute_unit_price_instruction(price: u64) -> Instruction {
    let mut data = vec![0u8; 9];
    data[0] = 3;
    data[1..9].copy_from_slice(&price.to_le_bytes());
    Instruction { program_id: Pubkey::from_str(COMPUTE_BUDGET_PROGRAM_ID).unwrap(), accounts: vec![], data }
}

/// Generate random serialized transactions: legacy or v0, optionally with an
/// address lookup table, with 1-6 mixed system/CU instructions.
fn tx_strategy() -> impl Strategy<Value = Vec<u8>> {
    (any::<bool>(), any::<bool>(), prop::collection::vec((any::<u8>(), any::<u64>()), 1..6)).prop_map(
        |(is_v0, with_alt, specs)| {
            let payer = Keypair::new();
            let to = Pubkey::new_unique();
            let recent_blockhash = Hash::new_from_array([7u8; 32]);

            let mut ixs: Vec<Instruction> = specs
                .iter()
                .map(|(kind, val)| match kind % 3 {
                    0 => system_transfer_instruction(&payer.pubkey(), &to, val % 1_000_000_000),
                    1 => set_compute_unit_limit_instruction((val % 1_000_000) as u32),
                    _ => set_compute_unit_price_instruction(val % 1_000_000),
                })
                .collect();

            let message = if is_v0 {
                let alt = if with_alt {
                    let alt = AddressLookupTableAccount {
                        key: Pubkey::new_unique(),
                        addresses: vec![Pubkey::new_unique(), Pubkey::new_unique()],
                    };
                    // Reference an ALT address so try_compile keeps the table.
                    ixs.last_mut()
                        .expect("at least one instruction")
                        .accounts
                        .push(AccountMeta::new_readonly(alt.addresses[0], false));
                    Some(alt)
                } else {
                    None
                };
                let alts: Vec<AddressLookupTableAccount> = alt.into_iter().collect();
                VersionedMessage::V0(v0::Message::try_compile(&payer.pubkey(), &ixs, &alts, recent_blockhash).unwrap())
            } else {
                VersionedMessage::Legacy(solana_sdk::message::legacy::Message::new_with_blockhash(
                    &ixs,
                    Some(&payer.pubkey()),
                    &recent_blockhash,
                ))
            };

            let tx = VersionedTransaction { signatures: vec![payer.sign_message(&message.serialize())], message };
            bincode::serialize(&tx).unwrap()
        },
    )
}

fn any_report() -> impl Strategy<Value = TransactionReport> {
    (
        any::<String>(),
        prop::collection::vec(any::<String>(), 0..8),
        prop::collection::vec(any::<String>(), 0..8),
        prop::collection::vec(any::<String>(), 0..8),
        any::<u64>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(fee_payer, program_ids, pubkeys, log_lines, cu, with_budget, with_sim, with_checks)| {
            let instructions: Vec<serde_json::Value> = program_ids
                .iter()
                .zip(pubkeys.iter())
                .enumerate()
                .map(|(i, (pid, name))| {
                    serde_json::json!({
                        "index": i,
                        "program_id": pid,
                        "program_name": name,
                        "instruction_name": name,
                        "accounts": [{
                            "name": "authority",
                            "pubkey": fee_payer,
                            "account_index": 0,
                            "is_signer": false,
                            "is_writable": true
                        }],
                        "data": null,
                        "raw_data_hex": "",
                        "token_amount": null
                    })
                })
                .collect();
            let compute_budget = with_budget.then(|| {
                serde_json::json!({
                    "compute_unit_limit": 200_000,
                    "compute_unit_price": 0,
                    "compute_unit_limit_set": true,
                    "compute_budget_positions": [0],
                    "is_reordered": false,
                    "high_cu_instructions": [],
                    "priority_fee_lamports": 0,
                    "priority_fee_actual": null
                })
            });
            let simulation = with_sim.then(|| {
                serde_json::json!({
                    "success": false,
                    "error": "Custom(1)",
                    "logs": log_lines,
                    "units_consumed": cu,
                    "return_data": null,
                    "error_code": "Custom(1)",
                    "error_instruction_index": null,
                    "instruction_cu": []
                })
            });
            let signature_verification = if with_checks {
                serde_json::json!([{
                    "index": 0,
                    "pubkey": fee_payer,
                    "verified": false,
                    "note": "missing signature"
                }])
            } else {
                serde_json::json!([])
            };
            serde_json::from_value::<TransactionReport>(serde_json::json!({
                "status": "DECODED SUCCESSFULLY",
                "fee_payer": fee_payer,
                "signatures": [],
                "recent_blockhash": "",
                "message_version": null,
                "accounts": [],
                "instructions": instructions,
                "address_lookup_tables": [],
                "compute_budget": compute_budget,
                "risk_flags": [],
                "simulation": simulation,
                "warnings": [],
                "signature_verification": signature_verification
            }))
            .expect("constructed report must deserialize")
        })
}

fn expectations_doc() -> ExpectationsDoc {
    let raw =
        std::fs::read_to_string("tests/fixtures/native_expectations.json").expect("expectations fixture must exist");
    serde_json::from_str(&raw).expect("expectations fixture must parse")
}

fn minimal_report() -> TransactionReport {
    serde_json::from_value(serde_json::json!({
        "status": "ok",
        "fee_payer": "",
        "signatures": [],
        "recent_blockhash": "",
        "message_version": null,
        "accounts": [],
        "instructions": [],
        "address_lookup_tables": [],
        "compute_budget": null,
        "risk_flags": [],
        "simulation": null,
        "warnings": []
    }))
    .expect("minimal report must deserialize")
}

proptest! {
    /// Arbitrary bytes must never panic the canonical decode paths.
    #[test]
    fn decode_raw_bytes_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = decoder::decode_raw_bytes(&bytes, None);
        let _ = decoder::decode_input(&bytes, None);
    }

    /// Arbitrary instruction data must never panic the named decoders.
    #[test]
    fn instruction_data_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = decode_instruction_data("11111111111111111111111111111111", &data, None);
        let _ = decode_instruction_data("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", &data, None);
        let _ = decode_instruction_data("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", &data, None);
    }

    /// Anchor argument decoding over arbitrary data must never panic.
    #[test]
    fn anchor_args_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let args = vec![
            IdlArg { name: "u8".into(), ty: serde_json::json!("u8") },
            IdlArg { name: "u64".into(), ty: serde_json::json!("u64") },
            IdlArg { name: "string".into(), ty: serde_json::json!("string") },
            IdlArg { name: "publicKey".into(), ty: serde_json::json!("publicKey") },
            IdlArg { name: "option".into(), ty: serde_json::json!({"option": "u64"}) },
            IdlArg { name: "vec".into(), ty: serde_json::json!({"vec": "u8"}) },
            IdlArg { name: "array".into(), ty: serde_json::json!({"array": ["u8", 8]}) },
            IdlArg { name: "defined".into(), ty: serde_json::json!({"defined": "Foo"}) },
        ];
        let _ = decode_anchor_args(&data, &args);
    }

    /// The differential decode gate holds for every generated transaction:
    /// the internal parser and solana-sdk must agree with zero warnings.
    #[test]
    fn differential_gate_random_valid_txs(tx_bytes in tx_strategy()) {
        let report = decoder::decode_raw_bytes(&tx_bytes, None).expect("generated tx must decode");
        let warnings = decoder::validate_decoding(&tx_bytes, &report).expect("validate_decoding must succeed");
        prop_assert!(warnings.is_empty(), "unexpected warnings: {:?}", warnings);
    }

    /// Every supported encoding of a generated transaction must decode to an
    /// identical report.
    #[test]
    fn encoding_roundtrip_random_valid_txs(tx_bytes in tx_strategy()) {
        let report = decoder::decode_raw_bytes(&tx_bytes, None).expect("generated tx must decode");
        let canonical = serde_json::to_string(&report).unwrap();

        let b64 = base64::engine::general_purpose::STANDARD.encode(&tx_bytes);
        let r = decoder::decode_transaction(&b64, None).expect("base64 decode");
        prop_assert_eq!(&canonical, &serde_json::to_string(&r).unwrap());

        let b58 = bs58::encode(&tx_bytes).into_string();
        let r = decoder::decode_transaction(&b58, None).expect("base58 decode");
        prop_assert_eq!(&canonical, &serde_json::to_string(&r).unwrap());

        let h = hex::encode(&tx_bytes);
        let r = decoder::decode_transaction(&h, None).expect("hex decode");
        prop_assert_eq!(&canonical, &serde_json::to_string(&r).unwrap());

        let (raw, r) = decoder::decode_input(&tx_bytes, None).expect("raw decode");
        prop_assert_eq!(raw, tx_bytes);
        prop_assert_eq!(canonical, serde_json::to_string(&r).unwrap());
    }

    #[test]
    fn no_panic_patterns_any_report(report in any_report()) {
        let _ = detect_patterns(&report);
    }

    #[test]
    fn no_panic_cross_reference_any_report(report in any_report()) {
        let mut report = report;
        let _ = cross_reference(&mut report);
    }

    #[test]
    fn no_panic_expectations_matching(
        program_id in any::<String>(),
        data in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let doc = expectations_doc();
        let _ = match_expectation(&program_id, &data, &doc);
        let _ = decode_instruction(&program_id, &data, &doc);
        let _ = doc.find_instruction(&program_id);
    }

    #[test]
    fn no_panic_signature_verify_any_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..2048),
        report in any_report(),
    ) {
        if let Ok(tx) = bincode::deserialize::<VersionedTransaction>(&bytes) {
            let _ = verify_transaction(&tx);
        }
        let mut report = report;
        let _ = verify_report(&mut report);
    }

    #[test]
    fn patterns_config_roundtrip_no_panic(
        report in any_report(),
        config_json in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        if let Ok(config) = serde_json::from_slice::<PatternConfig>(&config_json) {
            let _ = detect_patterns_with_config(&report, &config);
        }
        let config = PatternConfig {
            rules: [
                (
                    "approve_then_transfer".to_string(),
                    PatternRuleOverride { enabled: Some(false), severity: Some("critical".to_string()) },
                ),
                (
                    "nonsigner_transfer_authority".to_string(),
                    PatternRuleOverride { enabled: Some(true), severity: Some("bogus".to_string()) },
                ),
                (
                    "unknown_rule".to_string(),
                    PatternRuleOverride { enabled: None, severity: Some("info".to_string()) },
                ),
            ]
            .into_iter()
            .collect(),
        };
        let round_tripped: PatternConfig =
            serde_json::from_value(serde_json::to_value(&config).expect("config serializes"))
                .expect("config round-trips");
        let _ = detect_patterns_with_config(&report, &round_tripped);
    }

    /// Arbitrary getTransaction meta must never panic the balance annotator.
    #[test]
    fn no_panic_balance_annotation_any_meta(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && let Ok(meta) = serde_json::from_value::<FetchedTxMeta>(value)
        {
            let mut report = minimal_report();
            let _ = rust_security_toolkit::balance_changes::annotate_report(&mut report, meta);
        }
    }
}
