use base64::Engine;
use proptest::prelude::*;
use rust_security_toolkit::anchor_decoder::decode_anchor_args;
use rust_security_toolkit::decoder;
use rust_security_toolkit::instruction_decoder::decode_instruction_data;
use rust_security_toolkit::types::IdlArg;
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
}
