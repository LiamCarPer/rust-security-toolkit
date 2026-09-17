use std::str::FromStr;

use anyhow::{Context, Result, bail};
use solana_sdk::hash::Hash;
use solana_sdk::message::compiled_instruction::CompiledInstruction;
use solana_sdk::message::{
    MessageHeader, VersionedMessage, legacy,
    v0::{self, MessageAddressTableLookup},
};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature};
use solana_sdk::signer::Signer;
use solana_sdk::transaction::VersionedTransaction;

use crate::types::{SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID};

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PocTemplate {
    pub schema_version: String,
    pub message_version: Option<u8>,
    pub required_signatures: u8,
    pub readonly_signed: u8,
    pub readonly_unsigned: u8,
    pub account_keys: Vec<String>,
    pub recent_blockhash: String,
    pub instructions: Vec<PocInstruction>,
    #[serde(default)]
    pub address_table_lookups: Vec<PocAltLookup>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PocInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data_hex: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PocAltLookup {
    pub account_key: String,
    pub writable_indexes: Vec<u8>,
    pub readonly_indexes: Vec<u8>,
}

pub fn from_transaction(tx: &VersionedTransaction) -> PocTemplate {
    let message = &tx.message;
    let header = message.header();
    let account_keys = message.static_account_keys().iter().map(ToString::to_string).collect();
    let instructions = message
        .instructions()
        .iter()
        .map(|ix| PocInstruction {
            program_id_index: ix.program_id_index,
            accounts: ix.accounts.clone(),
            data_hex: hex::encode(&ix.data),
        })
        .collect();
    let address_table_lookups = message
        .address_table_lookups()
        .map(|lookups| {
            lookups
                .iter()
                .map(|lookup| PocAltLookup {
                    account_key: lookup.account_key.to_string(),
                    writable_indexes: lookup.writable_indexes.clone(),
                    readonly_indexes: lookup.readonly_indexes.clone(),
                })
                .collect()
        })
        .unwrap_or_default();
    let message_version = match message {
        VersionedMessage::Legacy(_) => None,
        VersionedMessage::V0(_) => Some(0),
        VersionedMessage::V1(_) => Some(1),
    };
    PocTemplate {
        schema_version: "1.0".to_string(),
        message_version,
        required_signatures: header.num_required_signatures,
        readonly_signed: header.num_readonly_signed_accounts,
        readonly_unsigned: header.num_readonly_unsigned_accounts,
        account_keys,
        recent_blockhash: message.recent_blockhash().to_string(),
        instructions,
        address_table_lookups,
    }
}

pub fn to_transaction(template: &PocTemplate) -> Result<VersionedTransaction> {
    let account_keys = template
        .account_keys
        .iter()
        .enumerate()
        .map(|(index, key)| Pubkey::from_str(key).with_context(|| format!("invalid account_keys[{index}] {key:?}")))
        .collect::<Result<Vec<Pubkey>>>()?;
    if template.required_signatures as usize > account_keys.len() {
        bail!(
            "required_signatures {} exceeds account_keys length {}",
            template.required_signatures,
            account_keys.len()
        );
    }
    let recent_blockhash = Hash::from_str(&template.recent_blockhash).context("invalid recent_blockhash")?;
    let instructions = template
        .instructions
        .iter()
        .enumerate()
        .map(|(index, ix)| {
            let data = hex::decode(&ix.data_hex).with_context(|| format!("invalid data_hex at instruction {index}"))?;
            Ok(CompiledInstruction { program_id_index: ix.program_id_index, accounts: ix.accounts.clone(), data })
        })
        .collect::<Result<Vec<CompiledInstruction>>>()?;
    let header = MessageHeader {
        num_required_signatures: template.required_signatures,
        num_readonly_signed_accounts: template.readonly_signed,
        num_readonly_unsigned_accounts: template.readonly_unsigned,
    };
    let message = match template.message_version {
        None => VersionedMessage::Legacy(legacy::Message { header, account_keys, recent_blockhash, instructions }),
        Some(0) => {
            let address_table_lookups = template
                .address_table_lookups
                .iter()
                .enumerate()
                .map(|(index, lookup)| {
                    if lookup.writable_indexes.len() > u8::MAX as usize
                        || lookup.readonly_indexes.len() > u8::MAX as usize
                    {
                        bail!(
                            "address_table_lookups[{index}] has more indexes than fit a u8 array \
                             (writable {}, readonly {})",
                            lookup.writable_indexes.len(),
                            lookup.readonly_indexes.len()
                        );
                    }
                    let account_key = Pubkey::from_str(&lookup.account_key)
                        .with_context(|| format!("invalid lookup account_key {lookup:?}"))?;
                    Ok(MessageAddressTableLookup {
                        account_key,
                        writable_indexes: lookup.writable_indexes.clone(),
                        readonly_indexes: lookup.readonly_indexes.clone(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            VersionedMessage::V0(v0::Message {
                header,
                account_keys,
                recent_blockhash,
                instructions,
                address_table_lookups,
            })
        }
        Some(other) => bail!("unsupported message_version {other}"),
    };
    let signatures = vec![Signature::default(); template.required_signatures as usize];
    Ok(VersionedTransaction { signatures, message })
}

pub fn to_base64(template: &PocTemplate) -> Result<String> {
    use base64::Engine;
    let tx = to_transaction(template)?;
    let bytes = bincode::serialize(&tx).context("failed to serialize rebuilt transaction")?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

impl PocTemplate {
    pub fn set_account_key(&mut self, index: usize, pubkey_b58: &str) -> Result<()> {
        if index >= self.account_keys.len() {
            bail!("account key index {index} out of range (len {})", self.account_keys.len());
        }
        let parsed = Pubkey::from_str(pubkey_b58).context("invalid pubkey")?;
        self.account_keys[index] = parsed.to_string();
        Ok(())
    }

    pub fn set_instruction_data(&mut self, ix_index: usize, data_hex: &str) -> Result<()> {
        if ix_index >= self.instructions.len() {
            bail!("instruction index {ix_index} out of range (len {})", self.instructions.len());
        }
        let bytes = hex::decode(data_hex).context("invalid instruction data hex")?;
        self.instructions[ix_index].data_hex = hex::encode(bytes);
        Ok(())
    }

    pub fn swap_instruction_accounts(&mut self, ix_index: usize, a: usize, b: usize) -> Result<()> {
        if ix_index >= self.instructions.len() {
            bail!("instruction index {ix_index} out of range (len {})", self.instructions.len());
        }
        let accounts = &mut self.instructions[ix_index].accounts;
        if a >= accounts.len() || b >= accounts.len() {
            bail!("account slot out of range (len {}, a {a}, b {b})", accounts.len());
        }
        accounts.swap(a, b);
        Ok(())
    }

    pub fn set_instruction_amount(&mut self, ix_index: usize, amount: u64) -> Result<()> {
        if ix_index >= self.instructions.len() {
            bail!("instruction index {ix_index} out of range (len {})", self.instructions.len());
        }
        let program_id_index = self.instructions[ix_index].program_id_index as usize;
        let program =
            self.account_keys.get(program_id_index).context("instruction program_id_index out of range")?.clone();
        let mut data = hex::decode(&self.instructions[ix_index].data_hex).context("invalid instruction data hex")?;
        let is_system = program == SYSTEM_PROGRAM_ID;
        let is_token = program == TOKEN_PROGRAM_ID || program == TOKEN_2022_PROGRAM_ID;
        let system_transfer =
            is_system && data.len() >= 12 && u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == 2;
        let token_transfer = is_token && data.len() >= 9 && matches!(data[0], 3 | 12);
        if system_transfer {
            data[4..12].copy_from_slice(&amount.to_le_bytes());
        } else if token_transfer {
            data[1..9].copy_from_slice(&amount.to_le_bytes());
        } else {
            bail!(
                "unsupported amount layout: program {program}, discriminator {}, data length {}; \
                 supported layouts are System Transfer (u32 2 + u64 lamports) and SPL Token Transfer/TransferChecked",
                data.first().copied().unwrap_or_default(),
                data.len()
            );
        }
        self.instructions[ix_index].data_hex = hex::encode(data);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PocEffects {
    pub success: bool,
    pub error_code: Option<String>,
    pub error_instruction_index: Option<u8>,
    pub units_consumed: u64,
    pub instruction_count: usize,
    pub risk_flag_summaries: Vec<String>,
}

pub fn effects(report: &crate::types::TransactionReport) -> PocEffects {
    let (success, error_code, error_instruction_index, units_consumed) = match &report.simulation {
        Some(sim) => (sim.success, sim.error_code.clone(), sim.error_instruction_index, sim.units_consumed),
        None => (false, None, None, 0),
    };
    let risk_flag_summaries =
        report.risk_flags.iter().map(|flag| format!("{:?}: {}", flag.category, flag.message)).collect();
    PocEffects {
        success,
        error_code,
        error_instruction_index,
        units_consumed,
        instruction_count: report.instructions.len(),
        risk_flag_summaries,
    }
}

pub fn diff_effects(baseline: &PocEffects, mutated: &PocEffects) -> Vec<String> {
    let mut changes = Vec::new();
    if baseline.success != mutated.success {
        match (&baseline.error_code, &mutated.error_code) {
            (None, Some(code)) => changes.push(format!(
                "outcome: success -> failure ({}{})",
                code,
                mutated.error_instruction_index.map(|i| format!(" at instruction #{}", i)).unwrap_or_default()
            )),
            (Some(code), None) => changes.push(format!("outcome: failure ({}) -> success", code)),
            (Some(a), Some(b)) => changes.push(format!("outcome: failure ({}) -> failure ({})", a, b)),
            (None, None) => changes.push("outcome changed".to_string()),
        }
    } else if baseline.error_code != mutated.error_code {
        changes.push(format!("error code: {:?} -> {:?}", baseline.error_code, mutated.error_code));
    }
    if baseline.units_consumed != mutated.units_consumed {
        let delta = mutated.units_consumed as i128 - baseline.units_consumed as i128;
        changes.push(format!("CU consumed: {} -> {} ({:+})", baseline.units_consumed, mutated.units_consumed, delta));
    }
    if baseline.instruction_count != mutated.instruction_count {
        changes.push(format!("instruction count: {} -> {}", baseline.instruction_count, mutated.instruction_count));
    }
    for summary in &mutated.risk_flag_summaries {
        if !baseline.risk_flag_summaries.contains(summary) {
            changes.push(format!("+ flag {}", summary));
        }
    }
    for summary in &baseline.risk_flag_summaries {
        if !mutated.risk_flag_summaries.contains(summary) {
            changes.push(format!("- flag {}", summary));
        }
    }
    changes
}

pub fn sign_with_keypairs(tx: &mut VersionedTransaction, keypairs: &[Keypair]) -> usize {
    let required = tx.message.header().num_required_signatures as usize;
    let keys = tx.message.static_account_keys();
    let message_bytes = tx.message.serialize();
    let mut signed = 0usize;
    for (index, key) in keys.iter().enumerate().take(required) {
        if let Some(keypair) = keypairs.iter().find(|kp| kp.pubkey() == *key) {
            tx.signatures[index] = keypair.sign_message(&message_bytes);
            signed += 1;
        }
    }
    signed
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use solana_sdk::instruction::{AccountMeta, Instruction};
    use solana_sdk::message::AddressLookupTableAccount;
    use solana_sdk::signature::Keypair;
    use solana_sdk::signer::Signer;

    use super::*;

    fn blockhash() -> Hash {
        Hash::new_from_array([7u8; 32])
    }

    fn system_transfer(from: Pubkey, to: Pubkey, lamports: u64) -> Instruction {
        let mut data = 2u32.to_le_bytes().to_vec();
        data.extend_from_slice(&lamports.to_le_bytes());
        Instruction {
            program_id: Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap(),
            accounts: vec![AccountMeta::new(from, true), AccountMeta::new(to, false)],
            data,
        }
    }

    fn token_transfer(program_id: &str, discriminator: u8) -> Instruction {
        let mut data = vec![discriminator];
        data.extend_from_slice(&5u64.to_le_bytes());
        if discriminator == 12 {
            data.push(6);
        }
        Instruction {
            program_id: Pubkey::from_str(program_id).unwrap(),
            accounts: vec![AccountMeta::new(Pubkey::new_unique(), false)],
            data,
        }
    }

    fn legacy_tx(instructions: &[Instruction], signers: &[&Keypair]) -> VersionedTransaction {
        let message = legacy::Message::new_with_blockhash(instructions, Some(&signers[0].pubkey()), &blockhash());
        let message_bytes = message.serialize();
        let required = message.header.num_required_signatures as usize;
        let mut signatures = Vec::with_capacity(required);
        for key in message.account_keys.iter().take(required) {
            let signer =
                signers.iter().find(|signer| signer.pubkey() == *key).expect("missing signer for required key");
            signatures.push(signer.sign_message(&message_bytes));
        }
        VersionedTransaction { signatures, message: VersionedMessage::Legacy(message) }
    }

    #[test]
    fn legacy_round_trip_is_byte_identical() {
        let payer = Keypair::new();
        let first_recipient = Pubkey::new_unique();
        let second_recipient = Pubkey::new_unique();
        let instructions = vec![
            system_transfer(payer.pubkey(), first_recipient, 1_000),
            system_transfer(payer.pubkey(), second_recipient, 2_000),
        ];
        let original = legacy_tx(&instructions, &[&payer]);
        assert_eq!(original.signatures.len(), 1);
        let original_bytes = bincode::serialize(&original).unwrap();
        let template = from_transaction(&original);
        assert_eq!(template.message_version, None);
        let rebuilt = to_transaction(&template).unwrap();
        assert_eq!(rebuilt.signatures.len(), original.signatures.len());
        assert_eq!(bincode::serialize(&original.message).unwrap(), bincode::serialize(&rebuilt.message).unwrap());
        let mut rebuilt_with_signatures = rebuilt.clone();
        rebuilt_with_signatures.signatures = original.signatures.clone();
        assert_eq!(bincode::serialize(&rebuilt_with_signatures).unwrap(), original_bytes);
    }

    #[test]
    fn v0_with_alt_round_trip() {
        let payer = Keypair::new();
        let loaded_readonly = Pubkey::new_unique();
        let loaded_writable = Pubkey::new_unique();
        let table_key = Pubkey::new_unique();
        let instruction = Instruction {
            program_id: Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap(),
            accounts: vec![AccountMeta::new_readonly(loaded_readonly, false), AccountMeta::new(loaded_writable, false)],
            data: vec![2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        };
        let table = AddressLookupTableAccount { key: table_key, addresses: vec![loaded_readonly, loaded_writable] };
        let message = v0::Message::try_compile(&payer.pubkey(), &[instruction], &[table], blockhash()).unwrap();
        assert_eq!(message.address_table_lookups.len(), 1);
        let original =
            VersionedTransaction { signatures: vec![Signature::default()], message: VersionedMessage::V0(message) };
        let template = from_transaction(&original);
        assert_eq!(template.message_version, Some(0));
        assert_eq!(template.address_table_lookups.len(), 1);
        assert_eq!(template.address_table_lookups[0].account_key, table_key.to_string());
        let rebuilt = to_transaction(&template).unwrap();
        assert_eq!(bincode::serialize(&original.message).unwrap(), bincode::serialize(&rebuilt.message).unwrap());
        assert_eq!(bincode::serialize(&original).unwrap(), bincode::serialize(&rebuilt).unwrap());
    }

    #[test]
    fn set_account_key_reflected() {
        let payer = Keypair::new();
        let original = legacy_tx(&[system_transfer(payer.pubkey(), Pubkey::new_unique(), 1)], &[&payer]);
        let mut template = from_transaction(&original);
        let replacement = Pubkey::new_unique();
        template.set_account_key(1, &replacement.to_string()).unwrap();
        assert_eq!(template.account_keys[1], replacement.to_string());
        let rebuilt = to_transaction(&template).unwrap();
        assert!(rebuilt.message.static_account_keys().contains(&replacement));
    }

    #[test]
    fn set_instruction_data_reflected() {
        let payer = Keypair::new();
        let original = legacy_tx(&[system_transfer(payer.pubkey(), Pubkey::new_unique(), 1)], &[&payer]);
        let mut template = from_transaction(&original);
        template.set_instruction_data(0, "aabbcc").unwrap();
        assert_eq!(template.instructions[0].data_hex, "aabbcc");
        let rebuilt = to_transaction(&template).unwrap();
        assert_eq!(rebuilt.message.instructions()[0].data, vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn set_amount_system_transfer() {
        let payer = Keypair::new();
        let original = legacy_tx(&[system_transfer(payer.pubkey(), Pubkey::new_unique(), 1)], &[&payer]);
        let mut template = from_transaction(&original);
        template.set_instruction_amount(0, 1_000_000).unwrap();
        let rebuilt = to_transaction(&template).unwrap();
        let data = &rebuilt.message.instructions()[0].data;
        assert_eq!(u64::from_le_bytes(data[4..12].try_into().unwrap()), 1_000_000);
    }

    #[test]
    fn set_amount_token_transfer() {
        let payer = Keypair::new();
        let original = legacy_tx(&[token_transfer(TOKEN_PROGRAM_ID, 3)], &[&payer]);
        let mut template = from_transaction(&original);
        template.set_instruction_amount(0, 777).unwrap();
        let rebuilt = to_transaction(&template).unwrap();
        let data = &rebuilt.message.instructions()[0].data;
        assert_eq!(u64::from_le_bytes(data[1..9].try_into().unwrap()), 777);
    }

    #[test]
    fn set_amount_token_2022_transfer_checked() {
        let payer = Keypair::new();
        let original = legacy_tx(&[token_transfer(TOKEN_2022_PROGRAM_ID, 12)], &[&payer]);
        let mut template = from_transaction(&original);
        template.set_instruction_amount(0, 4_200).unwrap();
        let rebuilt = to_transaction(&template).unwrap();
        let data = &rebuilt.message.instructions()[0].data;
        assert_eq!(data[0], 12);
        assert_eq!(u64::from_le_bytes(data[1..9].try_into().unwrap()), 4_200);
    }

    #[test]
    fn set_amount_rejects_unknown() {
        let payer = Keypair::new();
        let instruction = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![AccountMeta::new(Pubkey::new_unique(), false)],
            data: vec![9, 9, 9],
        };
        let original = legacy_tx(&[instruction], &[&payer]);
        let mut template = from_transaction(&original);
        let error = template.set_instruction_amount(0, 1).unwrap_err();
        assert!(error.to_string().contains("unsupported amount layout"));
    }

    #[test]
    fn dummy_signatures_sized_to_required() {
        let payer = Keypair::new();
        let second = Keypair::new();
        let instruction = Instruction {
            program_id: Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap(),
            accounts: vec![AccountMeta::new(payer.pubkey(), true), AccountMeta::new(second.pubkey(), true)],
            data: vec![2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        };
        let original = legacy_tx(&[instruction], &[&payer, &second]);
        assert_eq!(original.signatures.len(), 2);
        let template = from_transaction(&original);
        assert_eq!(template.required_signatures, 2);
        let rebuilt = to_transaction(&template).unwrap();
        assert_eq!(rebuilt.signatures.len(), 2);
        assert!(rebuilt.signatures.iter().all(|signature| *signature == Signature::default()));
    }

    #[test]
    fn json_round_trip() {
        let payer = Keypair::new();
        let original = legacy_tx(&[system_transfer(payer.pubkey(), Pubkey::new_unique(), 1)], &[&payer]);
        let template = from_transaction(&original);
        let json = serde_json::to_string(&template).unwrap();
        let parsed: PocTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(template, parsed);
        assert_eq!(
            bincode::serialize(&to_transaction(&template).unwrap().message).unwrap(),
            bincode::serialize(&to_transaction(&parsed).unwrap().message).unwrap()
        );
    }

    #[test]
    fn invalid_pubkey_error() {
        let payer = Keypair::new();
        let original = legacy_tx(&[system_transfer(payer.pubkey(), Pubkey::new_unique(), 1)], &[&payer]);
        let mut template = from_transaction(&original);
        assert!(template.set_account_key(0, "not-a-pubkey").is_err());
        template.account_keys[0] = "not-a-pubkey".to_string();
        let error = to_transaction(&template).unwrap_err();
        assert!(error.to_string().contains("account_keys"));
    }

    #[test]
    fn invalid_hex_error() {
        let payer = Keypair::new();
        let original = legacy_tx(&[system_transfer(payer.pubkey(), Pubkey::new_unique(), 1)], &[&payer]);
        let mut template = from_transaction(&original);
        assert!(template.set_instruction_data(0, "not-hex").is_err());
        template.instructions[0].data_hex = "not-hex".to_string();
        let error = to_transaction(&template).unwrap_err();
        assert!(error.to_string().contains("data_hex"));
    }

    #[test]
    fn invalid_blockhash_error() {
        let payer = Keypair::new();
        let original = legacy_tx(&[system_transfer(payer.pubkey(), Pubkey::new_unique(), 1)], &[&payer]);
        let mut template = from_transaction(&original);
        template.recent_blockhash = "not-a-hash".to_string();
        let error = to_transaction(&template).unwrap_err();
        assert!(error.to_string().contains("recent_blockhash"));
    }

    #[test]
    fn invalid_message_version_error() {
        let payer = Keypair::new();
        let original = legacy_tx(&[system_transfer(payer.pubkey(), Pubkey::new_unique(), 1)], &[&payer]);
        let mut template = from_transaction(&original);
        template.message_version = Some(9);
        let error = to_transaction(&template).unwrap_err();
        assert!(error.to_string().contains("unsupported message_version 9"));
    }

    #[test]
    fn index_out_of_range_error() {
        let payer = Keypair::new();
        let original = legacy_tx(&[system_transfer(payer.pubkey(), Pubkey::new_unique(), 1)], &[&payer]);
        let mut template = from_transaction(&original);
        assert!(template.set_account_key(999, &Pubkey::new_unique().to_string()).is_err());
        assert!(template.set_instruction_data(999, "00").is_err());
        assert!(template.set_instruction_amount(999, 1).is_err());
    }

    #[test]
    fn v0_lookup_index_count_error() {
        let payer = Keypair::new();
        let table_key = Pubkey::new_unique();
        let instruction = Instruction {
            program_id: Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap(),
            accounts: vec![AccountMeta::new(Pubkey::new_unique(), false)],
            data: vec![2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        };
        let table = AddressLookupTableAccount { key: table_key, addresses: vec![] };
        let message = v0::Message::try_compile(&payer.pubkey(), &[instruction], &[table], blockhash()).unwrap();
        let original =
            VersionedTransaction { signatures: vec![Signature::default()], message: VersionedMessage::V0(message) };
        let mut template = from_transaction(&original);
        template.address_table_lookups.push(PocAltLookup {
            account_key: table_key.to_string(),
            writable_indexes: vec![0; 256],
            readonly_indexes: vec![],
        });
        let error = to_transaction(&template).unwrap_err();
        assert!(error.to_string().contains("more indexes than fit a u8 array"));
    }

    #[test]
    fn to_base64_matches_standard_encoding() {
        use base64::Engine;
        let payer = Keypair::new();
        let original = legacy_tx(&[system_transfer(payer.pubkey(), Pubkey::new_unique(), 1)], &[&payer]);
        let template = from_transaction(&original);
        let encoded = to_base64(&template).unwrap();
        let expected = base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&to_transaction(&template).unwrap()).unwrap());
        assert_eq!(encoded, expected);
    }
    #[test]
    fn sign_with_keypairs_signs_matching_slots() {
        let payer = Keypair::new();
        let second = Keypair::new();
        let ix = Instruction {
            program_id: Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap(),
            accounts: vec![AccountMeta::new(payer.pubkey(), true), AccountMeta::new(second.pubkey(), true)],
            data: vec![2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        };
        let message = legacy::Message::new_with_blockhash(&[ix], Some(&payer.pubkey()), &blockhash());
        let mut tx = VersionedTransaction {
            signatures: vec![Signature::default(); 2],
            message: VersionedMessage::Legacy(message),
        };
        let signed = sign_with_keypairs(&mut tx, &[payer.insecure_clone(), second.insecure_clone()]);
        assert_eq!(signed, 2);
        let bytes = tx.message.serialize();
        for (index, keypair) in [&payer, &second].iter().enumerate() {
            assert!(tx.signatures[index].verify(keypair.pubkey().as_ref(), &bytes));
        }
    }

    #[test]
    fn sign_with_keypairs_partial_keeps_defaults() {
        let payer = Keypair::new();
        let second = Keypair::new();
        let ix = Instruction {
            program_id: Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap(),
            accounts: vec![AccountMeta::new(payer.pubkey(), true), AccountMeta::new(second.pubkey(), true)],
            data: vec![2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        };
        let message = legacy::Message::new_with_blockhash(&[ix], Some(&payer.pubkey()), &blockhash());
        let mut tx = VersionedTransaction {
            signatures: vec![Signature::default(); 2],
            message: VersionedMessage::Legacy(message),
        };
        let signed = sign_with_keypairs(&mut tx, &[payer.insecure_clone()]);
        assert_eq!(signed, 1);
        let bytes = tx.message.serialize();
        assert!(tx.signatures[0].verify(payer.pubkey().as_ref(), &bytes));
        assert_eq!(tx.signatures[1], Signature::default());
    }

    #[test]
    fn swap_instruction_accounts_reflected() {
        let payer = Keypair::new();
        let message = legacy::Message::new_with_blockhash(
            &[system_transfer(payer.pubkey(), Pubkey::new_unique(), 5)],
            Some(&payer.pubkey()),
            &blockhash(),
        );
        let tx = VersionedTransaction {
            signatures: vec![payer.sign_message(&message.serialize())],
            message: VersionedMessage::Legacy(message),
        };
        let mut template = from_transaction(&tx);
        let original_accounts = template.instructions[0].accounts.clone();
        assert_eq!(original_accounts.len(), 2);
        template.swap_instruction_accounts(0, 0, 1).unwrap();
        let rebuilt = to_transaction(&template).unwrap();
        assert_eq!(rebuilt.message.instructions()[0].accounts[0], original_accounts[1]);
        assert_eq!(rebuilt.message.instructions()[0].accounts[1], original_accounts[0]);
    }

    #[test]
    fn swap_out_of_range_errors() {
        let payer = Keypair::new();
        let message = legacy::Message::new_with_blockhash(
            &[system_transfer(payer.pubkey(), Pubkey::new_unique(), 5)],
            Some(&payer.pubkey()),
            &blockhash(),
        );
        let tx = VersionedTransaction {
            signatures: vec![payer.sign_message(&message.serialize())],
            message: VersionedMessage::Legacy(message),
        };
        let mut template = from_transaction(&tx);
        assert!(template.swap_instruction_accounts(0, 0, 9).is_err());
        assert!(template.swap_instruction_accounts(9, 0, 1).is_err());
    }

    fn effects_report(
        success: bool,
        error_code: Option<&str>,
        units: u64,
        flags: Vec<crate::types::RiskFlag>,
    ) -> crate::types::TransactionReport {
        use crate::types::{SimulationResult, TransactionReport};
        TransactionReport {
            status: "DECODED SUCCESSFULLY".to_string(),
            fee_payer: String::new(),
            signatures: Vec::new(),
            recent_blockhash: String::new(),
            message_version: None,
            accounts: Vec::new(),
            instructions: Vec::new(),
            address_lookup_tables: Vec::new(),
            compute_budget: None,
            risk_flags: flags,
            simulation: Some(SimulationResult {
                success,
                error: None,
                logs: Vec::new(),
                units_consumed: units,
                return_data: None,
                error_code: error_code.map(str::to_string),
                error_instruction_index: Some(0),
                instruction_cu: Vec::new(),
            }),
            warnings: Vec::new(),
            signature_verification: Vec::new(),
            inner_instructions: Vec::new(),
            balance_changes_sol: Vec::new(),
            token_balance_changes: Vec::new(),
            oracle_feeds: Vec::new(),
            idl_source: None,
            program_analyses: Vec::new(),
            logs: Vec::new(),
            events: Vec::new(),
        }
    }

    fn sample_flag(message: &str) -> crate::types::RiskFlag {
        use crate::types::{RiskCategory, RiskFlag, RiskSeverity};
        RiskFlag {
            severity: RiskSeverity::Warning,
            category: RiskCategory::PatternDetection,
            instruction_index: Some(0),
            message: message.to_string(),
            details: String::new(),
        }
    }

    #[test]
    fn diff_reports_outcome_cu_and_flags() {
        let baseline = effects(&effects_report(true, None, 150, Vec::new()));
        let mutated = effects(&effects_report(false, Some("Custom(1)"), 220, vec![sample_flag("new risk")]));
        let changes = diff_effects(&baseline, &mutated);
        assert!(changes.iter().any(|line| line.contains("success -> failure (Custom(1) at instruction #0)")));
        assert!(changes.iter().any(|line| line.contains("CU consumed: 150 -> 220 (+70)")));
        assert!(changes.iter().any(|line| line.starts_with("+ flag")));
    }

    #[test]
    fn diff_identical_reports_is_empty() {
        let report = effects_report(true, None, 150, Vec::new());
        let changes = diff_effects(&effects(&report), &effects(&report));
        assert!(changes.is_empty());
    }
}
