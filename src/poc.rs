use std::str::FromStr;

use anyhow::{Context, Result, bail};
use solana_sdk::hash::Hash;
use solana_sdk::message::compiled_instruction::CompiledInstruction;
use solana_sdk::message::{
    MessageHeader, VersionedMessage, legacy,
    v0::{self, MessageAddressTableLookup},
};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
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
    let account_keys = message.static_account_keys().iter().map(|key| key.to_string()).collect();
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
        _ => Some(1),
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
        .map(|(index, key)| Pubkey::from_str(key).with_context(|| format!("invalid account_keys[{index}] {:?}", key)))
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
                .map(|lookup| {
                    let account_key = Pubkey::from_str(&lookup.account_key)
                        .with_context(|| format!("invalid lookup account_key {:?}", lookup.account_key))?;
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
    pub fn set_account_key(&mut self, index: usize, pubkey: &str) -> Result<()> {
        if index >= self.account_keys.len() {
            bail!("account key index {index} out of range (len {})", self.account_keys.len());
        }
        let parsed = Pubkey::from_str(pubkey).context("invalid pubkey")?;
        self.account_keys[index] = parsed.to_string();
        Ok(())
    }

    pub fn set_instruction_data(&mut self, ix_index: usize, data_hex: &str) -> Result<()> {
        if ix_index >= self.instructions.len() {
            bail!("instruction index {ix_index} out of range (len {})", self.instructions.len());
        }
        let bytes = hex::decode(data_hex).context("invalid data hex")?;
        self.instructions[ix_index].data_hex = hex::encode(bytes);
        Ok(())
    }

    pub fn set_instruction_amount(&mut self, ix_index: usize, amount: u64) -> Result<()> {
        if ix_index >= self.instructions.len() {
            bail!("instruction index {ix_index} out of range (len {})", self.instructions.len());
        }
        let program_key = self.instructions[ix_index].program_id_index as usize;
        let program = self.account_keys.get(program_key).context("instruction program_id_index out of range")?.clone();
        let mut data = hex::decode(&self.instructions[ix_index].data_hex).context("invalid data hex")?;
        let is_system = program == SYSTEM_PROGRAM_ID;
        let is_token = program == TOKEN_PROGRAM_ID || program == TOKEN_2022_PROGRAM_ID;
        if is_system && data.len() >= 12 && u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == 2 {
            data[4..12].copy_from_slice(&amount.to_le_bytes());
        } else if is_token && data.len() >= 9 && matches!(data[0], 3 | 12) {
            data[1..9].copy_from_slice(&amount.to_le_bytes());
        } else {
            bail!(
                "unsupported amount layout: program {program}, first byte {}, length {}",
                data.first().copied().unwrap_or_default(),
                data.len()
            );
        }
        self.instructions[ix_index].data_hex = hex::encode(data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use solana_sdk::instruction::{AccountMeta, Instruction};
    use solana_sdk::message::AddressLookupTableAccount;
    use solana_sdk::signature::Keypair;
    use solana_sdk::signer::Signer;

    use super::*;

    fn system_transfer(from: Pubkey, to: Pubkey, lamports: u64) -> Instruction {
        let mut data = 2u32.to_le_bytes().to_vec();
        data.extend_from_slice(&lamports.to_le_bytes());
        Instruction {
            program_id: Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap(),
            accounts: vec![AccountMeta::new(from, true), AccountMeta::new(to, false)],
            data,
        }
    }

    fn blockhash() -> Hash {
        Hash::new_from_array([7u8; 32])
    }

    #[test]
    fn legacy_message_round_trip_is_byte_identical() {
        let payer = Keypair::new();
        let recipient = Keypair::new();
        let ix1 = system_transfer(payer.pubkey(), recipient.pubkey(), 1_000);
        let ix2 = system_transfer(recipient.pubkey(), payer.pubkey(), 2_000);
        let message = legacy::Message::new_with_blockhash(&[ix1, ix2], Some(&payer.pubkey()), &blockhash());
        let original = VersionedTransaction {
            signatures: vec![payer.sign_message(&message.serialize()), recipient.sign_message(&message.serialize())],
            message: VersionedMessage::Legacy(message),
        };
        let template = from_transaction(&original);
        assert_eq!(template.message_version, None);
        let rebuilt = to_transaction(&template).expect("rebuild");
        let original_bytes = bincode::serialize(&original.message).unwrap();
        let rebuilt_bytes = bincode::serialize(&rebuilt.message).unwrap();
        assert_eq!(original_bytes, rebuilt_bytes);
        assert_eq!(rebuilt.signatures.len(), original.signatures.len());
    }

    #[test]
    fn v0_with_alt_message_round_trip_is_byte_identical() {
        let payer = Keypair::new();
        let loaded_readonly = Pubkey::new_unique();
        let loaded_writable = Pubkey::new_unique();
        let table_key = Pubkey::new_unique();
        let ix = Instruction {
            program_id: Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap(),
            accounts: vec![AccountMeta::new_readonly(loaded_readonly, false), AccountMeta::new(loaded_writable, false)],
            data: vec![2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        };
        let table = AddressLookupTableAccount { key: table_key, addresses: vec![loaded_readonly, loaded_writable] };
        let message = v0::Message::try_compile(&payer.pubkey(), &[ix], &[table], blockhash()).expect("compile");
        assert_eq!(message.address_table_lookups.len(), 1);
        let original = VersionedTransaction {
            signatures: vec![payer.sign_message(&message.serialize())],
            message: VersionedMessage::V0(message),
        };
        let template = from_transaction(&original);
        assert_eq!(template.message_version, Some(0));
        assert_eq!(template.address_table_lookups.len(), 1);
        let rebuilt = to_transaction(&template).expect("rebuild");
        assert_eq!(bincode::serialize(&original.message).unwrap(), bincode::serialize(&rebuilt.message).unwrap());
    }

    #[test]
    fn set_account_key_reflected() {
        let payer = Keypair::new();
        let recipient = Pubkey::new_unique();
        let message = legacy::Message::new_with_blockhash(
            &[system_transfer(payer.pubkey(), recipient, 1)],
            Some(&payer.pubkey()),
            &blockhash(),
        );
        let tx = VersionedTransaction {
            signatures: vec![payer.sign_message(&message.serialize())],
            message: VersionedMessage::Legacy(message),
        };
        let mut template = from_transaction(&tx);
        let replacement = Pubkey::new_unique();
        let index = template.account_keys.iter().position(|k| *k == recipient.to_string()).unwrap();
        template.set_account_key(index, &replacement.to_string()).unwrap();
        let rebuilt = to_transaction(&template).unwrap();
        assert!(rebuilt.message.static_account_keys().contains(&replacement));
    }

    #[test]
    fn set_instruction_data_reflected() {
        let payer = Keypair::new();
        let message = legacy::Message::new_with_blockhash(
            &[system_transfer(payer.pubkey(), Pubkey::new_unique(), 1)],
            Some(&payer.pubkey()),
            &blockhash(),
        );
        let tx = VersionedTransaction {
            signatures: vec![payer.sign_message(&message.serialize())],
            message: VersionedMessage::Legacy(message),
        };
        let mut template = from_transaction(&tx);
        template.set_instruction_data(0, "aabbcc").unwrap();
        let rebuilt = to_transaction(&template).unwrap();
        assert_eq!(rebuilt.message.instructions()[0].data, vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn set_amount_system_transfer() {
        let payer = Keypair::new();
        let message = legacy::Message::new_with_blockhash(
            &[system_transfer(payer.pubkey(), Pubkey::new_unique(), 1)],
            Some(&payer.pubkey()),
            &blockhash(),
        );
        let tx = VersionedTransaction {
            signatures: vec![payer.sign_message(&message.serialize())],
            message: VersionedMessage::Legacy(message),
        };
        let mut template = from_transaction(&tx);
        template.set_instruction_amount(0, 1_000_000).unwrap();
        let rebuilt = to_transaction(&template).unwrap();
        let data = &rebuilt.message.instructions()[0].data;
        assert_eq!(u64::from_le_bytes(data[4..12].try_into().unwrap()), 1_000_000);
    }

    #[test]
    fn set_amount_token_transfer() {
        let payer = Keypair::new();
        let mut data = vec![3u8];
        data.extend_from_slice(&5u64.to_le_bytes());
        let ix = Instruction {
            program_id: Pubkey::from_str(TOKEN_PROGRAM_ID).unwrap(),
            accounts: vec![AccountMeta::new(Pubkey::new_unique(), false)],
            data,
        };
        let message = legacy::Message::new_with_blockhash(&[ix], Some(&payer.pubkey()), &blockhash());
        let tx = VersionedTransaction {
            signatures: vec![payer.sign_message(&message.serialize())],
            message: VersionedMessage::Legacy(message),
        };
        let mut template = from_transaction(&tx);
        template.set_instruction_amount(0, 777).unwrap();
        let rebuilt = to_transaction(&template).unwrap();
        let data = &rebuilt.message.instructions()[0].data;
        assert_eq!(u64::from_le_bytes(data[1..9].try_into().unwrap()), 777);
    }

    #[test]
    fn set_amount_rejects_unknown() {
        let payer = Keypair::new();
        let ix = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![AccountMeta::new(Pubkey::new_unique(), false)],
            data: vec![9, 9, 9],
        };
        let message = legacy::Message::new_with_blockhash(&[ix], Some(&payer.pubkey()), &blockhash());
        let tx = VersionedTransaction {
            signatures: vec![payer.sign_message(&message.serialize())],
            message: VersionedMessage::Legacy(message),
        };
        let mut template = from_transaction(&tx);
        assert!(template.set_instruction_amount(0, 1).is_err());
    }

    #[test]
    fn out_of_range_indexes_error() {
        let payer = Keypair::new();
        let message = legacy::Message::new_with_blockhash(
            &[system_transfer(payer.pubkey(), Pubkey::new_unique(), 1)],
            Some(&payer.pubkey()),
            &blockhash(),
        );
        let tx = VersionedTransaction {
            signatures: vec![payer.sign_message(&message.serialize())],
            message: VersionedMessage::Legacy(message),
        };
        let mut template = from_transaction(&tx);
        assert!(template.set_account_key(999, &Pubkey::new_unique().to_string()).is_err());
        assert!(template.set_instruction_data(9, "00").is_err());
        assert!(template.set_instruction_amount(9, 1).is_err());
    }

    #[test]
    fn default_signatures_sized() {
        let payer = Keypair::new();
        let second = Keypair::new();
        let ix = Instruction {
            program_id: Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap(),
            accounts: vec![AccountMeta::new(payer.pubkey(), true), AccountMeta::new(second.pubkey(), true)],
            data: vec![2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        };
        let message = legacy::Message::new_with_blockhash(&[ix], Some(&payer.pubkey()), &blockhash());
        let tx = VersionedTransaction {
            signatures: vec![payer.sign_message(&message.serialize()), second.sign_message(&message.serialize())],
            message: VersionedMessage::Legacy(message),
        };
        let template = from_transaction(&tx);
        assert_eq!(template.required_signatures, 2);
        let rebuilt = to_transaction(&template).unwrap();
        assert_eq!(rebuilt.signatures.len(), 2);
        assert!(rebuilt.signatures.iter().all(|s| s == &Signature::default()));
    }

    #[test]
    fn json_round_trip() {
        let payer = Keypair::new();
        let message = legacy::Message::new_with_blockhash(
            &[system_transfer(payer.pubkey(), Pubkey::new_unique(), 1)],
            Some(&payer.pubkey()),
            &blockhash(),
        );
        let tx = VersionedTransaction {
            signatures: vec![payer.sign_message(&message.serialize())],
            message: VersionedMessage::Legacy(message),
        };
        let template = from_transaction(&tx);
        let json = serde_json::to_string(&template).unwrap();
        let parsed: PocTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(template, parsed);
        assert_eq!(
            bincode::serialize(&to_transaction(&template).unwrap().message).unwrap(),
            bincode::serialize(&to_transaction(&parsed).unwrap().message).unwrap()
        );
    }

    #[test]
    fn malformed_templates_return_errors() {
        let mut template = PocTemplate {
            schema_version: "1.0".to_string(),
            message_version: None,
            required_signatures: 1,
            readonly_signed: 0,
            readonly_unsigned: 0,
            account_keys: vec!["not-a-pubkey".to_string()],
            recent_blockhash: "bad-hash".to_string(),
            instructions: vec![],
            address_table_lookups: vec![],
        };
        assert!(to_transaction(&template).is_err());
        template.account_keys = vec![Pubkey::new_unique().to_string()];
        template.recent_blockhash = Hash::new_from_array([1u8; 32]).to_string();
        template.message_version = Some(9);
        assert!(to_transaction(&template).is_err());
    }
}
