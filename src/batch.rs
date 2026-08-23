use anyhow::Result;

pub fn parse_batch_input(contents: &str) -> Result<Vec<String>, String> {
    Ok(contents.lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect())
}

pub fn decode_batch_line(line: &str) -> Result<(Vec<u8>, crate::types::TransactionReport)> {
    crate::decoder::decode_input(line.as_bytes(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_no_lines() {
        assert!(parse_batch_input("").unwrap().is_empty());
    }

    #[test]
    fn blank_lines_skipped() {
        let lines = parse_batch_input("a\n\n  \nb\n").unwrap();
        assert_eq!(lines, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn trailing_whitespace_trimmed() {
        assert_eq!(parse_batch_input("x   \n").unwrap(), vec!["x".to_string()]);
    }

    #[test]
    fn lines_preserved_in_order() {
        let lines = parse_batch_input("1\n2\n3\n").unwrap();
        assert_eq!(lines, vec!["1", "2", "3"]);
    }

    #[test]
    fn decodes_sdk_built_transaction() {
        use solana_sdk::{
            hash::Hash,
            instruction::Instruction,
            message::{VersionedMessage, legacy},
            pubkey::Pubkey,
            signature::Keypair,
            signer::Signer,
            transaction::VersionedTransaction,
        };
        use std::str::FromStr;
        let payer = Keypair::new();
        let recipient = Pubkey::new_unique();
        let ix = Instruction {
            program_id: Pubkey::from_str("11111111111111111111111111111111").unwrap(),
            accounts: vec![solana_sdk::instruction::AccountMeta::new(recipient, false)],
            data: 1_000_000u64.to_le_bytes().to_vec(),
        };
        let message = VersionedMessage::Legacy(legacy::Message::new_with_blockhash(
            &[ix],
            Some(&payer.pubkey()),
            &Hash::new_from_array([7u8; 32]),
        ));
        let tx = VersionedTransaction { signatures: vec![payer.sign_message(&message.serialize())], message };
        let hex_line = hex::encode(bincode::serialize(&tx).unwrap());
        let (_, report) = decode_batch_line(&hex_line).expect("decode");
        assert_eq!(report.status, "DECODED SUCCESSFULLY");
    }

    #[test]
    fn rejects_garbage_line() {
        assert!(decode_batch_line("definitely-not-a-transaction").is_err());
    }
}
