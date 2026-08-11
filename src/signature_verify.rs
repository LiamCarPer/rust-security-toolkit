use solana_sdk::signature::Signature;
use solana_sdk::transaction::VersionedTransaction;

use crate::types::{RiskCategory, RiskFlag, RiskSeverity, SignatureCheck, TransactionReport};

pub fn verify_transaction(tx: &VersionedTransaction) -> Vec<SignatureCheck> {
    let message = &tx.message;
    let keys = message.static_account_keys();
    let required = message.header().num_required_signatures as usize;
    let message_bytes = message.serialize();

    let mut checks: Vec<SignatureCheck> = Vec::with_capacity(required.max(tx.signatures.len()));
    for index in 0..required {
        let pubkey = keys.get(index).map(ToString::to_string).unwrap_or_default();
        let (verified, note) = match tx.signatures.get(index) {
            None => (false, "missing signature".to_string()),
            Some(_) if keys.get(index).is_none() => (false, "missing signer key".to_string()),
            Some(sig) if *sig == Signature::default() => (false, "zeroed signature".to_string()),
            Some(sig) => {
                let ok = sig.verify(keys[index].as_ref(), &message_bytes);
                (ok, if ok { "verified".to_string() } else { "invalid signature".to_string() })
            }
        };
        checks.push(SignatureCheck { index: index as u8, pubkey, verified, note });
    }
    for index in required..tx.signatures.len() {
        checks.push(SignatureCheck {
            index: index as u8,
            pubkey: keys.get(index).map(ToString::to_string).unwrap_or_default(),
            verified: false,
            note: "extra signature not required by message".to_string(),
        });
    }
    checks
}

pub fn verify_report(report: &mut TransactionReport) -> Vec<RiskFlag> {
    let report_fee_payer = report.fee_payer.clone();
    let mut flags = Vec::new();
    for check in &report.signature_verification {
        if check.verified {
            continue;
        }
        let is_fee_payer = check.index == 0 || (!report_fee_payer.is_empty() && check.pubkey == report_fee_payer);
        flags.push(RiskFlag {
            severity: if is_fee_payer { RiskSeverity::Critical } else { RiskSeverity::Warning },
            category: RiskCategory::SignatureMismatch,
            instruction_index: None,
            message: format!(
                "signature #{} by {} failed verification ({})",
                check.index,
                check.pubkey,
                if is_fee_payer { "fee payer" } else { "signer" }
            ),
            details: format!(
                "{}; the transaction as given cannot be submitted or land because of the invalid signature",
                check.note
            ),
        });
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::{verify_report, verify_transaction};
    use crate::types::{RiskCategory, RiskSeverity, SignatureCheck, TransactionReport};
    use solana_sdk::hash::Hash;
    use solana_sdk::instruction::{AccountMeta, Instruction};
    use solana_sdk::message::compiled_instruction::CompiledInstruction;
    use solana_sdk::message::v0::Message as MessageV0;
    use solana_sdk::message::{MessageHeader, VersionedMessage, legacy};
    use solana_sdk::pubkey::Pubkey;
    use solana_sdk::signature::{Keypair, Signature};
    use solana_sdk::signer::Signer;
    use solana_sdk::transaction::VersionedTransaction;
    use std::str::FromStr;

    const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

    fn blockhash() -> Hash {
        Hash::new_from_array([7u8; 32])
    }

    fn system_program() -> Pubkey {
        Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap()
    }

    fn transfer(from: &Keypair, to: &Pubkey, to_is_signer: bool, lamports: u64) -> Instruction {
        let mut data = vec![2u8, 0, 0, 0];
        data.extend_from_slice(&lamports.to_le_bytes());
        Instruction {
            program_id: system_program(),
            accounts: vec![AccountMeta::new(from.pubkey(), true), AccountMeta::new(*to, to_is_signer)],
            data,
        }
    }

    fn legacy_tx(instructions: Vec<Instruction>, signers: &[&Keypair]) -> VersionedTransaction {
        let message = VersionedMessage::Legacy(legacy::Message::new_with_blockhash(
            &instructions,
            Some(&signers[0].pubkey()),
            &blockhash(),
        ));
        let message_bytes = message.serialize();
        let required = message.header().num_required_signatures as usize;
        let mut signatures = Vec::with_capacity(required);
        for key in message.static_account_keys().iter().take(required) {
            let signer = signers
                .iter()
                .find(|s| s.pubkey() == *key)
                .unwrap_or_else(|| panic!("no signer supplied for required signer {}", key));
            signatures.push(signer.sign_message(&message_bytes));
        }
        VersionedTransaction { signatures, message }
    }

    fn report_with(checks: Vec<SignatureCheck>, fee_payer: String) -> TransactionReport {
        TransactionReport {
            status: "DECODED SUCCESSFULLY".to_string(),
            fee_payer,
            signatures: Vec::new(),
            recent_blockhash: blockhash().to_string(),
            message_version: None,
            accounts: Vec::new(),
            instructions: Vec::new(),
            address_lookup_tables: Vec::new(),
            compute_budget: None,
            risk_flags: Vec::new(),
            simulation: None,
            warnings: Vec::new(),
            signature_verification: checks,
            inner_instructions: Vec::new(),
            balance_changes_sol: Vec::new(),
            token_balance_changes: Vec::new(),
        }
    }

    #[test]
    fn legacy_two_signers_verify_clean() {
        let payer = Keypair::new();
        let second = Keypair::new();
        let tx = legacy_tx(vec![transfer(&payer, &second.pubkey(), true, 1_000)], &[&payer, &second]);

        let checks = verify_transaction(&tx);

        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0].index, 0);
        assert_eq!(checks[1].index, 1);
        assert_eq!(checks[0].pubkey, payer.pubkey().to_string());
        assert_eq!(checks[1].pubkey, second.pubkey().to_string());
        for check in &checks {
            assert!(check.verified);
            assert_eq!(check.note, "verified");
        }

        let flags = verify_report(&mut report_with(checks, payer.pubkey().to_string()));
        assert!(flags.is_empty());
    }

    #[test]
    fn v0_message_verified() {
        let payer = Keypair::new();
        let v0 = MessageV0 {
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            },
            account_keys: vec![payer.pubkey(), system_program()],
            recent_blockhash: blockhash(),
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![2, 0, 0, 0, 0xe8, 0x03, 0, 0],
            }],
            address_table_lookups: Vec::new(),
        };
        let message = VersionedMessage::V0(v0);
        let message_bytes = message.serialize();
        assert!(message_bytes[0] & 0x80 != 0);
        let tx = VersionedTransaction { signatures: vec![payer.sign_message(&message_bytes)], message };

        let checks = verify_transaction(&tx);

        assert_eq!(checks.len(), 1);
        assert!(checks[0].verified);
        assert_eq!(checks[0].note, "verified");
        assert_eq!(checks[0].pubkey, payer.pubkey().to_string());
    }

    #[test]
    fn tampered_signature_yields_warning() {
        let payer = Keypair::new();
        let second = Keypair::new();
        let mut tx = legacy_tx(vec![transfer(&payer, &second.pubkey(), true, 1_000)], &[&payer, &second]);
        let mut bytes = *tx.signatures[1].as_array();
        bytes[0] ^= 0xff;
        tx.signatures[1] = Signature::from(bytes);

        let checks = verify_transaction(&tx);

        assert!(checks[0].verified);
        assert!(!checks[1].verified);
        assert_eq!(checks[1].note, "invalid signature");

        let flags = verify_report(&mut report_with(checks, payer.pubkey().to_string()));
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].severity, RiskSeverity::Warning);
        assert_eq!(flags[0].category, RiskCategory::SignatureMismatch);
        assert!(flags[0].instruction_index.is_none());
        assert!(flags[0].message.contains(&second.pubkey().to_string()));
        assert!(flags[0].message.contains("signer"));
        assert!(flags[0].details.contains("invalid signature"));
    }

    #[test]
    fn tampered_fee_payer_signature_is_critical() {
        let payer = Keypair::new();
        let second = Keypair::new();
        let mut tx = legacy_tx(vec![transfer(&payer, &second.pubkey(), true, 1_000)], &[&payer, &second]);
        let mut bytes = *tx.signatures[0].as_array();
        bytes[10] ^= 0x01;
        tx.signatures[0] = Signature::from(bytes);

        let checks = verify_transaction(&tx);

        assert!(!checks[0].verified);
        assert!(checks[1].verified);

        let flags = verify_report(&mut report_with(checks, payer.pubkey().to_string()));
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].severity, RiskSeverity::Critical);
        assert_eq!(flags[0].category, RiskCategory::SignatureMismatch);
        assert!(flags[0].instruction_index.is_none());
        assert!(flags[0].message.contains(&payer.pubkey().to_string()));
        assert!(flags[0].message.contains("fee payer"));
    }

    #[test]
    fn missing_signature_is_flagged() {
        let payer = Keypair::new();
        let second = Keypair::new();
        let mut tx = legacy_tx(vec![transfer(&payer, &second.pubkey(), true, 1_000)], &[&payer, &second]);
        tx.signatures.pop();

        let checks = verify_transaction(&tx);

        assert_eq!(checks.len(), 2);
        assert!(checks[0].verified);
        assert!(!checks[1].verified);
        assert_eq!(checks[1].note, "missing signature");
        assert_eq!(checks[1].pubkey, second.pubkey().to_string());

        let flags = verify_report(&mut report_with(checks, payer.pubkey().to_string()));
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].severity, RiskSeverity::Warning);
        assert_eq!(flags[0].category, RiskCategory::SignatureMismatch);
        assert!(flags[0].details.contains("missing signature"));
    }

    #[test]
    fn zeroed_signature_is_flagged() {
        let payer = Keypair::new();
        let second = Keypair::new();
        let mut tx = legacy_tx(vec![transfer(&payer, &second.pubkey(), true, 1_000)], &[&payer, &second]);
        tx.signatures[0] = Signature::default();

        let checks = verify_transaction(&tx);

        assert!(!checks[0].verified);
        assert_eq!(checks[0].note, "zeroed signature");
        assert!(checks[1].verified);

        let flags = verify_report(&mut report_with(checks, payer.pubkey().to_string()));
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].severity, RiskSeverity::Critical);
        assert_eq!(flags[0].category, RiskCategory::SignatureMismatch);
        assert!(flags[0].details.contains("zeroed signature"));
    }

    #[test]
    fn duplicate_signer_pubkey_both_verified() {
        let payer = Keypair::new();
        let message = VersionedMessage::Legacy(legacy::Message {
            header: MessageHeader {
                num_required_signatures: 2,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
            account_keys: vec![payer.pubkey(), payer.pubkey()],
            recent_blockhash: blockhash(),
            instructions: vec![CompiledInstruction { program_id_index: 0, accounts: vec![0], data: Vec::new() }],
        });
        let message_bytes = message.serialize();
        let signature = payer.sign_message(&message_bytes);
        let tx = VersionedTransaction { signatures: vec![signature, signature], message };

        let checks = verify_transaction(&tx);

        assert_eq!(checks.len(), 2);
        assert!(checks.iter().all(|check| check.verified));
        assert_eq!(checks[0].pubkey, checks[1].pubkey);
        assert_eq!(checks[0].pubkey, payer.pubkey().to_string());
    }

    #[test]
    fn empty_signature_verification_no_flags() {
        let flags = verify_report(&mut report_with(Vec::new(), "11111111111111111111111111111111".to_string()));
        assert!(flags.is_empty());
    }

    #[test]
    fn extra_signature_is_flagged_unverified() {
        let payer = Keypair::new();
        let mut tx = legacy_tx(vec![transfer(&payer, &Pubkey::new_unique(), false, 1_000)], &[&payer]);
        tx.signatures.push(Signature::new_unique());

        let checks = verify_transaction(&tx);

        assert_eq!(checks.len(), 2);
        assert!(checks[0].verified);
        assert!(!checks[1].verified);
        assert_eq!(checks[1].note, "extra signature not required by message");

        let flags = verify_report(&mut report_with(checks, payer.pubkey().to_string()));
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].severity, RiskSeverity::Warning);
        assert_eq!(flags[0].category, RiskCategory::SignatureMismatch);
    }
}
