use crate::account_roles::annotate_inner_instruction_roles;
use crate::instruction_decoder;
use crate::types::{
    ADDRESS_LOOKUP_TABLE_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, AccountInfo, COMPUTE_BUDGET_PROGRAM_ID,
    DecodedInstruction, FetchedTxMeta, InnerInstruction, MappedAccount, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID,
    TOKEN_PROGRAM_ID, TransactionReport,
};

pub(crate) fn full_key_list(report: &TransactionReport, meta: &FetchedTxMeta) -> Vec<String> {
    let mut statics: Vec<&AccountInfo> = report.accounts.iter().collect();
    statics.sort_by_key(|a| a.index);

    let mut full_keys: Vec<String> = statics.iter().map(|a| a.pubkey.clone()).collect();

    let (loaded_writable, loaded_readonly) = match &meta.loaded_addresses {
        Some(loaded) => (loaded.writable.clone(), loaded.readonly.clone()),
        None => (Vec::new(), Vec::new()),
    };
    full_keys.extend(loaded_writable.iter().cloned());
    full_keys.extend(loaded_readonly.iter().cloned());

    full_keys
}

pub fn annotate_report(report: &mut TransactionReport, meta: FetchedTxMeta) -> Vec<String> {
    let mut statics: Vec<&AccountInfo> = report.accounts.iter().collect();
    statics.sort_by_key(|a| a.index);

    let full_keys = full_key_list(report, &meta);

    let (loaded_writable, loaded_readonly) = match &meta.loaded_addresses {
        Some(loaded) => (loaded.writable.clone(), loaded.readonly.clone()),
        None => (Vec::new(), Vec::new()),
    };
    let static_len = full_keys.len() - loaded_writable.len() - loaded_readonly.len();

    let mut warnings = Vec::new();

    for group in &meta.inner_instructions {
        let parent = group.index;
        for (inner_idx, raw) in group.instructions.iter().enumerate() {
            let inner_idx = inner_idx as u32;
            let Some(program_id) = full_keys.get(raw.program_id_index as usize) else {
                warnings.push(format!(
                    "inner instruction {inner_idx} under parent {parent} has out-of-range programIdIndex"
                ));
                continue;
            };

            let bytes = match bs58::decode(&raw.data).into_vec() {
                Ok(bytes) => bytes,
                Err(_) => {
                    warnings
                        .push(format!("inner instruction {inner_idx} under parent {parent} has invalid base58 data"));
                    Vec::new()
                }
            };

            let (instruction_name, decoded_data) =
                instruction_decoder::decode_instruction_data(program_id, &bytes, None);

            let program_name = match program_id.as_str() {
                SYSTEM_PROGRAM_ID => "System Program".to_string(),
                TOKEN_PROGRAM_ID => "Token Program".to_string(),
                TOKEN_2022_PROGRAM_ID => "Token-2022 Program".to_string(),
                ASSOCIATED_TOKEN_PROGRAM_ID => "Associated Token Program".to_string(),
                COMPUTE_BUDGET_PROGRAM_ID => "Compute Budget".to_string(),
                ADDRESS_LOOKUP_TABLE_PROGRAM_ID => "Address Lookup Table".to_string(),
                _ => "Unknown Program".to_string(),
            };

            let accounts: Vec<MappedAccount> = raw
                .accounts
                .iter()
                .map(|&ai| {
                    let idx = ai as usize;
                    let pubkey = full_keys.get(idx).cloned().unwrap_or_else(|| "unknown".to_string());
                    let (is_signer, is_writable) = if idx < static_len {
                        let info = statics.get(idx);
                        (info.map(|a| a.is_signer).unwrap_or(false), info.map(|a| a.is_writable).unwrap_or(false))
                    } else {
                        (false, idx < static_len + loaded_writable.len())
                    };
                    MappedAccount { name: None, pubkey, account_index: ai, is_signer, is_writable }
                })
                .collect();

            report.inner_instructions.push(InnerInstruction {
                inner_index: inner_idx,
                parent_instruction_index: parent,
                program_id: program_id.clone(),
                program_name,
                instruction_name,
                accounts,
                data: decoded_data,
                raw_data_hex: hex::encode(&bytes),
                token_amount: None,
            });
        }
    }

    annotate_inner_instruction_roles(&mut report.inner_instructions);

    warnings
}

pub enum AnyInstructionRef<'a> {
    Top(&'a DecodedInstruction),
    Inner(&'a InnerInstruction),
}

pub fn all_instructions(report: &TransactionReport) -> impl Iterator<Item = AnyInstructionRef<'_>> {
    report
        .instructions
        .iter()
        .map(AnyInstructionRef::Top)
        .chain(report.inner_instructions.iter().map(AnyInstructionRef::Inner))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_roles::annotate_inner_instruction_roles;
    use crate::types::{FetchedTxLoadedAddresses, TxMetaInnerInstructions, TxMetaRawInnerInstruction};

    fn account(index: u8, pubkey: &str, is_signer: bool, is_writable: bool) -> AccountInfo {
        AccountInfo { index, pubkey: pubkey.to_string(), is_signer, is_writable, role: None, pda_info: None }
    }

    fn mapped(pubkey: &str) -> MappedAccount {
        MappedAccount { name: None, pubkey: pubkey.to_string(), account_index: 0, is_signer: false, is_writable: false }
    }

    fn raw_inner(program_id_index: u8, accounts: Vec<u8>, data: &str) -> TxMetaRawInnerInstruction {
        TxMetaRawInnerInstruction { program_id_index, accounts, data: data.to_string() }
    }

    fn report_with_accounts(accounts: Vec<AccountInfo>) -> TransactionReport {
        TransactionReport {
            status: "ok".to_string(),
            fee_payer: "fee_payer".to_string(),
            signatures: Vec::new(),
            recent_blockhash: String::new(),
            message_version: None,
            accounts,
            instructions: Vec::new(),
            address_lookup_tables: Vec::new(),
            compute_budget: None,
            risk_flags: Vec::new(),
            simulation: None,
            warnings: Vec::new(),
            signature_verification: Vec::new(),
            inner_instructions: Vec::new(),
            balance_changes_sol: Vec::new(),
            token_balance_changes: Vec::new(),
            oracle_feeds: Vec::new(),
        }
    }

    fn top(index: u8) -> DecodedInstruction {
        DecodedInstruction {
            index,
            program_id: String::new(),
            program_name: String::new(),
            instruction_name: None,
            accounts: Vec::new(),
            data: serde_json::Value::Null,
            raw_data_hex: String::new(),
            token_amount: None,
        }
    }

    fn inner(parent: u8, inner_index: u32) -> InnerInstruction {
        InnerInstruction {
            inner_index,
            parent_instruction_index: parent,
            program_id: String::new(),
            program_name: String::new(),
            instruction_name: None,
            accounts: Vec::new(),
            data: serde_json::Value::Null,
            raw_data_hex: String::new(),
            token_amount: None,
        }
    }

    fn meta_with_groups(
        groups: Vec<TxMetaInnerInstructions>,
        loaded: Option<FetchedTxLoadedAddresses>,
    ) -> FetchedTxMeta {
        FetchedTxMeta {
            inner_instructions: groups,
            loaded_addresses: loaded,
            error: None,
            units_consumed: None,
            pre_balances: Vec::new(),
            post_balances: Vec::new(),
            pre_token_balances: Vec::new(),
            post_token_balances: Vec::new(),
        }
    }

    #[test]
    fn annotate_populates_known_program_inner() {
        let token_accounts = vec![
            account(0, "source1111111111111111111111111111111111", false, true),
            account(1, "delegate11111111111111111111111111111111", false, false),
            account(2, "owner11111111111111111111111111111111111", true, false),
            account(3, TOKEN_PROGRAM_ID, false, false),
        ];
        let mut report = report_with_accounts(token_accounts);

        let data = vec![4u8, 0, 0, 0, 0, 0, 0, 0, 0];
        let data_b58 = bs58::encode(&data).into_string();
        let meta = meta_with_groups(
            vec![TxMetaInnerInstructions { index: 0, instructions: vec![raw_inner(3, vec![0, 1, 2], &data_b58)] }],
            None,
        );

        let warnings = annotate_report(&mut report, meta);
        assert!(warnings.is_empty());
        assert_eq!(report.inner_instructions.len(), 1);

        let inner = &report.inner_instructions[0];
        assert_eq!(inner.inner_index, 0);
        assert_eq!(inner.parent_instruction_index, 0);
        assert_eq!(inner.program_id, TOKEN_PROGRAM_ID);
        assert_eq!(inner.program_name, "Token Program");
        assert_eq!(inner.instruction_name.as_deref(), Some("Approve"));
        assert_eq!(inner.accounts.len(), 3);
        assert_eq!(inner.accounts[0].pubkey, "source1111111111111111111111111111111111");
        assert_eq!(inner.accounts[1].pubkey, "delegate11111111111111111111111111111111");
        assert_eq!(inner.accounts[2].pubkey, "owner11111111111111111111111111111111111");
        assert_eq!(inner.accounts.iter().map(|a| a.is_signer).collect::<Vec<_>>(), [false, false, true]);
        assert_eq!(inner.accounts.iter().map(|a| a.is_writable).collect::<Vec<_>>(), [true, false, false]);
        assert_eq!(inner.accounts.iter().map(|a| a.account_index).collect::<Vec<_>>(), [0, 1, 2]);
        assert_eq!(inner.raw_data_hex, "040000000000000000");
    }

    #[test]
    fn annotate_resolves_alt_loaded_keys() {
        let static_accounts = vec![
            account(0, "static0001111111111111111111111111111111", true, true),
            account(1, "static11111111111111111111111111111111111", false, false),
        ];
        let mut report = report_with_accounts(static_accounts);

        let meta = meta_with_groups(
            vec![TxMetaInnerInstructions { index: 0, instructions: vec![raw_inner(2, vec![3], "8")] }],
            Some(FetchedTxLoadedAddresses {
                writable: vec!["w1pubkey".to_string()],
                readonly: vec!["r1pubkey".to_string()],
            }),
        );

        let warnings = annotate_report(&mut report, meta);
        assert!(warnings.is_empty());
        assert_eq!(report.inner_instructions.len(), 1);

        let inner = &report.inner_instructions[0];
        assert_eq!(inner.program_id, "w1pubkey");
        assert_eq!(inner.accounts.len(), 1);
        assert_eq!(inner.accounts[0].pubkey, "r1pubkey");
        assert!(!inner.accounts[0].is_signer);
        assert!(!inner.accounts[0].is_writable);
    }

    #[test]
    fn annotate_skips_out_of_range_with_warning() {
        let mut report = report_with_accounts(vec![account(0, "static0001111111111111111111111111111111", true, true)]);
        let meta = meta_with_groups(
            vec![TxMetaInnerInstructions { index: 0, instructions: vec![raw_inner(99, Vec::new(), "8")] }],
            None,
        );

        let warnings = annotate_report(&mut report, meta);
        assert!(warnings.iter().any(|w| w.contains("out-of-range")));
        assert!(report.inner_instructions.is_empty());
    }

    #[test]
    fn annotate_skips_bad_base58_with_warning() {
        let mut report = report_with_accounts(vec![account(0, TOKEN_PROGRAM_ID, false, false)]);
        let meta = meta_with_groups(
            vec![TxMetaInnerInstructions { index: 1, instructions: vec![raw_inner(0, vec![0], "!!notbase58!!")] }],
            None,
        );

        let warnings = annotate_report(&mut report, meta);
        assert!(warnings.iter().any(|w| w.contains("base58")));
        assert_eq!(report.inner_instructions.len(), 1);

        let inner = &report.inner_instructions[0];
        assert_eq!(inner.program_id, TOKEN_PROGRAM_ID);
        assert_eq!(inner.program_name, "Token Program");
        assert!(inner.instruction_name.is_none());
        assert!(inner.raw_data_hex.is_empty());
        assert_eq!(inner.parent_instruction_index, 1);
    }

    #[test]
    fn annotate_empty_meta_no_warnings() {
        let mut report = report_with_accounts(Vec::new());
        let meta = meta_with_groups(Vec::new(), None);

        let warnings = annotate_report(&mut report, meta);
        assert!(warnings.is_empty());
        assert!(report.inner_instructions.is_empty());
    }

    #[test]
    fn all_instructions_flattens_in_order() {
        let mut report = report_with_accounts(Vec::new());
        report.instructions = vec![top(0), top(1)];
        report.inner_instructions = vec![inner(0, 0), inner(1, 0), inner(0, 1)];

        let flat: Vec<AnyInstructionRef> = all_instructions(&report).collect();
        assert_eq!(flat.len(), 5);
        match flat[0] {
            AnyInstructionRef::Top(ix) => assert_eq!(ix.index, 0),
            AnyInstructionRef::Inner(_) => panic!("expected Top at position 0"),
        }
        match flat[1] {
            AnyInstructionRef::Top(ix) => assert_eq!(ix.index, 1),
            AnyInstructionRef::Inner(_) => panic!("expected Top at position 1"),
        }
        match flat[2] {
            AnyInstructionRef::Inner(ix) => {
                assert_eq!(ix.parent_instruction_index, 0);
                assert_eq!(ix.inner_index, 0);
            }
            AnyInstructionRef::Top(_) => panic!("expected Inner at position 2"),
        }
        match flat[3] {
            AnyInstructionRef::Inner(ix) => {
                assert_eq!(ix.parent_instruction_index, 1);
                assert_eq!(ix.inner_index, 0);
            }
            AnyInstructionRef::Top(_) => panic!("expected Inner at position 3"),
        }
        match flat[4] {
            AnyInstructionRef::Inner(ix) => {
                assert_eq!(ix.parent_instruction_index, 0);
                assert_eq!(ix.inner_index, 1);
            }
            AnyInstructionRef::Top(_) => panic!("expected Inner at position 4"),
        }
    }

    #[test]
    fn annotate_inner_instruction_roles_names() {
        let mut ix = InnerInstruction {
            inner_index: 0,
            parent_instruction_index: 0,
            program_id: TOKEN_PROGRAM_ID.to_string(),
            program_name: "Token Program".to_string(),
            instruction_name: Some("TransferChecked".to_string()),
            accounts: vec![mapped("source"), mapped("mint"), mapped("dest"), mapped("auth")],
            data: serde_json::Value::Null,
            raw_data_hex: String::new(),
            token_amount: None,
        };

        annotate_inner_instruction_roles(std::slice::from_mut(&mut ix));
        let names: Vec<_> = ix.accounts.iter().map(|a| a.name.as_deref()).collect();
        assert_eq!(names, [Some("source"), Some("mint"), Some("destination"), Some("authority")]);
    }

    #[test]
    fn loaded_writable_flag() {
        let mut report = report_with_accounts(vec![
            account(0, "static0001111111111111111111111111111111", true, true),
            account(1, "static11111111111111111111111111111111111", false, false),
        ]);
        let meta = meta_with_groups(
            vec![TxMetaInnerInstructions { index: 0, instructions: vec![raw_inner(2, vec![2, 3], "8")] }],
            Some(FetchedTxLoadedAddresses {
                writable: vec!["w1pubkey".to_string()],
                readonly: vec!["r1pubkey".to_string()],
            }),
        );

        let warnings = annotate_report(&mut report, meta);
        assert!(warnings.is_empty());
        assert_eq!(report.inner_instructions.len(), 1);

        let inner = &report.inner_instructions[0];
        assert_eq!(inner.accounts.len(), 2);
        assert_eq!(inner.accounts[0].pubkey, "w1pubkey");
        assert!(inner.accounts[0].is_writable);
        assert!(!inner.accounts[0].is_signer);
        assert_eq!(inner.accounts[1].pubkey, "r1pubkey");
        assert!(!inner.accounts[1].is_writable);
        assert!(!inner.accounts[1].is_signer);
    }
}
