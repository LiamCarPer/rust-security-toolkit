//! Matching decoded Solana instructions against sat's native "expectations"
//! document — the native analog of an Anchor IDL for programs that ship no
//! IDL (e.g. Mango). The expectations document declares instruction
//! discriminators (1-byte u8 tags or 8-byte prefixes), positional account
//! roles, and static PDA seed declarations; this module maps raw instruction
//! data onto those declarations and annotates decoded accounts/PDA info.

use crate::types::{AccountInfo, DecodedInstruction, ExpectationInstruction, ExpectationsDoc};

/// Match a decoded instruction against the expectations document.
///
/// Rules (locked contract):
/// - When `exp.program_id` is `Some`, the instruction's program_id must equal
///   it; otherwise the doc applies to any program.
/// - `discriminator_hex` values are hex strings of either 2 chars (1-byte
///   u8-tag dispatch, e.g. Mango's `MangoInstruction::unpack(data[0])`) or
///   16 chars (8-byte byte-match dispatch). Malformed/other-length values are
///   skipped.
/// - The instruction data must START with the discriminator bytes.
/// - If several instructions match, the longest discriminator wins (8-byte
///   hashes are globally unique; 1-byte tags are only unique per program);
///   ties resolve to the first in document order.
pub fn match_expectation<'a>(
    program_id: &str,
    data: &[u8],
    exp: &'a ExpectationsDoc,
) -> Option<&'a ExpectationInstruction> {
    if let Some(expected_program_id) = exp.program_id.as_deref()
        && expected_program_id != program_id
    {
        return None;
    }

    let mut best: Option<(&'a ExpectationInstruction, usize)> = None;
    for ix in &exp.instructions {
        let Some(discriminator_hex) = ix.discriminator_hex.as_deref() else {
            continue;
        };
        let Ok(discriminator) = hex::decode(discriminator_hex) else {
            continue;
        };
        if discriminator.len() != 1 && discriminator.len() != 8 {
            continue;
        }
        if !data.starts_with(&discriminator) {
            continue;
        }
        let is_longer = match best {
            Some((_, best_len)) => discriminator.len() > best_len,
            None => true,
        };
        if is_longer {
            best = Some((ix, discriminator.len()));
        }
    }
    best.map(|(ix, _)| ix)
}

/// Decode an instruction under native expectations: on match returns
/// `(Some(name), hex-string rendering of the full data)`; on no-match returns
/// `(None, hex-string rendering)` — mirroring the generic fallback.
pub fn decode_instruction(program_id: &str, data: &[u8], exp: &ExpectationsDoc) -> (Option<String>, serde_json::Value) {
    let hex_str = hex::encode(data);
    match_expectation(program_id, data, exp)
        .map(|ix| (Some(ix.name.clone()), serde_json::Value::String(hex_str.clone())))
        .unwrap_or((None, serde_json::Value::String(hex_str)))
}

/// Positionally annotate `MappedAccount.name` from the expectations for
/// instructions that matched (only fills names that are still `None`).
pub fn annotate_account_names(instructions: &mut [DecodedInstruction], exp: &ExpectationsDoc) {
    for decoded_ix in instructions.iter_mut() {
        let Some(name) = decoded_ix.instruction_name.as_deref() else {
            continue;
        };
        let Some(exp_ix) = exp.find_instruction(name) else {
            continue;
        };
        for exp_account in &exp_ix.accounts {
            let Some(mapped) = decoded_ix.accounts.get_mut(exp_account.index) else {
                continue;
            };
            if mapped.name.is_none() {
                mapped.name = Some(exp_account.name.clone());
            }
        }
    }
}

/// Populate `AccountInfo.pda_info.seeds_declared` for matched instructions'
/// PDA accounts (bump/expected_address stay `None` here — the validator's
/// tier-2 check fills them). Seeds render as `"escrow"` (quoted literal) for
/// literal seeds; dynamic seeds render as `"<dynamic>"` entries.
pub fn annotate_pda_accounts(accounts: &mut [AccountInfo], instructions: &[DecodedInstruction], exp: &ExpectationsDoc) {
    for decoded_ix in instructions.iter() {
        let Some(name) = decoded_ix.instruction_name.as_deref() else {
            continue;
        };
        let Some(exp_ix) = exp.find_instruction(name) else {
            continue;
        };
        for exp_account in &exp_ix.accounts {
            let Some(exp_pda) = exp_account.pda.as_ref() else {
                continue;
            };
            let Some(mapped) = decoded_ix.accounts.get(exp_account.index) else {
                continue;
            };
            let mut seeds_declared: Vec<String> = exp_pda.seeds.iter().map(|seed| format!("\"{}\"", seed)).collect();
            for _ in 0..exp_pda.dynamic_seed_count {
                seeds_declared.push("<dynamic>".to_string());
            }
            let Some(info) = accounts.get_mut(mapped.account_index as usize) else {
                continue;
            };
            info.pda_info = Some(crate::types::PdaInfo { seeds_declared, bump: None, expected_address: None });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{MappedAccount, PdaInfo};

    /// Two-instruction doc (Mango-style 1-byte tags) plus a third 8-byte
    /// byte-match instruction. `program_id` is gated to "Mango".
    fn exp_json() -> String {
        r#"{
          "program_name": "Mango",
          "program_id": "Mango",
          "source": "native",
          "instructions": [
            {
              "name": "WithdrawMsrm",
              "discriminator_hex": "24",
              "handler": "withdraw_msrm",
              "accounts": [
                {"name": "owner_ai", "index": 2, "is_signer_expected": true, "is_writable_expected": false, "pda": null},
                {"name": "mango_account_ai", "index": 1, "is_signer_expected": false, "is_writable_expected": true, "pda": null}
              ]
            },
            {
              "name": "withdraw_escrow",
              "discriminator_hex": "25",
              "handler": "withdraw_escrow",
              "accounts": [
                {"name": "escrow", "index": 0, "is_signer_expected": false, "is_writable_expected": true,
                 "pda": {"seeds": ["escrow"], "dynamic_seed_count": 1}}
              ]
            },
            {
              "name": "byte_match",
              "discriminator_hex": "2400000000000000",
              "handler": "byte_match",
              "accounts": [
                {"name": "only_account", "index": 0, "is_signer_expected": false, "is_writable_expected": true, "pda": null}
              ]
            }
          ]
        }"#
        .to_string()
    }

    fn doc() -> ExpectationsDoc {
        serde_json::from_str(&exp_json()).expect("parse expectations doc")
    }

    fn account_infos(len: u8) -> Vec<AccountInfo> {
        (0..len)
            .map(|i| AccountInfo {
                index: i,
                pubkey: format!("pk{i}"),
                is_signer: false,
                is_writable: true,
                role: None,
                pda_info: None,
            })
            .collect()
    }

    #[test]
    fn matches_1byte_tag() {
        let doc = doc();
        let matched = match_expectation("Mango", &[0x24, 1, 2, 3], &doc).expect("WithdrawMsrm matches");
        assert_eq!(matched.name, "WithdrawMsrm");
        assert_eq!(matched.handler, "withdraw_msrm");
    }

    #[test]
    fn longest_discriminator_wins() {
        let doc = doc();
        let matched = match_expectation("Mango", &[0x24, 0, 0, 0, 0, 0, 0, 0, 1, 2], &doc).expect("byte_match matches");
        assert_eq!(matched.name, "byte_match");
    }

    #[test]
    fn program_id_gate_blocks_wrong_program() {
        let doc = doc();
        assert!(match_expectation("Other", &[0x24, 1, 2, 3], &doc).is_none());
    }

    #[test]
    fn program_id_gate_missing_accepts_any() {
        let mut doc = doc();
        doc.program_id = None;
        let matched = match_expectation("AnyProgram", &[0x24, 1, 2, 3], &doc).expect("any program matches");
        assert_eq!(matched.name, "WithdrawMsrm");
    }

    #[test]
    fn no_match_returns_hex_fallback() {
        let doc = doc();
        let (name, data) = decode_instruction("Mango", &[0x99], &doc);
        assert!(name.is_none());
        assert_eq!(data, serde_json::Value::String("99".to_string()));
    }

    #[test]
    fn data_shorter_than_discriminator_no_match() {
        let doc = doc();
        let matched = match_expectation("Mango", &[0x24], &doc).expect("WithdrawMsrm still matches");
        assert_eq!(matched.name, "WithdrawMsrm");
        assert_ne!(matched.name, "byte_match");
    }

    #[test]
    fn malformed_discriminator_skipped() {
        let mut doc = doc();
        doc.instructions.push(ExpectationInstruction {
            name: "bad_hex".to_string(),
            discriminator_hex: Some("zz".to_string()),
            handler: "bad_hex".to_string(),
            accounts: Vec::new(),
        });
        doc.instructions.push(ExpectationInstruction {
            name: "odd_len".to_string(),
            discriminator_hex: Some("123".to_string()),
            handler: "odd_len".to_string(),
            accounts: Vec::new(),
        });
        // Only the malformed entries could match these prefixes; None proves
        // they were skipped.
        assert!(match_expectation("Mango", &[0x99], &doc).is_none());
        assert!(match_expectation("Mango", &[0x12, 0x30], &doc).is_none());
    }

    #[test]
    fn tie_breaks_to_first_in_doc() {
        let mut doc = doc();
        doc.instructions.push(ExpectationInstruction {
            name: "WithdrawMsrmDup".to_string(),
            discriminator_hex: Some("24".to_string()),
            handler: "withdraw_msrm_dup".to_string(),
            accounts: Vec::new(),
        });
        let matched = match_expectation("Mango", &[0x24, 1, 2, 3], &doc).expect("tie matches");
        assert_eq!(matched.name, "WithdrawMsrm");
    }

    #[test]
    fn annotate_account_names_positional_and_only_none() {
        let doc = doc();
        let mut decoded = vec![DecodedInstruction {
            index: 0,
            program_id: "Mango".to_string(),
            program_name: "Mango".to_string(),
            instruction_name: Some("WithdrawMsrm".to_string()),
            accounts: vec![
                MappedAccount {
                    name: Some("pre_named".to_string()),
                    pubkey: "pk0".to_string(),
                    account_index: 0,
                    is_signer: false,
                    is_writable: false,
                },
                MappedAccount {
                    name: Some("keep_me".to_string()),
                    pubkey: "pk1".to_string(),
                    account_index: 1,
                    is_signer: false,
                    is_writable: true,
                },
                MappedAccount {
                    name: None,
                    pubkey: "pk2".to_string(),
                    account_index: 2,
                    is_signer: true,
                    is_writable: false,
                },
            ],
            data: serde_json::Value::Null,
            raw_data_hex: "24".to_string(),
            token_amount: None,
        }];
        annotate_account_names(&mut decoded, &doc);
        // Out-of-doc account keeps its pre-existing name.
        assert_eq!(decoded[0].accounts[0].name.as_deref(), Some("pre_named"));
        // In-doc account with a pre-existing name is NOT overwritten.
        assert_eq!(decoded[0].accounts[1].name.as_deref(), Some("keep_me"));
        // None name at positional index 2 becomes "owner_ai".
        assert_eq!(decoded[0].accounts[2].name.as_deref(), Some("owner_ai"));
    }

    #[test]
    fn annotate_pda_accounts_seeds_declared() {
        let doc = doc();
        let decoded = vec![DecodedInstruction {
            index: 0,
            program_id: "Mango".to_string(),
            program_name: "Mango".to_string(),
            instruction_name: Some("withdraw_escrow".to_string()),
            accounts: vec![MappedAccount {
                name: None,
                pubkey: "escrow_pubkey".to_string(),
                account_index: 5,
                is_signer: false,
                is_writable: true,
            }],
            data: serde_json::Value::Null,
            raw_data_hex: "25".to_string(),
            token_amount: None,
        }];
        let mut infos = account_infos(6);
        annotate_pda_accounts(&mut infos, &decoded, &doc);
        let pda = infos[5].pda_info.as_ref().expect("pda_info populated");
        assert_eq!(pda.seeds_declared, vec!["\"escrow\"".to_string(), "<dynamic>".to_string()]);
        assert!(pda.bump.is_none());
        assert!(pda.expected_address.is_none());
        // Unrelated accounts stay untouched.
        assert!(infos[0].pda_info.is_none());
    }

    #[test]
    fn annotate_skips_unknown_instruction_names() {
        let doc = doc();
        let decoded = vec![DecodedInstruction {
            index: 0,
            program_id: "Mango".to_string(),
            program_name: "Mango".to_string(),
            instruction_name: Some("Nope".to_string()),
            accounts: vec![MappedAccount {
                name: None,
                pubkey: "pk".to_string(),
                account_index: 3,
                is_signer: false,
                is_writable: true,
            }],
            data: serde_json::Value::Null,
            raw_data_hex: "99".to_string(),
            token_amount: None,
        }];
        let mut infos = account_infos(4);
        let mut ixs = decoded;
        annotate_account_names(&mut ixs, &doc);
        assert!(ixs[0].accounts[0].name.is_none());
        annotate_pda_accounts(&mut infos, &ixs, &doc);
        assert!(infos[3].pda_info.is_none());
    }

    #[test]
    fn decode_matched_returns_name_and_hex() {
        let doc = doc();
        let (name, data) = decode_instruction("Mango", &[0x24, 1, 2, 3], &doc);
        assert_eq!(name.as_deref(), Some("WithdrawMsrm"));
        assert_eq!(data, serde_json::Value::String("24010203".to_string()));
    }

    #[test]
    fn missing_discriminator_skipped() {
        let mut doc = doc();
        doc.instructions.push(ExpectationInstruction {
            name: "no_discriminator".to_string(),
            discriminator_hex: None,
            handler: "no_discriminator".to_string(),
            accounts: Vec::new(),
        });
        let matched = match_expectation("Mango", &[0x24, 1, 2, 3], &doc).expect("WithdrawMsrm matches");
        assert_eq!(matched.name, "WithdrawMsrm");
    }

    #[test]
    fn pda_info_type_shape_is_checked() {
        // Guards the PdaInfo field contract used by the validator's tier-2 check.
        let pda = PdaInfo {
            seeds_declared: vec!["\"escrow\"".to_string(), "<dynamic>".to_string()],
            bump: None,
            expected_address: None,
        };
        assert_eq!(pda.seeds_declared.len(), 2);
        assert!(pda.bump.is_none());
        assert!(pda.expected_address.is_none());
    }
}
