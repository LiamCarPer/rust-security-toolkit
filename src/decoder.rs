use anyhow::{Context, Result};
use solana_sdk::{message::VersionedMessage, transaction::VersionedTransaction};

use crate::types::{
    ADDRESS_LOOKUP_TABLE_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, AccountInfo, AltResolution,
    COMPUTE_BUDGET_PROGRAM_ID, ComputeBudgetInfo, DecodedInstruction, Encoding, IdlJson, MappedAccount, PdaInfo,
    ProgramSchema, ResolvedAccount, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, TransactionReport,
};

use crate::{account_roles, anchor_decoder, encoding, expectations_decoder, instruction_decoder, internal_parser};

pub use anchor_decoder::compute_anchor_discriminator;
pub use encoding::detect_encoding;
pub use internal_parser::validate_decoding;

/// Decode a transaction from pre-decoded raw bytes and produce a structured report.
/// Use this when the caller has already handled encoding detection to avoid redundant work.
pub fn decode_raw_bytes(raw_bytes: &[u8], schema: Option<&ProgramSchema>) -> Result<TransactionReport> {
    let tx: VersionedTransaction =
        bincode::deserialize(raw_bytes).context("Failed to deserialize transaction via bincode (solana-sdk format)")?;

    decode_versioned_tx(tx, schema)
}

/// Decode a transaction from raw input bytes (text in Base58/Base64/Hex, or raw
/// binary) and return the decoded bytes alongside the report.
///
/// All-hex even-length text is ambiguous: it is detected as Hex, but could be a
/// Base58 or padding-less Base64 encoding. When the Hex interpretation fails to
/// deserialize, the alternatives are retried before the primary error is
/// returned.
pub fn decode_input(input: &[u8], schema: Option<&ProgramSchema>) -> Result<(Vec<u8>, TransactionReport)> {
    let bytes = encoding::decode_input_bytes(input)?;
    if bytes.is_empty() {
        anyhow::bail!("Transaction input is empty");
    }

    match decode_raw_bytes(&bytes, schema) {
        Ok(report) => Ok((bytes, report)),
        Err(primary_err) => {
            if let Ok(text) = std::str::from_utf8(input) {
                let trimmed = text.trim();
                if is_ambiguous_hex_text(trimmed) {
                    for candidate in [Encoding::Base58, Encoding::Base64] {
                        if let Ok(alt_bytes) = encoding::decode_from_encoding(trimmed, candidate)
                            && let Ok(report) = decode_raw_bytes(&alt_bytes, schema)
                        {
                            return Ok((alt_bytes, report));
                        }
                    }
                }
            }
            Err(primary_err)
        }
    }
}

/// True for all-hex even-length text — the case where Hex, Base58, and
/// padding-less Base64 interpretations all exist.
fn is_ambiguous_hex_text(trimmed: &str) -> bool {
    !trimmed.is_empty() && trimmed.len().is_multiple_of(2) && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Decode a transaction from any supported encoding and produce a structured report.
pub fn decode_transaction(input: &str, schema: Option<&ProgramSchema>) -> Result<TransactionReport> {
    decode_input(input.as_bytes(), schema).map(|(_, report)| report)
}

fn decode_versioned_tx(tx: VersionedTransaction, schema: Option<&ProgramSchema>) -> Result<TransactionReport> {
    let message = &tx.message;
    let static_accounts = message.static_account_keys();
    let header = message.header();

    let is_v0 = matches!(message, VersionedMessage::V0(_));
    let message_version = if is_v0 { Some(0u8) } else { None };

    let fee_payer = static_accounts.first().map(|k| k.to_string()).unwrap_or_default();

    let signatures: Vec<String> = tx.signatures.iter().map(|s| s.to_string()).collect();

    let recent_blockhash = message.recent_blockhash().to_string();

    let num_required_signatures = header.num_required_signatures as usize;
    let num_readonly_signed = header.num_readonly_signed_accounts as usize;
    let num_readonly_unsigned = header.num_readonly_unsigned_accounts as usize;

    let static_len = static_accounts.len();
    let mut accounts: Vec<AccountInfo> = Vec::with_capacity(static_len);
    for (i, pubkey) in static_accounts.iter().enumerate() {
        let is_signer = i < num_required_signatures;
        // The runtime rule (solana-message is_writable_index): the first
        // `req - ro_signed` signers are writable, then the non-signer window
        // [req, len - ro_unsigned). A naive `i >= ro_signed` inversion here
        // mislabels every account whenever a readonly signer is present.
        let is_writable = i < num_required_signatures.saturating_sub(num_readonly_signed)
            || (i >= num_required_signatures && i < static_len.saturating_sub(num_readonly_unsigned));

        let role = if i == 0 {
            Some("fee_payer".to_string())
        } else if is_signer && is_writable {
            Some("signer+writable".to_string())
        } else if is_signer {
            Some("signer".to_string())
        } else if is_writable {
            Some("writable".to_string())
        } else {
            Some("readonly".to_string())
        };

        accounts.push(AccountInfo {
            index: i as u8,
            pubkey: pubkey.to_string(),
            is_signer,
            is_writable,
            role,
            pda_info: None,
        });
    }

    let mut address_lookup_tables: Vec<AltResolution> = Vec::new();
    let mut alt_resolved_len = 0usize;
    if let VersionedMessage::V0(v0_msg) = message {
        let alt_entries = &v0_msg.address_table_lookups;
        for alt in alt_entries {
            let mut resolved = Vec::new();
            for idx in &alt.writable_indexes {
                let global_idx = static_len + alt_resolved_len;
                alt_resolved_len += 1;
                resolved.push(ResolvedAccount {
                    index_in_tx: global_idx as u8,
                    pubkey: format!("<alt_index_{}>", idx),
                    is_writable: true,
                    table_index: Some(*idx),
                });
            }
            for idx in &alt.readonly_indexes {
                let global_idx = static_len + alt_resolved_len;
                alt_resolved_len += 1;
                resolved.push(ResolvedAccount {
                    index_in_tx: global_idx as u8,
                    pubkey: format!("<alt_index_{}>", idx),
                    is_writable: false,
                    table_index: Some(*idx),
                });
            }

            address_lookup_tables.push(AltResolution {
                table_address: alt.account_key.to_string(),
                resolved_accounts: resolved,
                resolved: false,
            });
        }
    }

    let decompile_ixs = message.instructions();
    let mut instructions: Vec<DecodedInstruction> = Vec::new();
    let mut compute_budget_info: Option<ComputeBudgetInfo> = None;
    let mut cb_positions: Vec<usize> = Vec::new();
    let mut has_explicit_cu_limit = false;
    let mut cu_limit: u32 = 200_000;
    let mut cu_price: u64 = 0;

    for (ix_idx, compiled_ix) in decompile_ixs.iter().enumerate() {
        let program_id = static_accounts
            .get(compiled_ix.program_id_index as usize)
            .map(|k| k.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let program_name = match program_id.as_str() {
            SYSTEM_PROGRAM_ID => "System Program".to_string(),
            TOKEN_PROGRAM_ID => "Token Program".to_string(),
            TOKEN_2022_PROGRAM_ID => "Token-2022 Program".to_string(),
            ASSOCIATED_TOKEN_PROGRAM_ID => "Associated Token Program".to_string(),
            COMPUTE_BUDGET_PROGRAM_ID => "Compute Budget".to_string(),
            ADDRESS_LOOKUP_TABLE_PROGRAM_ID => "Address Lookup Table".to_string(),
            _ => "Unknown Program".to_string(),
        };

        let raw_data_hex = hex::encode(&compiled_ix.data);

        let mapped_accounts: Vec<MappedAccount> = compiled_ix
            .accounts
            .iter()
            .map(|&ai| {
                let idx = ai as usize;
                let pubkey = static_accounts.get(idx).map(|k| k.to_string()).unwrap_or_else(|| "unknown".to_string());
                let info = accounts.get(idx);
                MappedAccount {
                    name: None,
                    pubkey,
                    account_index: ai,
                    is_signer: info.map(|a| a.is_signer).unwrap_or(false),
                    is_writable: info.map(|a| a.is_writable).unwrap_or(false),
                }
            })
            .collect();

        let (instruction_name, decoded_data) =
            instruction_decoder::decode_instruction_data(program_id.as_str(), &compiled_ix.data, schema);

        if program_id == COMPUTE_BUDGET_PROGRAM_ID {
            cb_positions.push(ix_idx);
            if let Some((limit, price)) = parse_compute_budget(&compiled_ix.data) {
                if limit > 0 {
                    has_explicit_cu_limit = true;
                    cu_limit = limit;
                }
                if price > 0 {
                    cu_price = price;
                }
            }
        }

        instructions.push(DecodedInstruction {
            index: ix_idx as u8,
            program_id: program_id.clone(),
            program_name,
            instruction_name,
            accounts: mapped_accounts,
            data: decoded_data,
            raw_data_hex,
            token_amount: None,
        });
    }

    // The Solana runtime requires all ComputeBudget instructions to be the first
    // instructions in the message. Positions that are not a contiguous prefix
    // [0, 1, .., n-1] mean a non-CB instruction precedes a CB instruction — an
    // invalid ordering or a mid-transaction injection.
    let is_reordered = cb_positions.iter().enumerate().any(|(i, &p)| p != i);

    if !cb_positions.is_empty() || has_explicit_cu_limit {
        // Worst-case priority fee: price (micro-lamports/CU) x limit (CU) / 1e6.
        // The runtime charges price x consumed CU, so this is the maximum the
        // fee payer commits to.
        let priority_fee_lamports = (cu_price as u128 * cu_limit as u128 / 1_000_000) as u64;
        compute_budget_info = Some(ComputeBudgetInfo {
            compute_unit_limit: cu_limit,
            compute_unit_price: cu_price,
            compute_unit_limit_set: has_explicit_cu_limit,
            compute_budget_positions: cb_positions,
            is_reordered,
            high_cu_instructions: Vec::new(),
            priority_fee_lamports,
            priority_fee_actual: None,
        });

        let high_cu = estimate_high_cu_instructions(&instructions, cu_limit);
        if let Some(ref mut cb) = compute_budget_info {
            cb.high_cu_instructions = high_cu;
        }
    }

    // Static role names for well-known programs (System/Token/Token-2022/AToken)
    // only fill accounts whose names are still unset.
    account_roles::annotate_known_program_roles(&mut instructions);

    if let Some(schema) = schema {
        match schema {
            ProgramSchema::Idl(idl) => {
                annotate_instruction_account_names(&mut instructions, idl);
                annotate_pda_accounts(&mut accounts, &instructions, idl);
            }
            ProgramSchema::Native(exp) => {
                expectations_decoder::annotate_account_names(&mut instructions, exp);
                expectations_decoder::annotate_pda_accounts(&mut accounts, &instructions, exp);
            }
        }
    }

    Ok(TransactionReport {
        status: "DECODED SUCCESSFULLY".to_string(),
        fee_payer,
        signatures,
        recent_blockhash,
        message_version,
        accounts,
        instructions,
        address_lookup_tables,
        compute_budget: compute_budget_info,
        risk_flags: Vec::new(),
        simulation: None,
        warnings: Vec::new(),
        signature_verification: Vec::new(),
        inner_instructions: Vec::new(),
        balance_changes_sol: Vec::new(),
        token_balance_changes: Vec::new(),
        oracle_feeds: Vec::new(),
        idl_source: None,
        logs: vec![],
        events: vec![],
    })
}

/// Annotate instruction account metas with their IDL-declared names
/// (positionally — the same assumption the `IdlAccountMismatch` validator flag
/// guards). These names drive the `sat` tx-report correlation.
fn annotate_instruction_account_names(instructions: &mut [DecodedInstruction], idl: &IdlJson) {
    for decoded_ix in instructions {
        let ix_name = match &decoded_ix.instruction_name {
            Some(name) => name,
            None => continue,
        };
        let idl_ix = match idl.find_instruction(ix_name) {
            Some(ix) => ix,
            None => continue,
        };

        for (acc_idx, idl_account) in idl_ix.accounts.iter().enumerate() {
            if let Some(mapped) = decoded_ix.accounts.get_mut(acc_idx)
                && mapped.name.is_none()
            {
                mapped.name = Some(idl_account.name.clone());
            }
        }
    }
}

fn annotate_pda_accounts(accounts: &mut [AccountInfo], instructions: &[DecodedInstruction], idl: &IdlJson) {
    for ix in instructions {
        let ix_name = match &ix.instruction_name {
            Some(name) => name,
            None => continue,
        };
        let idl_ix = match idl.find_instruction(ix_name) {
            Some(ix) => ix,
            None => continue,
        };

        for (acc_idx, idl_account) in idl_ix.accounts.iter().enumerate() {
            let pda = match &idl_account.pda {
                Some(pda) => pda,
                None => continue,
            };

            let mapped = match ix.accounts.get(acc_idx) {
                Some(a) => a,
                None => continue,
            };

            let seeds: Vec<String> = pda
                .seeds
                .iter()
                .map(|s| match s.kind.as_str() {
                    "const" => {
                        let val = s
                            .value
                            .as_ref()
                            .map(|v| String::from_utf8_lossy(v).to_string())
                            .unwrap_or_else(|| "?".to_string());
                        format!("\"{}\"", val)
                    }
                    "account" => s.path.as_deref().or(s.account.as_deref()).unwrap_or("?").to_string(),
                    "arg" => format!("arg({})", s.path.as_deref().unwrap_or("?")),
                    other => format!("{}(?)", other),
                })
                .collect();

            if let Some(account) = accounts.get_mut(mapped.account_index as usize) {
                account.pda_info = Some(PdaInfo { seeds_declared: seeds, bump: None, expected_address: None });
            }
        }
    }
}

fn parse_compute_budget(data: &[u8]) -> Option<(u32, u64)> {
    if data.is_empty() {
        return None;
    }
    let mut limit: u32 = 0;
    let mut price: u64 = 0;
    match data[0] {
        // 0: RequestUnitsDeprecated { units, additional_fee } — sets a CU limit.
        0 if data.len() >= 5 => limit = u32::from_le_bytes([data[1], data[2], data[3], data[4]]),
        // 1: RequestHeapFrame — heap size only, NOT a CU limit.
        // 2: SetComputeUnitLimit { units } — the modern CU limit instruction.
        2 if data.len() >= 5 => limit = u32::from_le_bytes([data[1], data[2], data[3], data[4]]),
        // 3: SetComputeUnitPrice { micro_lamports }.
        3 if data.len() >= 9 => {
            price = u64::from_le_bytes([data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8]]);
        }
        // 4: SetLoadedAccountsDataSizeLimit — not a CU limit.
        _ => {}
    }
    Some((limit, price))
}

pub(crate) fn estimate_cu_cost(ix: &DecodedInstruction) -> u32 {
    match ix.program_name.as_str() {
        "System Program" => match ix.instruction_name.as_deref() {
            Some("CreateAccount") | Some("CreateAccountWithSeed") => 15_000,
            Some("Allocate") | Some("AllocateWithSeed") => 3_000,
            Some("Assign") | Some("AssignWithSeed") => 1_000,
            Some("Transfer") => 1_000,
            _ => 2_000,
        },
        "Token Program" | "Token-2022 Program" => match ix.instruction_name.as_deref() {
            Some("InitializeMint") | Some("InitializeMint2") => 5_000,
            Some("InitializeAccount") | Some("InitializeAccount2") | Some("InitializeAccount3") => 5_000,
            Some("InitializeMultisig") | Some("InitializeMultisig2") => 5_000,
            Some("Transfer") | Some("TransferChecked") => 3_000,
            Some("MintTo") | Some("MintToChecked") => 3_000,
            Some("Burn") | Some("BurnChecked") => 3_000,
            Some("CloseAccount") => 3_000,
            Some("Approve") | Some("ApproveChecked") => 3_000,
            Some("SetAuthority") => 3_000,
            Some("FreezeAccount") | Some("ThawAccount") => 3_000,
            Some("ConfidentialTransfer") => 25_000,
            Some("InitializeTransferFeeConfig") => 15_000,
            _ => 5_000,
        },
        "Associated Token Program" => match ix.instruction_name.as_deref() {
            Some("Create") | Some("CreateIdempotent") => 15_000,
            _ => 5_000,
        },
        "Compute Budget" => 0,
        "Address Lookup Table" => 5_000,
        _ => 5_000,
    }
}

pub(crate) fn high_cu_threshold(cu_limit: u32) -> u32 {
    (cu_limit / 5).clamp(5_000, 10_000)
}

fn estimate_high_cu_instructions(instructions: &[DecodedInstruction], cu_limit: u32) -> Vec<u8> {
    let threshold = high_cu_threshold(cu_limit);
    instructions
        .iter()
        .filter_map(|ix| {
            let cost = estimate_cu_cost(ix);
            if cost >= threshold { Some(ix.index) } else { None }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        decode_raw_bytes, estimate_cu_cost, estimate_high_cu_instructions, high_cu_threshold, parse_compute_budget,
    };
    use crate::types::DecodedInstruction;

    fn cb(data: &[u8]) -> (u32, u64) {
        parse_compute_budget(data).unwrap_or((0, 0))
    }

    fn ix(program_name: &str, instruction_name: Option<&str>, index: u8) -> DecodedInstruction {
        DecodedInstruction {
            index,
            program_id: String::new(),
            program_name: program_name.to_string(),
            instruction_name: instruction_name.map(str::to_string),
            accounts: vec![],
            data: serde_json::Value::Null,
            raw_data_hex: String::new(),
            token_amount: None,
        }
    }

    #[test]
    fn request_units_deprecated_sets_limit() {
        // 0: RequestUnitsDeprecated { units: 200_000, additional_fee: 0 }
        let mut data = vec![0u8];
        data.extend_from_slice(&200_000u32.to_le_bytes());
        assert_eq!(cb(&data), (200_000, 0));
    }

    #[test]
    fn request_heap_frame_is_not_a_cu_limit() {
        // 1: RequestHeapFrame — must NOT be treated as a CU limit.
        let mut data = vec![1u8];
        data.extend_from_slice(&131_072u32.to_le_bytes());
        assert_eq!(cb(&data), (0, 0));
    }

    #[test]
    fn set_compute_unit_limit_sets_limit() {
        // 2: SetComputeUnitLimit { units: 1_400_000 } — the modern instruction.
        let mut data = vec![2u8];
        data.extend_from_slice(&1_400_000u32.to_le_bytes());
        assert_eq!(cb(&data), (1_400_000, 0));
    }

    #[test]
    fn set_compute_unit_price_sets_price() {
        // 3: SetComputeUnitPrice { micro_lamports: 123_456_789 }
        let mut data = vec![3u8];
        data.extend_from_slice(&123_456_789u64.to_le_bytes());
        assert_eq!(cb(&data), (0, 123_456_789));
    }

    #[test]
    fn loaded_accounts_size_limit_is_not_a_cu_limit() {
        // 4: SetLoadedAccountsDataSizeLimit — must not set limit or price.
        let mut data = vec![4u8];
        data.extend_from_slice(&64_512u32.to_le_bytes());
        assert_eq!(cb(&data), (0, 0));
    }

    #[test]
    fn limit_and_price_parse_together() {
        // A realistic modern fee-priority pair: limit 2 then price 3.
        let mut data = vec![3u8];
        data.extend_from_slice(&10_000u64.to_le_bytes());
        let (limit, price) = parse_compute_budget(&data).unwrap();
        assert_eq!(limit, 0);
        assert_eq!(price, 10_000);
    }

    #[test]
    fn system_transfer_estimated_at_one_k() {
        assert_eq!(estimate_cu_cost(&ix("System Program", Some("Transfer"), 0)), 1_000);
    }

    #[test]
    fn system_create_account_estimated_at_fifteen_k() {
        assert_eq!(estimate_cu_cost(&ix("System Program", Some("CreateAccount"), 0)), 15_000);
        assert_eq!(estimate_cu_cost(&ix("System Program", Some("CreateAccountWithSeed"), 0)), 15_000);
    }

    #[test]
    fn system_allocate_estimated_at_three_k() {
        assert_eq!(estimate_cu_cost(&ix("System Program", Some("Allocate"), 0)), 3_000);
        assert_eq!(estimate_cu_cost(&ix("System Program", Some("AllocateWithSeed"), 0)), 3_000);
    }

    #[test]
    fn system_assign_estimated_at_one_k() {
        assert_eq!(estimate_cu_cost(&ix("System Program", Some("Assign"), 0)), 1_000);
        assert_eq!(estimate_cu_cost(&ix("System Program", Some("AssignWithSeed"), 0)), 1_000);
    }

    #[test]
    fn system_unknown_instruction_estimated_at_two_k() {
        assert_eq!(estimate_cu_cost(&ix("System Program", Some("NonceInitialize"), 0)), 2_000);
    }

    #[test]
    fn token_operations_estimated_at_three_k() {
        for program in ["Token Program", "Token-2022 Program"] {
            for name in [
                "Transfer",
                "TransferChecked",
                "MintTo",
                "MintToChecked",
                "Burn",
                "BurnChecked",
                "CloseAccount",
                "Approve",
                "ApproveChecked",
                "SetAuthority",
                "FreezeAccount",
                "ThawAccount",
            ] {
                assert_eq!(estimate_cu_cost(&ix(program, Some(name), 0)), 3_000, "{program} {name}");
            }
        }
    }

    #[test]
    fn token_initialize_estimated_at_five_k() {
        for program in ["Token Program", "Token-2022 Program"] {
            for name in [
                "InitializeMint",
                "InitializeMint2",
                "InitializeAccount",
                "InitializeAccount2",
                "InitializeAccount3",
                "InitializeMultisig",
                "InitializeMultisig2",
            ] {
                assert_eq!(estimate_cu_cost(&ix(program, Some(name), 0)), 5_000, "{program} {name}");
            }
        }
    }

    #[test]
    fn token_confidential_transfer_estimated_at_twenty_five_k() {
        for program in ["Token Program", "Token-2022 Program"] {
            assert_eq!(estimate_cu_cost(&ix(program, Some("ConfidentialTransfer"), 0)), 25_000);
        }
    }

    #[test]
    fn token_transfer_fee_config_estimated_at_fifteen_k() {
        assert_eq!(estimate_cu_cost(&ix("Token-2022 Program", Some("InitializeTransferFeeConfig"), 0)), 15_000);
    }

    #[test]
    fn compute_budget_estimated_at_zero() {
        assert_eq!(estimate_cu_cost(&ix("Compute Budget", Some("SetComputeUnitLimit"), 0)), 0);
    }

    #[test]
    fn unknown_program_estimated_at_five_k() {
        assert_eq!(estimate_cu_cost(&ix("Some Other Program", Some("Whatever"), 0)), 5_000);
        assert_eq!(estimate_cu_cost(&ix("Associated Token Program", Some("Unknown"), 0)), 5_000);
        assert_eq!(estimate_cu_cost(&ix("Address Lookup Table", Some("Extend"), 0)), 5_000);
    }

    #[test]
    fn high_cu_flags_create_account_but_not_system_transfer() {
        let instructions =
            vec![ix("System Program", Some("CreateAccount"), 0), ix("System Program", Some("Transfer"), 1)];
        assert_eq!(estimate_high_cu_instructions(&instructions, 200_000), vec![0]);
    }

    #[test]
    fn high_cu_threshold_formula() {
        assert_eq!(high_cu_threshold(200_000), 10_000);
        assert_eq!(high_cu_threshold(20_000), 5_000);
        assert_eq!(high_cu_threshold(1_400_000), 10_000);
    }

    /// Regression: the writable-header derivation must match the runtime rule
    /// (solana-message is_writable_index) when the message has a readonly
    /// signer. The old code inverted signer writability and shifted the
    /// non-signer window, mislabeling every account in such messages.
    #[test]
    fn writable_header_matches_runtime_with_readonly_signer() {
        use solana_sdk::{
            hash::Hash,
            instruction::{AccountMeta, Instruction},
            message::{VersionedMessage, legacy},
            pubkey::Pubkey,
            signature::Keypair,
            signer::Signer,
            transaction::VersionedTransaction,
        };

        let program_id = Pubkey::new_from_array([1u8; 32]);
        let payer = Keypair::new();
        let owner = Pubkey::new_unique();
        let vault = Pubkey::new_unique();
        let group = Pubkey::new_unique();
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(group, false),
                AccountMeta::new_readonly(owner, true),
                AccountMeta::new(vault, false),
            ],
            data: vec![0x24],
        };
        let message = VersionedMessage::Legacy(legacy::Message::new_with_blockhash(
            &[ix],
            Some(&payer.pubkey()),
            &Hash::new_from_array([7u8; 32]),
        ));
        let tx = VersionedTransaction { signatures: vec![payer.sign_message(&message.serialize())], message };
        let report = decode_raw_bytes(&bincode::serialize(&tx).unwrap(), None).expect("decode");

        let by_key = |k: &str| report.accounts.iter().find(|a| a.pubkey == k).expect("account in message");
        assert!(by_key(&payer.pubkey().to_string()).is_writable, "payer must be writable");
        assert!(by_key(&vault.to_string()).is_writable, "vault (declared writable) must be writable");
        assert!(!by_key(&owner.to_string()).is_writable, "readonly signer must not be writable");
        assert!(!by_key(&group.to_string()).is_writable, "readonly account must not be writable");
        assert!(!by_key(&program_id.to_string()).is_writable, "program id must not be writable");
    }
}
