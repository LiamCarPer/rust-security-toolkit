use anyhow::{Context, Result};
use solana_sdk::{message::VersionedMessage, transaction::VersionedTransaction};

use crate::types::{
    ADDRESS_LOOKUP_TABLE_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, AccountInfo, AltResolution,
    COMPUTE_BUDGET_PROGRAM_ID, ComputeBudgetInfo, DecodedInstruction, IdlJson, MappedAccount, PdaInfo, ResolvedAccount,
    SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, TransactionReport,
};

use crate::{anchor_decoder, encoding, instruction_decoder, internal_parser};

pub use anchor_decoder::compute_anchor_discriminator;
pub use encoding::detect_encoding;
pub use internal_parser::validate_decoding;

/// Decode a transaction from pre-decoded raw bytes and produce a structured report.
/// Use this when the caller has already handled encoding detection to avoid redundant work.
pub fn decode_raw_bytes(raw_bytes: &[u8], idl: Option<&IdlJson>) -> Result<TransactionReport> {
    let tx: VersionedTransaction =
        bincode::deserialize(raw_bytes).context("Failed to deserialize transaction via bincode (solana-sdk format)")?;

    decode_versioned_tx(tx, idl)
}

/// Decode a transaction from any supported encoding and produce a structured report.
pub fn decode_transaction(input: &str, idl: Option<&IdlJson>) -> Result<TransactionReport> {
    let encoding = detect_encoding(input);
    let raw_bytes = encoding::decode_from_encoding(input, encoding)?;
    decode_raw_bytes(&raw_bytes, idl)
}

fn decode_versioned_tx(tx: VersionedTransaction, idl: Option<&IdlJson>) -> Result<TransactionReport> {
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
        let is_writable = if is_signer {
            i >= num_readonly_signed
        } else {
            let writable_signer_end = num_required_signatures.saturating_sub(num_readonly_signed);
            let writable_unsigned_end =
                writable_signer_end + (static_len - num_required_signatures - num_readonly_unsigned);
            i >= writable_signer_end && i < writable_unsigned_end
        };

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
                });
            }
            for idx in &alt.readonly_indexes {
                let global_idx = static_len + alt_resolved_len;
                alt_resolved_len += 1;
                resolved.push(ResolvedAccount {
                    index_in_tx: global_idx as u8,
                    pubkey: format!("<alt_index_{}>", idx),
                    is_writable: false,
                });
            }

            address_lookup_tables
                .push(AltResolution { table_address: alt.account_key.to_string(), resolved_accounts: resolved });
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
            instruction_decoder::decode_instruction_data(program_id.as_str(), &compiled_ix.data, idl);

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
        });
    }

    let is_reordered = cb_positions.iter().any(|&p| p >= cb_positions.len());

    if !cb_positions.is_empty() || has_explicit_cu_limit {
        compute_budget_info = Some(ComputeBudgetInfo {
            compute_unit_limit: cu_limit,
            compute_unit_price: cu_price,
            compute_unit_limit_set: has_explicit_cu_limit,
            compute_budget_positions: cb_positions,
            is_reordered,
            high_cu_instructions: Vec::new(),
        });

        let high_cu = estimate_high_cu_instructions(&instructions, cu_limit);
        if let Some(ref mut cb) = compute_budget_info {
            cb.high_cu_instructions = high_cu;
        }
    }

    if let Some(idl) = idl {
        annotate_pda_accounts(&mut accounts, &instructions, idl);
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
    })
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
        0 if data.len() >= 5 => limit = u32::from_le_bytes([data[1], data[2], data[3], data[4]]),
        1 if data.len() >= 5 => limit = u32::from_le_bytes([data[1], data[2], data[3], data[4]]),
        3 if data.len() >= 9 => {
            price = u64::from_le_bytes([data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8]]);
        }
        _ => {}
    }
    Some((limit, price))
}

fn estimate_cu_cost(ix: &DecodedInstruction) -> u32 {
    match ix.program_name.as_str() {
        "System Program" => match ix.instruction_name.as_deref() {
            Some("CreateAccount") | Some("CreateAccountWithSeed") => 15_000,
            Some("Allocate") | Some("AllocateWithSeed") => 5_000,
            Some("Assign") | Some("AssignWithSeed") => 2_000,
            Some("Transfer") => 1_500,
            _ => 3_000,
        },
        "Token Program" | "Token-2022 Program" => match ix.instruction_name.as_deref() {
            Some("InitializeMint") | Some("InitializeMint2") => 15_000,
            Some("InitializeAccount") | Some("InitializeAccount2") | Some("InitializeAccount3") => 15_000,
            Some("InitializeMultisig") | Some("InitializeMultisig2") => 15_000,
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

fn estimate_high_cu_instructions(instructions: &[DecodedInstruction], cu_limit: u32) -> Vec<u8> {
    let threshold = (cu_limit / 5).clamp(5000, 10_000);
    instructions
        .iter()
        .filter_map(|ix| {
            let cost = estimate_cu_cost(ix);
            if cost >= threshold { Some(ix.index) } else { None }
        })
        .collect()
}
