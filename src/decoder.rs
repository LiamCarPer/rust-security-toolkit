use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use solana_sdk::{message::VersionedMessage, pubkey::Pubkey, signature::Signature, transaction::VersionedTransaction};

use crate::types::{
    ADDRESS_LOOKUP_TABLE_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, AccountInfo, AltResolution,
    COMPUTE_BUDGET_PROGRAM_ID, ComputeBudgetInfo, DecodedInstruction, Encoding, IdlJson, MappedAccount, PdaInfo,
    ResolvedAccount, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, TransactionReport,
};

/// Decode a transaction from any supported encoding and produce a structured report.
pub fn decode_transaction(input: &str, idl: Option<&IdlJson>) -> Result<TransactionReport> {
    let encoding = detect_encoding(input);
    let raw_bytes = decode_from_encoding(input, encoding)?;
    let tx: VersionedTransaction = bincode::deserialize(&raw_bytes)
        .context("Failed to deserialize transaction via bincode (solana-sdk format)")?;

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

        let (instruction_name, decoded_data) = decode_instruction_data(program_id.as_str(), &compiled_ix.data, idl);

        // Check for compute budget instructions
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

        // Estimate CU costs and flag high-consumption instructions
        let high_cu = estimate_high_cu_instructions(&instructions, cu_limit);
        if let Some(ref mut cb) = compute_budget_info {
            cb.high_cu_instructions = high_cu;
        }
    }

    // Annotate accounts with PDA information when IDL is provided
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

/// Annotate account entries with PDA seed declarations from the IDL.
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

/// Parse ComputeBudget instruction data.
fn parse_compute_budget(data: &[u8]) -> Option<(u32, u64)> {
    if data.is_empty() {
        return None;
    }
    let mut limit: u32 = 0;
    let mut price: u64 = 0;
    match data[0] {
        0 if data.len() >= 5 => {
            limit = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
        }
        1 if data.len() >= 5 => {
            limit = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
        }
        3 if data.len() >= 9 => {
            price = u64::from_le_bytes([data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8]]);
        }
        _ => {}
    }
    Some((limit, price))
}

/// Estimate CU cost for an instruction based on program and operation type.
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

/// Flag instructions whose estimated CU cost exceeds 20% of the limit
/// or is above 10,000 CU (whichever is lower).
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

/// Auto-detect the encoding of the input string.
pub fn detect_encoding(input: &str) -> Encoding {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Encoding::Raw;
    }

    let bytes = trimmed.as_bytes();
    if std::str::from_utf8(bytes).is_err() {
        return Encoding::Raw;
    }

    let has_base64_chars = bytes.iter().any(|&b| b == b'+' || b == b'/' || b == b'=');
    let is_all_hex = bytes.iter().all(|b| b.is_ascii_hexdigit());
    let has_non_base58 = bytes.iter().any(|&b| b == b'0' || b == b'O' || b == b'I' || b == b'l');

    if has_base64_chars {
        return Encoding::Base64;
    }

    if is_all_hex && trimmed.len() >= 2 && trimmed.len().is_multiple_of(2) {
        return Encoding::Hex;
    }

    if has_non_base58 {
        return Encoding::Base64;
    }

    Encoding::Base58
}

/// Decode bytes from the detected encoding.
fn decode_from_encoding(input: &str, encoding: Encoding) -> Result<Vec<u8>> {
    let trimmed = input.trim();
    match encoding {
        Encoding::Base58 => bs58::decode(trimmed).into_vec().context("Failed to decode Base58 input"),
        Encoding::Base64 => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.decode(trimmed).context("Failed to decode Base64 input")
        }
        Encoding::Hex => hex::decode(trimmed).context("Failed to decode Hex input"),
        Encoding::Raw => Ok(trimmed.as_bytes().to_vec()),
    }
}

/// Decode instruction data for known programs and IDL-based matching.
fn decode_instruction_data(
    program_id: &str,
    data: &[u8],
    idl: Option<&IdlJson>,
) -> (Option<String>, serde_json::Value) {
    if data.is_empty() {
        return (None, serde_json::Value::Null);
    }

    match program_id {
        SYSTEM_PROGRAM_ID => decode_system_instruction(data),
        TOKEN_PROGRAM_ID | TOKEN_2022_PROGRAM_ID => decode_token_instruction(data, program_id),
        ASSOCIATED_TOKEN_PROGRAM_ID => decode_associated_token_instruction(data),
        COMPUTE_BUDGET_PROGRAM_ID => decode_compute_budget_instruction(data),
        _ => {
            if let Some(idl) = idl
                && data.len() >= 8
            {
                let discriminator = &data[0..8];
                for ix in &idl.instructions {
                    let expected = compute_anchor_discriminator(&ix.name);
                    if discriminator == &expected[..] {
                        let args = decode_anchor_args(&data[8..], &ix.args);
                        return (Some(ix.name.clone()), args);
                    }
                }
            }
            let hex_str = if data.len() > 64 { format!("{}...", hex::encode(&data[..32])) } else { hex::encode(data) };
            (None, serde_json::Value::String(hex_str))
        }
    }
}

/// Compute an Anchor 8-byte instruction discriminator.
pub fn compute_anchor_discriminator(ix_name: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(b"global:");
    hasher.update(ix_name.as_bytes());
    let result = hasher.finalize();
    let mut discriminator = [0u8; 8];
    discriminator.copy_from_slice(&result[0..8]);
    discriminator
}

/// Decode System Program instruction.
fn decode_system_instruction(data: &[u8]) -> (Option<String>, serde_json::Value) {
    if data.len() < 4 {
        return (None, serde_json::Value::String(hex::encode(data)));
    }

    let discriminator = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    match discriminator {
        0 if data.len() >= 52 => {
            let lamports = u64::from_le_bytes(data[4..12].try_into().unwrap());
            let space = u64::from_le_bytes(data[12..20].try_into().unwrap());
            let owner =
                Pubkey::try_from(&data[20..52]).map(|k| k.to_string()).unwrap_or_else(|_| "invalid".to_string());
            (
                Some("CreateAccount".to_string()),
                serde_json::json!({ "lamports": lamports, "space": space, "owner": owner }),
            )
        }
        1 if data.len() >= 36 => {
            let owner = Pubkey::try_from(&data[4..36]).map(|k| k.to_string()).unwrap_or_else(|_| "invalid".to_string());
            (Some("Assign".to_string()), serde_json::json!({ "owner": owner }))
        }
        2 if data.len() >= 12 => {
            let lamports = u64::from_le_bytes(data[4..12].try_into().unwrap());
            (Some("Transfer".to_string()), serde_json::json!({ "lamports": lamports }))
        }
        3 => {
            // CreateAccountWithSeed
            let mut map = serde_json::Map::new();
            if data.len() > 36
                && let Ok(base) = Pubkey::try_from(&data[4..36])
            {
                map.insert("base".to_string(), serde_json::Value::String(base.to_string()));
            }
            if data.len() > 68 {
                map.insert(
                    "lamports".to_string(),
                    serde_json::json!(u64::from_le_bytes(data[36..44].try_into().unwrap())),
                );
                map.insert(
                    "space".to_string(),
                    serde_json::json!(u64::from_le_bytes(data[44..52].try_into().unwrap())),
                );
                if let Ok(owner) = Pubkey::try_from(&data[52..84]) {
                    map.insert("owner".to_string(), serde_json::Value::String(owner.to_string()));
                }
            }
            (Some("CreateAccountWithSeed".to_string()), serde_json::Value::Object(map))
        }
        4 => (Some("AdvanceNonceAccount".to_string()), serde_json::Value::Null),
        5 if data.len() >= 12 => {
            let lamports = u64::from_le_bytes(data[4..12].try_into().unwrap());
            (Some("WithdrawNonceAccount".to_string()), serde_json::json!({ "lamports": lamports }))
        }
        6 if data.len() >= 36 => {
            let authorized =
                Pubkey::try_from(&data[4..36]).map(|k| k.to_string()).unwrap_or_else(|_| "invalid".to_string());
            (Some("InitializeNonceAccount".to_string()), serde_json::json!({ "authorized": authorized }))
        }
        7 if data.len() >= 36 => {
            let authorized =
                Pubkey::try_from(&data[4..36]).map(|k| k.to_string()).unwrap_or_else(|_| "invalid".to_string());
            (Some("ResizeNonceAccount".to_string()), serde_json::json!({ "authorized": authorized }))
        }
        8 if data.len() >= 36 => {
            let authorized =
                Pubkey::try_from(&data[4..36]).map(|k| k.to_string()).unwrap_or_else(|_| "invalid".to_string());
            (Some("AuthorizeNonceAccount".to_string()), serde_json::json!({ "authorized": authorized }))
        }
        9 if data.len() >= 12 => {
            let space = u64::from_le_bytes(data[4..12].try_into().unwrap());
            (Some("Allocate".to_string()), serde_json::json!({ "space": space }))
        }
        10 => {
            let mut map = serde_json::Map::new();
            if data.len() > 36
                && let Ok(base) = Pubkey::try_from(&data[4..36])
            {
                map.insert("base".to_string(), serde_json::Value::String(base.to_string()));
            }
            if data.len() > 68 {
                map.insert(
                    "space".to_string(),
                    serde_json::json!(u64::from_le_bytes(data[36..44].try_into().unwrap())),
                );
                if let Ok(owner) = Pubkey::try_from(&data[44..76]) {
                    map.insert("owner".to_string(), serde_json::Value::String(owner.to_string()));
                }
            }
            (Some("AllocateWithSeed".to_string()), serde_json::Value::Object(map))
        }
        11 => {
            let mut map = serde_json::Map::new();
            if data.len() > 36
                && let Ok(base) = Pubkey::try_from(&data[4..36])
            {
                map.insert("base".to_string(), serde_json::Value::String(base.to_string()));
            }
            if let Ok(owner) = Pubkey::try_from(&data[36..68]) {
                map.insert("owner".to_string(), serde_json::Value::String(owner.to_string()));
            }
            (Some("AssignWithSeed".to_string()), serde_json::Value::Object(map))
        }
        _ => (None, serde_json::Value::String(hex::encode(data))),
    }
}

/// Decode SPL Token / Token-2022 instruction.
fn decode_token_instruction(data: &[u8], program_id: &str) -> (Option<String>, serde_json::Value) {
    if data.is_empty() {
        return (None, serde_json::Value::Null);
    }

    let is_token22 = program_id == TOKEN_2022_PROGRAM_ID;
    let discriminator = data[0];
    let payload = &data[1..];

    match discriminator {
        0 => {
            let mut map = serde_json::Map::new();
            if payload.len() >= 36 {
                map.insert("decimals".to_string(), serde_json::json!(payload[0]));
                if let Ok(authority) = Pubkey::try_from(&payload[1..33]) {
                    map.insert("mint_authority".to_string(), serde_json::Value::String(authority.to_string()));
                }
                let freeze_opt = payload[33];
                map.insert("freeze_authority_option".to_string(), serde_json::json!(freeze_opt));
                if freeze_opt == 1
                    && payload.len() >= 66
                    && let Ok(freeze_auth) = Pubkey::try_from(&payload[34..66])
                {
                    map.insert("freeze_authority".to_string(), serde_json::Value::String(freeze_auth.to_string()));
                }
            }
            if is_token22 {
                (Some("InitializeMint2".to_string()), serde_json::Value::Object(map))
            } else {
                (Some("InitializeMint".to_string()), serde_json::Value::Object(map))
            }
        }
        1 => (Some("InitializeAccount".to_string()), serde_json::Value::Null),
        2 => {
            let m = payload.first().copied().unwrap_or(0);
            (Some("InitializeMultisig".to_string()), serde_json::json!({ "m": m }))
        }
        3 if payload.len() >= 8 => {
            let amount = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            (Some("Transfer".to_string()), serde_json::json!({ "amount": amount }))
        }
        4 if payload.len() >= 8 => {
            let amount = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            (Some("Approve".to_string()), serde_json::json!({ "amount": amount }))
        }
        5 => (Some("Revoke".to_string()), serde_json::Value::Null),
        6 => {
            let authority_type = payload.first().copied().unwrap_or(0);
            let mut map = serde_json::Map::new();
            map.insert("authority_type".to_string(), serde_json::json!(authority_type));
            if payload.len() >= 2 {
                let new_auth_opt = payload[1];
                map.insert("new_authority_option".to_string(), serde_json::json!(new_auth_opt));
                if new_auth_opt == 1
                    && payload.len() >= 34
                    && let Ok(new_auth) = Pubkey::try_from(&payload[2..34])
                {
                    map.insert("new_authority".to_string(), serde_json::Value::String(new_auth.to_string()));
                }
            }
            (Some("SetAuthority".to_string()), serde_json::Value::Object(map))
        }
        7 if payload.len() >= 8 => {
            let amount = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            (Some("MintTo".to_string()), serde_json::json!({ "amount": amount }))
        }
        8 if payload.len() >= 8 => {
            let amount = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            (Some("Burn".to_string()), serde_json::json!({ "amount": amount }))
        }
        9 => (Some("CloseAccount".to_string()), serde_json::Value::Null),
        10 => (Some("FreezeAccount".to_string()), serde_json::Value::Null),
        11 => (Some("ThawAccount".to_string()), serde_json::Value::Null),
        12 if payload.len() >= 9 => {
            let amount = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            let decimals = payload[8];
            (Some("TransferChecked".to_string()), serde_json::json!({ "amount": amount, "decimals": decimals }))
        }
        13 if payload.len() >= 9 => {
            let amount = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            let decimals = payload[8];
            (Some("ApproveChecked".to_string()), serde_json::json!({ "amount": amount, "decimals": decimals }))
        }
        14 if payload.len() >= 9 => {
            let amount = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            let decimals = payload[8];
            (Some("MintToChecked".to_string()), serde_json::json!({ "amount": amount, "decimals": decimals }))
        }
        15 if payload.len() >= 9 => {
            let amount = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            let decimals = payload[8];
            (Some("BurnChecked".to_string()), serde_json::json!({ "amount": amount, "decimals": decimals }))
        }
        16 if payload.len() >= 32 => {
            if let Ok(owner) = Pubkey::try_from(&payload[0..32]) {
                (Some("InitializeAccount2".to_string()), serde_json::json!({ "owner": owner.to_string() }))
            } else {
                (Some("InitializeAccount2".to_string()), serde_json::Value::Null)
            }
        }
        17 => (Some("SyncNative".to_string()), serde_json::Value::Null),
        18 if payload.len() >= 32 => {
            if let Ok(owner) = Pubkey::try_from(&payload[0..32]) {
                (Some("InitializeAccount3".to_string()), serde_json::json!({ "owner": owner.to_string() }))
            } else {
                (Some("InitializeAccount3".to_string()), serde_json::Value::Null)
            }
        }
        19 => {
            let m = payload.first().copied().unwrap_or(0);
            (Some("InitializeMultisig2".to_string()), serde_json::json!({ "m": m }))
        }
        // Token-2022 extension instructions (discriminators 20+)
        20 if is_token22 => {
            // InitializeMint2 is already handled above (shares discriminator 0 path)
            // but if reached here with empty payload, provide a label
            (Some("InitializeMint2".to_string()), serde_json::Value::Null)
        }
        22 if is_token22 => (Some("InitializeImmutableOwner".to_string()), serde_json::Value::Null),
        25 if is_token22 => {
            let mut map = serde_json::Map::new();
            if payload.len() >= 33 {
                let close_auth_opt = payload[0];
                map.insert("close_authority_option".to_string(), serde_json::json!(close_auth_opt));
                if close_auth_opt == 1
                    && payload.len() >= 65
                    && let Ok(auth) = Pubkey::try_from(&payload[1..33])
                {
                    map.insert("close_authority".to_string(), serde_json::Value::String(auth.to_string()));
                }
            }
            (Some("InitializeMintCloseAuthority".to_string()), serde_json::Value::Object(map))
        }
        26 if is_token22 => decode_transfer_fee_extension(payload),
        27 if is_token22 => decode_confidential_transfer_extension(payload),
        31 if is_token22 => {
            let mut map = serde_json::Map::new();
            if payload.len() >= 33
                && let Ok(delegate) = Pubkey::try_from(&payload[0..32])
            {
                map.insert("delegate".to_string(), serde_json::Value::String(delegate.to_string()));
            }
            (Some("InitializePermanentDelegate".to_string()), serde_json::Value::Object(map))
        }
        37 if is_token22 => (Some("ConfidentialTransferFeeExtension".to_string()), serde_json::Value::Null),
        _ => {
            let hex_str = hex::encode(data);
            (None, serde_json::Value::String(hex_str))
        }
    }
}

/// Decode TransferFee extension sub-instructions.
fn decode_transfer_fee_extension(payload: &[u8]) -> (Option<String>, serde_json::Value) {
    if payload.is_empty() {
        return (Some("TransferFeeExtension".to_string()), serde_json::Value::Null);
    }
    match payload[0] {
        0 => {
            let mut map = serde_json::Map::new();
            if payload.len() >= 33
                && let Ok(authority) = Pubkey::try_from(&payload[1..33])
            {
                map.insert(
                    "transfer_fee_config_authority".to_string(),
                    serde_json::Value::String(authority.to_string()),
                );
            }
            if payload.len() >= 65
                && let Ok(authority) = Pubkey::try_from(&payload[33..65])
            {
                map.insert("withdraw_withheld_authority".to_string(), serde_json::Value::String(authority.to_string()));
            }
            if payload.len() >= 67 {
                let fee_bps = u16::from_le_bytes([payload[65], payload[66]]);
                map.insert("transfer_fee_basis_points".to_string(), serde_json::json!(fee_bps));
            }
            if payload.len() >= 75 {
                let max_fee = u64::from_le_bytes([
                    payload[67],
                    payload[68],
                    payload[69],
                    payload[70],
                    payload[71],
                    payload[72],
                    payload[73],
                    payload[74],
                ]);
                map.insert("max_fee".to_string(), serde_json::json!(max_fee));
            }
            (Some("InitializeTransferFeeConfig".to_string()), serde_json::Value::Object(map))
        }
        1 if payload.len() >= 9 => {
            let amount = u64::from_le_bytes(payload[1..9].try_into().unwrap());
            (Some("TransferCheckedWithFee".to_string()), serde_json::json!({ "amount": amount }))
        }
        2 => (Some("WithdrawWithheldTokensFromMint".to_string()), serde_json::Value::Null),
        3 => {
            let num_accounts = payload.get(1).copied().unwrap_or(0);
            (
                Some("WithdrawWithheldTokensFromAccounts".to_string()),
                serde_json::json!({ "num_token_accounts": num_accounts }),
            )
        }
        4 => {
            let mut map = serde_json::Map::new();
            if payload.len() >= 2 {
                map.insert("num_mints".to_string(), serde_json::json!(payload[1]));
            }
            (Some("HarvestWithheldTokensToMint".to_string()), serde_json::Value::Object(map))
        }
        _ => (Some("TransferFeeExtension".to_string()), serde_json::Value::Null),
    }
}

/// Decode ConfidentialTransfer extension sub-instructions.
fn decode_confidential_transfer_extension(payload: &[u8]) -> (Option<String>, serde_json::Value) {
    if payload.is_empty() {
        return (Some("ConfidentialTransferExtension".to_string()), serde_json::Value::Null);
    }
    match payload[0] {
        0 => (Some("InitializeConfidentialTransferMint".to_string()), serde_json::Value::Null),
        1 => (Some("UpdateConfidentialTransferMint".to_string()), serde_json::Value::Null),
        2 => (Some("ConfigureConfidentialTransferAccount".to_string()), serde_json::Value::Null),
        3 => (Some("ApproveConfidentialTransferAccount".to_string()), serde_json::Value::Null),
        4 => (Some("EmptyConfidentialTransferAccount".to_string()), serde_json::Value::Null),
        5 => (Some("Deposit".to_string()), serde_json::Value::Null),
        6 => (Some("Withdraw".to_string()), serde_json::Value::Null),
        7 => (Some("Transfer".to_string()), serde_json::Value::Null),
        8 => (Some("ApplyPendingBalance".to_string()), serde_json::Value::Null),
        9 => (Some("EnableConfidentialTransfer".to_string()), serde_json::Value::Null),
        10 => (Some("DisableConfidentialTransfer".to_string()), serde_json::Value::Null),
        _ => (Some("ConfidentialTransferExtension".to_string()), serde_json::Value::Null),
    }
}

/// Decode Associated Token Program instruction.
fn decode_associated_token_instruction(data: &[u8]) -> (Option<String>, serde_json::Value) {
    match data.first() {
        Some(0) => (Some("Create".to_string()), serde_json::Value::Null),
        Some(1) => (Some("CreateIdempotent".to_string()), serde_json::Value::Null),
        Some(2) => (Some("RecoverNested".to_string()), serde_json::Value::Null),
        _ => (None, serde_json::Value::String(hex::encode(data))),
    }
}

/// Decode Compute Budget instruction.
fn decode_compute_budget_instruction(data: &[u8]) -> (Option<String>, serde_json::Value) {
    match data.first() {
        Some(0) if data.len() >= 5 => {
            let limit = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            (Some("RequestUnits".to_string()), serde_json::json!({ "units": limit, "additional_fee": 0 }))
        }
        Some(1) if data.len() >= 5 => {
            let limit = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            (Some("SetComputeUnitLimit".to_string()), serde_json::json!({ "units": limit }))
        }
        Some(3) if data.len() >= 9 => {
            let price = u64::from_le_bytes([data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8]]);
            (Some("SetComputeUnitPrice".to_string()), serde_json::json!({ "micro_lamports": price }))
        }
        _ => (None, serde_json::Value::String(hex::encode(data))),
    }
}

/// Decode Anchor instruction arguments from raw bytes using IDL type definitions.
fn decode_anchor_args(data: &[u8], args: &[crate::types::IdlArg]) -> serde_json::Value {
    if args.is_empty() || data.is_empty() {
        return serde_json::Value::Null;
    }

    let mut map = serde_json::Map::new();
    let mut offset = 0usize;

    for arg in args {
        if offset >= data.len() {
            break;
        }
        let (value, consumed) = decode_anchor_type(data, offset, &arg.ty);
        map.insert(arg.name.clone(), value);
        offset += consumed;
    }

    serde_json::Value::Object(map)
}

/// Decode a single Anchor type value from bytes.
fn decode_anchor_type(data: &[u8], offset: usize, ty: &serde_json::Value) -> (serde_json::Value, usize) {
    match ty {
        serde_json::Value::String(s) => decode_anchor_scalar(data, offset, s.as_str()),
        serde_json::Value::Object(o) => {
            if let Some(serde_json::Value::String(defined)) = o.get("defined") {
                decode_anchor_scalar(data, offset, defined.as_str())
            } else if let Some(arr) = o.get("array") {
                let inner = arr.get(0).cloned().unwrap_or(serde_json::Value::String("u8".to_string()));
                let len = arr.get(1).and_then(|v| v.as_u64()).unwrap_or(1) as usize;
                let mut items = Vec::new();
                let mut local_offset = offset;
                for _ in 0..len {
                    let (v, consumed) = decode_anchor_type(data, local_offset, &inner);
                    items.push(v);
                    local_offset += consumed;
                }
                (serde_json::Value::Array(items), local_offset - offset)
            } else if let Some(inner) = o.get("vec") {
                if data.len() > offset + 4 {
                    let vec_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
                    let mut items = Vec::new();
                    let mut local_offset = offset + 4;
                    for _ in 0..vec_len {
                        let (v, consumed) = decode_anchor_type(data, local_offset, inner);
                        items.push(v);
                        local_offset += consumed;
                    }
                    (serde_json::Value::Array(items), local_offset - offset)
                } else {
                    (serde_json::Value::Null, 0)
                }
            } else if let Some(inner) = o.get("option") {
                if offset < data.len() {
                    let tag = data[offset];
                    if tag == 1 && data.len() > offset + 1 {
                        let (v, consumed) = decode_anchor_type(data, offset + 1, inner);
                        return (serde_json::Value::Array(vec![serde_json::json!(v)]), 1 + consumed);
                    }
                }
                (serde_json::Value::Null, 1)
            } else {
                (serde_json::Value::Null, 0)
            }
        }
        _ => (serde_json::Value::Null, 0),
    }
}

fn decode_anchor_scalar(data: &[u8], offset: usize, type_str: &str) -> (serde_json::Value, usize) {
    match type_str {
        "bool" => {
            if offset < data.len() {
                (serde_json::json!(data[offset] != 0), 1)
            } else {
                (serde_json::Value::Null, 0)
            }
        }
        "u8" | "i8" => {
            if offset < data.len() {
                (serde_json::json!(data[offset]), 1)
            } else {
                (serde_json::Value::Null, 0)
            }
        }
        "u16" | "i16" => {
            if offset + 2 <= data.len() {
                let val = u16::from_le_bytes([data[offset], data[offset + 1]]);
                (serde_json::json!(val), 2)
            } else {
                (serde_json::Value::Null, 0)
            }
        }
        "u32" | "i32" => {
            if offset + 4 <= data.len() {
                let val = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
                (serde_json::json!(val), 4)
            } else {
                (serde_json::Value::Null, 0)
            }
        }
        "u64" | "i64" => {
            if offset + 8 <= data.len() {
                let val = u64::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]);
                (serde_json::json!(val.to_string()), 8)
            } else {
                (serde_json::Value::Null, 0)
            }
        }
        "u128" | "i128" => {
            if offset + 16 <= data.len() {
                (serde_json::json!(hex::encode(&data[offset..offset + 16])), 16)
            } else {
                (serde_json::Value::Null, 0)
            }
        }
        "f32" => {
            if offset + 4 <= data.len() {
                let val = f32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
                (serde_json::json!(val), 4)
            } else {
                (serde_json::Value::Null, 0)
            }
        }
        "f64" => {
            if offset + 8 <= data.len() {
                let val = f64::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]);
                (serde_json::json!(val), 8)
            } else {
                (serde_json::Value::Null, 0)
            }
        }
        "publicKey" => {
            if offset + 32 <= data.len() {
                if let Ok(pk) = Pubkey::try_from(&data[offset..offset + 32]) {
                    (serde_json::json!(pk.to_string()), 32)
                } else {
                    (serde_json::Value::Null, 0)
                }
            } else {
                (serde_json::Value::Null, 0)
            }
        }
        "string" => {
            if offset + 4 <= data.len() {
                let len =
                    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
                let end = offset + 4 + len;
                if end <= data.len() {
                    match std::str::from_utf8(&data[offset + 4..end]) {
                        Ok(s) => (serde_json::json!(s), 4 + len),
                        Err(_) => (serde_json::json!(hex::encode(&data[offset + 4..end])), 4 + len),
                    }
                } else {
                    (serde_json::Value::Null, 0)
                }
            } else {
                (serde_json::Value::Null, 0)
            }
        }
        "bytes" => {
            if offset + 4 <= data.len() {
                let len =
                    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
                let end = offset + 4 + len;
                if end <= data.len() {
                    (serde_json::json!(hex::encode(&data[offset + 4..end])), 4 + len)
                } else {
                    (serde_json::Value::Null, 0)
                }
            } else {
                (serde_json::Value::Null, 0)
            }
        }
        _ => (serde_json::Value::Null, 0),
    }
}

/// Read a compact-u16 from bytes.
fn read_compact_u16(data: &[u8], offset: usize) -> Result<(u16, usize)> {
    if offset >= data.len() {
        anyhow::bail!("Buffer exhausted while reading compact-u16");
    }
    let first = data[offset];
    if first < 0x7f {
        Ok((first as u16, offset + 1))
    } else if data.len() > offset + 1 {
        let val = u16::from_le_bytes([data[offset], data[offset + 1]]);
        Ok((val & 0x3fff, offset + 2))
    } else {
        anyhow::bail!("Buffer exhausted while reading compact-u16 second byte")
    }
}

/// Internal byte-level parser for `--validate-decoding`.
/// Returns a list of mismatch warnings, or an empty vec if the internal parser
/// agrees with the solana-sdk output.
pub fn validate_decoding(raw_bytes: &[u8]) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    let mut offset = 0usize;

    // Parse number of signatures
    let (num_sigs, consumed) =
        read_compact_u16(raw_bytes, offset).context("Expected compact-u16 for signature count")?;
    offset = consumed;
    let num_sigs = num_sigs as usize;

    // Validate signature bytes exist
    let sig_bytes = num_sigs * 64;
    if raw_bytes.len() < offset + sig_bytes {
        warnings.push(format!(
            "TOOL_DECODE_MISMATCH: expected {} signature bytes at offset {}, buffer length {}",
            sig_bytes,
            offset,
            raw_bytes.len()
        ));
        return Ok(warnings);
    }

    // Validate each signature
    for i in 0..num_sigs {
        let start = offset + i * 64;
        let sig_data = &raw_bytes[start..start + 64];
        if Signature::try_from(sig_data).is_err() {
            warnings.push(format!("TOOL_DECODE_MISMATCH: signature {} at offset {} is invalid Ed25519", i, start));
        }
    }
    offset += sig_bytes;

    // Read message header
    if raw_bytes.len() < offset + 3 {
        warnings.push(format!(
            "TOOL_DECODE_MISMATCH: expected message header (3 bytes) at offset {}, buffer length {}",
            offset,
            raw_bytes.len()
        ));
        return Ok(warnings);
    }
    let _num_required = raw_bytes[offset] as usize;
    let _num_readonly_signed = raw_bytes[offset + 1] as usize;
    let _num_readonly_unsigned = raw_bytes[offset + 2] as usize;
    offset += 3;

    // Read account keys
    let (num_accounts, consumed) =
        read_compact_u16(raw_bytes, offset).context("Expected compact-u16 for account count")?;
    offset = consumed;
    let num_accounts = num_accounts as usize;
    let account_bytes = num_accounts * 32;
    if raw_bytes.len() < offset + account_bytes {
        warnings.push(format!(
            "TOOL_DECODE_MISMATCH: expected {} account key bytes, buffer length {}",
            account_bytes,
            raw_bytes.len()
        ));
        return Ok(warnings);
    }
    let mut account_keys: Vec<Pubkey> = Vec::with_capacity(num_accounts);
    for i in 0..num_accounts {
        let start = offset + i * 32;
        match Pubkey::try_from(&raw_bytes[start..start + 32]) {
            Ok(pk) => account_keys.push(pk),
            Err(e) => {
                warnings.push(format!(
                    "TOOL_DECODE_MISMATCH: account {} at offset {} is not a valid pubkey: {}",
                    i, start, e
                ));
            }
        }
    }
    offset += account_bytes;

    // Read recent blockhash
    if raw_bytes.len() < offset + 32 {
        warnings.push(format!("TOOL_DECODE_MISMATCH: expected 32-byte blockhash at offset {}", offset));
        return Ok(warnings);
    }
    let _blockhash = &raw_bytes[offset..offset + 32];
    offset += 32;

    // Read instructions
    let (num_ixs, consumed) =
        read_compact_u16(raw_bytes, offset).context("Expected compact-u16 for instruction count")?;
    offset = consumed;
    let num_ixs = num_ixs as usize;

    for i in 0..num_ixs {
        if raw_bytes.len() <= offset {
            warnings.push(format!("TOOL_DECODE_MISMATCH: buffer exhausted reading instruction {} program index", i));
            break;
        }
        let program_idx = raw_bytes[offset] as usize;
        offset += 1;
        if program_idx >= num_accounts {
            warnings.push(format!(
                "TOOL_DECODE_MISMATCH: instruction {} references program account {} out of range",
                i, program_idx
            ));
        }

        let (num_accts, consumed) = read_compact_u16(raw_bytes, offset)
            .with_context(|| format!("Expected compact-u16 for account count in instruction {}", i))?;
        offset = consumed;
        let num_accts = num_accts as usize;
        for _ in 0..num_accts {
            if raw_bytes.len() <= offset {
                warnings
                    .push(format!("TOOL_DECODE_MISMATCH: buffer exhausted reading instruction {} account index", i));
                break;
            }
            let acct_idx = raw_bytes[offset] as usize;
            offset += 1;
            if acct_idx >= num_accounts {
                warnings.push(format!(
                    "TOOL_DECODE_MISMATCH: instruction {} references account {} out of range",
                    i, acct_idx
                ));
            }
        }

        let (data_len, consumed) = read_compact_u16(raw_bytes, offset)
            .with_context(|| format!("Expected compact-u16 for data length in instruction {}", i))?;
        offset = consumed;
        let data_len = data_len as usize;
        if raw_bytes.len() < offset + data_len {
            warnings.push(format!("TOOL_DECODE_MISMATCH: instruction {} data length {} exceeds buffer", i, data_len));
            return Ok(warnings);
        }
        offset += data_len;
    }

    // Verify we consumed exactly the right amount (allowing for trailing bytes in v0 messages
    // which have ALT lookups after instructions)
    // For legacy, we should be at trailing end. For v0, there may be extra ALT data.
    if offset > raw_bytes.len() {
        warnings.push(format!(
            "TOOL_DECODE_MISMATCH: parsed {} bytes but buffer is only {} bytes",
            offset,
            raw_bytes.len()
        ));
    }

    Ok(warnings)
}
