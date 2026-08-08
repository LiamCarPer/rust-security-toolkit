use solana_sdk::pubkey::Pubkey;

use crate::types::TOKEN_2022_PROGRAM_ID;

use crate::anchor_decoder::{compute_anchor_discriminator, decode_anchor_args};
use crate::types::{
    ASSOCIATED_TOKEN_PROGRAM_ID, COMPUTE_BUDGET_PROGRAM_ID, IdlJson, SYSTEM_PROGRAM_ID, TOKEN_PROGRAM_ID,
};

/// Decode instruction data for known programs and IDL-based matching.
pub fn decode_instruction_data(
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
            (Some("CreateAccount".into()), serde_json::json!({ "lamports": lamports, "space": space, "owner": owner }))
        }
        1 if data.len() >= 36 => {
            let owner = Pubkey::try_from(&data[4..36]).map(|k| k.to_string()).unwrap_or_else(|_| "invalid".to_string());
            (Some("Assign".into()), serde_json::json!({ "owner": owner }))
        }
        2 if data.len() >= 12 => {
            let lamports = u64::from_le_bytes(data[4..12].try_into().unwrap());
            (Some("Transfer".into()), serde_json::json!({ "lamports": lamports }))
        }
        3 => {
            let mut map = serde_json::Map::new();
            if data.len() > 36
                && let Ok(base) = Pubkey::try_from(&data[4..36])
            {
                map.insert("base".into(), serde_json::Value::String(base.to_string()));
            }
            if data.len() > 68 {
                map.insert("lamports".into(), serde_json::json!(u64::from_le_bytes(data[36..44].try_into().unwrap())));
                map.insert("space".into(), serde_json::json!(u64::from_le_bytes(data[44..52].try_into().unwrap())));
                if let Ok(owner) = Pubkey::try_from(&data[52..84]) {
                    map.insert("owner".into(), serde_json::Value::String(owner.to_string()));
                }
            }
            (Some("CreateAccountWithSeed".into()), serde_json::Value::Object(map))
        }
        4 => (Some("AdvanceNonceAccount".into()), serde_json::Value::Null),
        5 if data.len() >= 12 => {
            let lamports = u64::from_le_bytes(data[4..12].try_into().unwrap());
            (Some("WithdrawNonceAccount".into()), serde_json::json!({ "lamports": lamports }))
        }
        6 if data.len() >= 36 => {
            let authorized =
                Pubkey::try_from(&data[4..36]).map(|k| k.to_string()).unwrap_or_else(|_| "invalid".to_string());
            (Some("InitializeNonceAccount".into()), serde_json::json!({ "authorized": authorized }))
        }
        7 if data.len() >= 36 => {
            let authorized =
                Pubkey::try_from(&data[4..36]).map(|k| k.to_string()).unwrap_or_else(|_| "invalid".to_string());
            (Some("AuthorizeNonceAccount".into()), serde_json::json!({ "authorized": authorized }))
        }
        8 if data.len() >= 12 => {
            let space = u64::from_le_bytes(data[4..12].try_into().unwrap());
            (Some("Allocate".into()), serde_json::json!({ "space": space }))
        }
        9 => {
            // AllocateWithSeed { base, seed: String, space, owner } in bincode order.
            let mut map = serde_json::Map::new();
            if data.len() >= 36
                && let Ok(base) = Pubkey::try_from(&data[4..36])
            {
                map.insert("base".into(), serde_json::Value::String(base.to_string()));
            }
            if data.len() >= 44 {
                let seed_len = u64::from_le_bytes(data[36..44].try_into().unwrap()) as usize;
                let seed_end = 44usize.saturating_add(seed_len);
                if data.len() >= seed_end {
                    map.insert(
                        "seed".into(),
                        serde_json::Value::String(String::from_utf8_lossy(&data[44..seed_end]).into_owned()),
                    );
                    if data.len() >= seed_end.saturating_add(8) {
                        map.insert(
                            "space".into(),
                            serde_json::json!(u64::from_le_bytes(data[seed_end..seed_end + 8].try_into().unwrap())),
                        );
                        if let Ok(owner) = Pubkey::try_from(&data[seed_end + 8..seed_end + 40]) {
                            map.insert("owner".into(), serde_json::Value::String(owner.to_string()));
                        }
                    }
                }
            }
            (Some("AllocateWithSeed".into()), serde_json::Value::Object(map))
        }
        10 => {
            // AssignWithSeed { base, seed: String, owner } in bincode order.
            let mut map = serde_json::Map::new();
            if data.len() >= 36
                && let Ok(base) = Pubkey::try_from(&data[4..36])
            {
                map.insert("base".into(), serde_json::Value::String(base.to_string()));
            }
            if data.len() >= 44 {
                let seed_len = u64::from_le_bytes(data[36..44].try_into().unwrap()) as usize;
                let seed_end = 44usize.saturating_add(seed_len);
                if data.len() >= seed_end {
                    map.insert(
                        "seed".into(),
                        serde_json::Value::String(String::from_utf8_lossy(&data[44..seed_end]).into_owned()),
                    );
                    if let Ok(owner) = Pubkey::try_from(&data[seed_end..seed_end + 32]) {
                        map.insert("owner".into(), serde_json::Value::String(owner.to_string()));
                    }
                }
            }
            (Some("AssignWithSeed".into()), serde_json::Value::Object(map))
        }
        11 => {
            // TransferWithSeed { lamports, from_seed: String, from_owner } in bincode order.
            let mut map = serde_json::Map::new();
            if data.len() >= 12 {
                map.insert("lamports".into(), serde_json::json!(u64::from_le_bytes(data[4..12].try_into().unwrap())));
            }
            if data.len() >= 20 {
                let seed_len = u64::from_le_bytes(data[12..20].try_into().unwrap()) as usize;
                let seed_end = 20usize.saturating_add(seed_len);
                if data.len() >= seed_end {
                    map.insert(
                        "from_seed".into(),
                        serde_json::Value::String(String::from_utf8_lossy(&data[20..seed_end]).into_owned()),
                    );
                    if let Ok(from_owner) = Pubkey::try_from(&data[seed_end..seed_end + 32]) {
                        map.insert("from_owner".into(), serde_json::Value::String(from_owner.to_string()));
                    }
                }
            }
            (Some("TransferWithSeed".into()), serde_json::Value::Object(map))
        }
        12 => (Some("UpgradeNonceAccount".into()), serde_json::Value::Null),
        13 if data.len() >= 52 => {
            let lamports = u64::from_le_bytes(data[4..12].try_into().unwrap());
            let space = u64::from_le_bytes(data[12..20].try_into().unwrap());
            let owner =
                Pubkey::try_from(&data[20..52]).map(|k| k.to_string()).unwrap_or_else(|_| "invalid".to_string());
            (
                Some("CreateAccountAllowPrefund".into()),
                serde_json::json!({ "lamports": lamports, "space": space, "owner": owner }),
            )
        }
        _ => (None, serde_json::Value::String(hex::encode(data))),
    }
}

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
                map.insert("decimals".into(), serde_json::json!(payload[0]));
                if let Ok(authority) = Pubkey::try_from(&payload[1..33]) {
                    map.insert("mint_authority".into(), serde_json::Value::String(authority.to_string()));
                }
                let freeze_opt = payload[33];
                map.insert("freeze_authority_option".into(), serde_json::json!(freeze_opt));
                if freeze_opt == 1
                    && payload.len() >= 66
                    && let Ok(freeze_auth) = Pubkey::try_from(&payload[34..66])
                {
                    map.insert("freeze_authority".into(), serde_json::Value::String(freeze_auth.to_string()));
                }
            }
            let name = if is_token22 { "InitializeMint2" } else { "InitializeMint" };
            (Some(name.into()), serde_json::Value::Object(map))
        }
        1 => (Some("InitializeAccount".into()), serde_json::Value::Null),
        2 => {
            let m = payload.first().copied().unwrap_or(0);
            (Some("InitializeMultisig".into()), serde_json::json!({ "m": m }))
        }
        3 if payload.len() >= 8 => (
            Some("Transfer".into()),
            serde_json::json!({ "amount": u64::from_le_bytes(payload[0..8].try_into().unwrap()) }),
        ),
        4 if payload.len() >= 8 => (
            Some("Approve".into()),
            serde_json::json!({ "amount": u64::from_le_bytes(payload[0..8].try_into().unwrap()) }),
        ),
        5 => (Some("Revoke".into()), serde_json::Value::Null),
        6 => {
            let authority_type = payload.first().copied().unwrap_or(0);
            let mut map = serde_json::Map::new();
            map.insert("authority_type".into(), serde_json::json!(authority_type));
            if payload.len() >= 2 {
                let new_auth_opt = payload[1];
                map.insert("new_authority_option".into(), serde_json::json!(new_auth_opt));
                if new_auth_opt == 1
                    && payload.len() >= 34
                    && let Ok(new_auth) = Pubkey::try_from(&payload[2..34])
                {
                    map.insert("new_authority".into(), serde_json::Value::String(new_auth.to_string()));
                }
            }
            (Some("SetAuthority".into()), serde_json::Value::Object(map))
        }
        7 if payload.len() >= 8 => (
            Some("MintTo".into()),
            serde_json::json!({ "amount": u64::from_le_bytes(payload[0..8].try_into().unwrap()) }),
        ),
        8 if payload.len() >= 8 => (
            Some("Burn".into()),
            serde_json::json!({ "amount": u64::from_le_bytes(payload[0..8].try_into().unwrap()) }),
        ),
        9 => (Some("CloseAccount".into()), serde_json::Value::Null),
        10 => (Some("FreezeAccount".into()), serde_json::Value::Null),
        11 => (Some("ThawAccount".into()), serde_json::Value::Null),
        12 if payload.len() >= 9 => {
            let amount = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            (Some("TransferChecked".into()), serde_json::json!({ "amount": amount, "decimals": payload[8] }))
        }
        13 if payload.len() >= 9 => {
            let amount = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            (Some("ApproveChecked".into()), serde_json::json!({ "amount": amount, "decimals": payload[8] }))
        }
        14 if payload.len() >= 9 => {
            let amount = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            (Some("MintToChecked".into()), serde_json::json!({ "amount": amount, "decimals": payload[8] }))
        }
        15 if payload.len() >= 9 => {
            let amount = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            (Some("BurnChecked".into()), serde_json::json!({ "amount": amount, "decimals": payload[8] }))
        }
        16 if payload.len() >= 32 => {
            if let Ok(owner) = Pubkey::try_from(&payload[0..32]) {
                (Some("InitializeAccount2".into()), serde_json::json!({ "owner": owner.to_string() }))
            } else {
                (Some("InitializeAccount2".into()), serde_json::Value::Null)
            }
        }
        17 => (Some("SyncNative".into()), serde_json::Value::Null),
        18 if payload.len() >= 32 => {
            if let Ok(owner) = Pubkey::try_from(&payload[0..32]) {
                (Some("InitializeAccount3".into()), serde_json::json!({ "owner": owner.to_string() }))
            } else {
                (Some("InitializeAccount3".into()), serde_json::Value::Null)
            }
        }
        19 => {
            let m = payload.first().copied().unwrap_or(0);
            (Some("InitializeMultisig2".into()), serde_json::json!({ "m": m }))
        }
        20 if is_token22 => (Some("InitializeMint2".into()), serde_json::Value::Null),
        21 if is_token22 => (Some("GetAccountDataSize".into()), decode_extension_types(payload)),
        22 if is_token22 => (Some("InitializeImmutableOwner".into()), serde_json::Value::Null),
        23 if is_token22 && payload.len() >= 8 => (
            Some("AmountToUiAmount".into()),
            serde_json::json!({"amount": u64::from_le_bytes(payload[0..8].try_into().unwrap())}),
        ),
        24 if is_token22 => {
            let ui_amount =
                std::str::from_utf8(payload).map(|s| s.to_string()).unwrap_or_else(|_| hex::encode(payload));
            (Some("UiAmountToAmount".into()), serde_json::json!({"ui_amount": ui_amount}))
        }
        25 if is_token22 => {
            let mut map = serde_json::Map::new();
            if payload.len() >= 33 {
                let close_auth_opt = payload[0];
                map.insert("close_authority_option".into(), serde_json::json!(close_auth_opt));
                if close_auth_opt == 1
                    && payload.len() >= 65
                    && let Ok(auth) = Pubkey::try_from(&payload[1..33])
                {
                    map.insert("close_authority".into(), serde_json::Value::String(auth.to_string()));
                }
            }
            (Some("InitializeMintCloseAuthority".into()), serde_json::Value::Object(map))
        }
        26 if is_token22 => decode_transfer_fee_extension(payload),
        27 if is_token22 => decode_confidential_transfer_extension(payload),
        28 if is_token22 => (Some("DefaultAccountStateExtension".into()), decode_extension_types(payload)),
        29 if is_token22 => (Some("Reallocate".into()), decode_extension_types(payload)),
        30 if is_token22 => (Some("MemoTransferExtension".into()), serde_json::Value::Null),
        31 if is_token22 => (Some("CreateNativeMint".into()), serde_json::Value::Null),
        32 if is_token22 => (Some("InitializeNonTransferableMint".into()), serde_json::Value::Null),
        33 if is_token22 => decode_interest_bearing_mint_extension(payload),
        34 if is_token22 => decode_cpi_guard_extension(payload),
        35 if is_token22 => {
            let mut map = serde_json::Map::new();
            if payload.len() >= 32
                && let Ok(delegate) = Pubkey::try_from(&payload[0..32])
            {
                map.insert("delegate".into(), serde_json::Value::String(delegate.to_string()));
            }
            (Some("InitializePermanentDelegate".into()), serde_json::Value::Object(map))
        }
        36 if is_token22 => decode_transfer_hook_extension(payload),
        37 if is_token22 => (Some("ConfidentialTransferFeeExtension".into()), serde_json::Value::Null),
        38 if is_token22 => (Some("WithdrawExcessLamports".into()), serde_json::Value::Null),
        39 if is_token22 => decode_pointer_extension(
            payload,
            "InitializeMetadataPointer",
            "UpdateMetadataPointer",
            "MetadataPointerExtension",
            "metadata_address",
        ),
        40 if is_token22 => decode_pointer_extension(
            payload,
            "InitializeGroupPointer",
            "UpdateGroupPointer",
            "GroupPointerExtension",
            "group_address",
        ),
        41 if is_token22 => decode_pointer_extension(
            payload,
            "InitializeGroupMemberPointer",
            "UpdateGroupMemberPointer",
            "GroupMemberPointerExtension",
            "group_member_address",
        ),
        42 if is_token22 => (Some("ConfidentialMintBurnExtension".into()), serde_json::Value::Null),
        43 if is_token22 => (Some("ScaledUiAmountExtension".into()), serde_json::Value::Null),
        44 if is_token22 => decode_pausable_extension(payload),
        _ => (None, serde_json::Value::String(hex::encode(data))),
    }
}

fn decode_transfer_fee_extension(payload: &[u8]) -> (Option<String>, serde_json::Value) {
    if payload.is_empty() {
        return (Some("TransferFeeExtension".into()), serde_json::Value::Null);
    }
    match payload[0] {
        0 => {
            let mut map = serde_json::Map::new();
            if payload.len() >= 33
                && let Ok(a) = Pubkey::try_from(&payload[1..33])
            {
                map.insert("transfer_fee_config_authority".into(), serde_json::Value::String(a.to_string()));
            }
            if payload.len() >= 65
                && let Ok(a) = Pubkey::try_from(&payload[33..65])
            {
                map.insert("withdraw_withheld_authority".into(), serde_json::Value::String(a.to_string()));
            }
            if payload.len() >= 67 {
                let fee_bps = u16::from_le_bytes([payload[65], payload[66]]);
                map.insert("transfer_fee_basis_points".into(), serde_json::json!(fee_bps));
            }
            if payload.len() >= 75 {
                let max_fee = u64::from_le_bytes(payload[67..75].try_into().unwrap());
                map.insert("max_fee".into(), serde_json::json!(max_fee));
            }
            (Some("InitializeTransferFeeConfig".into()), serde_json::Value::Object(map))
        }
        1 if payload.len() >= 9 => (
            Some("TransferCheckedWithFee".into()),
            serde_json::json!({ "amount": u64::from_le_bytes(payload[1..9].try_into().unwrap()) }),
        ),
        2 => (Some("WithdrawWithheldTokensFromMint".into()), serde_json::Value::Null),
        3 => {
            let num = payload.get(1).copied().unwrap_or(0);
            (Some("WithdrawWithheldTokensFromAccounts".into()), serde_json::json!({ "num_token_accounts": num }))
        }
        4 => {
            let mut map = serde_json::Map::new();
            if payload.len() >= 2 {
                map.insert("num_mints".into(), serde_json::json!(payload[1]));
            }
            (Some("HarvestWithheldTokensToMint".into()), serde_json::Value::Object(map))
        }
        _ => (Some("TransferFeeExtension".into()), serde_json::Value::Null),
    }
}

fn decode_pointer_extension(
    payload: &[u8],
    init_name: &str,
    update_name: &str,
    fallback: &str,
    field: &str,
) -> (Option<String>, serde_json::Value) {
    // Option<Pubkey> values: 1-byte tag + 32-byte pubkey when present.
    let read_option_pubkey = |offset: usize| -> (Option<String>, usize) {
        if payload.len() <= offset {
            return (None, 1);
        }
        if payload[offset] == 1 && payload.len() >= offset + 33 {
            (Pubkey::try_from(&payload[offset + 1..offset + 33]).ok().map(|p| p.to_string()), 33)
        } else {
            (None, 1)
        }
    };

    match payload.first() {
        Some(0) => {
            let mut map = serde_json::Map::new();
            let (authority, consumed) = read_option_pubkey(1);
            if let Some(a) = authority {
                map.insert("authority".into(), serde_json::Value::String(a));
            }
            let (address, _) = read_option_pubkey(1 + consumed);
            if let Some(a) = address {
                map.insert(field.into(), serde_json::Value::String(a));
            }
            (Some(init_name.into()), serde_json::Value::Object(map))
        }
        Some(1) => {
            let mut map = serde_json::Map::new();
            let (address, _) = read_option_pubkey(1);
            if let Some(a) = address {
                map.insert(field.into(), serde_json::Value::String(a));
            }
            (Some(update_name.into()), serde_json::Value::Object(map))
        }
        _ => (Some(fallback.into()), serde_json::Value::Null),
    }
}

fn decode_interest_bearing_mint_extension(payload: &[u8]) -> (Option<String>, serde_json::Value) {
    match payload.first() {
        Some(0) if payload.len() >= 3 => {
            let rate_bps = i16::from_le_bytes([payload[1], payload[2]]);
            (Some("InitializeInterestBearingMint".into()), serde_json::json!({"rate_bps": rate_bps}))
        }
        Some(1) if payload.len() >= 3 => {
            let rate_bps = i16::from_le_bytes([payload[1], payload[2]]);
            (Some("UpdateInterestBearingMintRate".into()), serde_json::json!({"rate_bps": rate_bps}))
        }
        _ => (Some("InterestBearingMintExtension".into()), serde_json::Value::Null),
    }
}

fn decode_cpi_guard_extension(payload: &[u8]) -> (Option<String>, serde_json::Value) {
    match payload.first() {
        Some(0) => (Some("EnableCpiGuard".into()), serde_json::Value::Null),
        Some(1) => (Some("DisableCpiGuard".into()), serde_json::Value::Null),
        _ => (Some("CpiGuardExtension".into()), serde_json::Value::Null),
    }
}

fn decode_transfer_hook_extension(payload: &[u8]) -> (Option<String>, serde_json::Value) {
    match payload.first() {
        Some(0) if payload.len() >= 65 => {
            let mut map = serde_json::Map::new();
            if let Ok(a) = Pubkey::try_from(&payload[1..33]) {
                map.insert("authority".into(), serde_json::Value::String(a.to_string()));
            }
            if let Ok(p) = Pubkey::try_from(&payload[33..65]) {
                map.insert("program_id".into(), serde_json::Value::String(p.to_string()));
            }
            (Some("InitializeTransferHook".into()), serde_json::Value::Object(map))
        }
        Some(1) if payload.len() >= 33 => {
            let mut map = serde_json::Map::new();
            if let Ok(p) = Pubkey::try_from(&payload[1..33]) {
                map.insert("program_id".into(), serde_json::Value::String(p.to_string()));
            }
            (Some("UpdateTransferHook".into()), serde_json::Value::Object(map))
        }
        _ => (Some("TransferHookExtension".into()), serde_json::Value::Null),
    }
}

fn decode_pausable_extension(payload: &[u8]) -> (Option<String>, serde_json::Value) {
    match payload.first() {
        Some(0) => (Some("Pause".into()), serde_json::Value::Null),
        Some(1) => (Some("Resume".into()), serde_json::Value::Null),
        _ => (Some("PausableExtension".into()), serde_json::Value::Null),
    }
}

/// Decode a `Vec<ExtensionType>` (u32 LE count + u16 items) from instruction data.
fn decode_extension_types(payload: &[u8]) -> serde_json::Value {
    if payload.len() < 4 {
        return serde_json::Value::Null;
    }
    let count = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
    let count = count.min(payload.len().saturating_sub(4) / 2);
    let items: Vec<serde_json::Value> = (0..count)
        .map(|i| {
            let off = 4 + i * 2;
            serde_json::json!(u16::from_le_bytes([payload[off], payload[off + 1]]))
        })
        .collect();
    serde_json::json!({"extension_types": items})
}

fn decode_confidential_transfer_extension(payload: &[u8]) -> (Option<String>, serde_json::Value) {
    if payload.is_empty() {
        return (Some("ConfidentialTransferExtension".into()), serde_json::Value::Null);
    }
    let name = match payload[0] {
        0 => "InitializeConfidentialTransferMint",
        1 => "UpdateConfidentialTransferMint",
        2 => "ConfigureConfidentialTransferAccount",
        3 => "ApproveConfidentialTransferAccount",
        4 => "EmptyConfidentialTransferAccount",
        5 => "Deposit",
        6 => "Withdraw",
        7 => "Transfer",
        8 => "ApplyPendingBalance",
        9 => "EnableConfidentialTransfer",
        10 => "DisableConfidentialTransfer",
        _ => return (Some("ConfidentialTransferExtension".into()), serde_json::Value::Null),
    };
    (Some(name.into()), serde_json::Value::Null)
}

fn decode_associated_token_instruction(data: &[u8]) -> (Option<String>, serde_json::Value) {
    match data.first() {
        Some(0) => (Some("Create".into()), serde_json::Value::Null),
        Some(1) => (Some("CreateIdempotent".into()), serde_json::Value::Null),
        Some(2) => (Some("RecoverNested".into()), serde_json::Value::Null),
        _ => (None, serde_json::Value::String(hex::encode(data))),
    }
}

fn decode_compute_budget_instruction(data: &[u8]) -> (Option<String>, serde_json::Value) {
    match data.first() {
        Some(0) if data.len() >= 9 => {
            let units = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            let additional_fee = u32::from_le_bytes([data[5], data[6], data[7], data[8]]);
            (Some("RequestUnits".into()), serde_json::json!({ "units": units, "additional_fee": additional_fee }))
        }
        Some(1) if data.len() >= 5 => {
            let bytes = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            (Some("RequestHeapFrame".into()), serde_json::json!({ "bytes": bytes }))
        }
        Some(2) if data.len() >= 5 => {
            let units = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            (Some("SetComputeUnitLimit".into()), serde_json::json!({ "units": units }))
        }
        Some(3) if data.len() >= 9 => {
            let price = u64::from_le_bytes([data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8]]);
            (Some("SetComputeUnitPrice".into()), serde_json::json!({ "micro_lamports": price }))
        }
        Some(4) if data.len() >= 5 => {
            let bytes = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            (Some("SetLoadedAccountsDataSizeLimit".into()), serde_json::json!({ "bytes": bytes }))
        }
        _ => (None, serde_json::Value::String(hex::encode(data))),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use solana_address::Address;
    use solana_system_interface::instruction::SystemInstruction;

    use super::decode_instruction_data;
    use crate::types::{COMPUTE_BUDGET_PROGRAM_ID, SYSTEM_PROGRAM_ID};

    /// Base58 keys with distinctive bytes so decoding mistakes (byte order, offsets) surface.
    fn key_a() -> Address {
        Address::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap()
    }

    fn key_b() -> Address {
        Address::from_str("So11111111111111111111111111111111111111112").unwrap()
    }

    /// Bincode-serialize a real SDK `SystemInstruction` and run it through the decoder.
    fn decode_system(ix: &SystemInstruction) -> (Option<String>, serde_json::Value) {
        let data = bincode::serialize(ix).unwrap();
        decode_instruction_data(SYSTEM_PROGRAM_ID, &data, None)
    }

    #[test]
    fn system_authorize_nonce_account_round_trip() {
        let (name, decoded) = decode_system(&SystemInstruction::AuthorizeNonceAccount(key_a()));
        assert_eq!(name.as_deref(), Some("AuthorizeNonceAccount"));
        assert_eq!(decoded["authorized"], key_a().to_string());
    }

    #[test]
    fn system_allocate_round_trip() {
        let (name, decoded) = decode_system(&SystemInstruction::Allocate { space: 4096 });
        assert_eq!(name.as_deref(), Some("Allocate"));
        assert_eq!(decoded["space"].as_u64(), Some(4096));
    }

    #[test]
    fn system_allocate_with_seed_round_trip() {
        let (name, decoded) = decode_system(&SystemInstruction::AllocateWithSeed {
            base: key_a(),
            seed: "seed".to_string(),
            space: 5120,
            owner: key_b(),
        });
        assert_eq!(name.as_deref(), Some("AllocateWithSeed"));
        assert_eq!(decoded["base"], key_a().to_string());
        assert_eq!(decoded["seed"], "seed");
        assert_eq!(decoded["space"].as_u64(), Some(5120));
        assert_eq!(decoded["owner"], key_b().to_string());
    }

    #[test]
    fn system_assign_with_seed_round_trip() {
        let (name, decoded) = decode_system(&SystemInstruction::AssignWithSeed {
            base: key_a(),
            seed: "seed".to_string(),
            owner: key_b(),
        });
        assert_eq!(name.as_deref(), Some("AssignWithSeed"));
        assert_eq!(decoded["base"], key_a().to_string());
        assert_eq!(decoded["seed"], "seed");
        assert_eq!(decoded["owner"], key_b().to_string());
    }

    #[test]
    fn system_transfer_with_seed_round_trip() {
        let (name, decoded) = decode_system(&SystemInstruction::TransferWithSeed {
            lamports: 99,
            from_seed: "seed".to_string(),
            from_owner: key_b(),
        });
        assert_eq!(name.as_deref(), Some("TransferWithSeed"));
        assert_eq!(decoded["lamports"].as_u64(), Some(99));
        assert_eq!(decoded["from_seed"], "seed");
        assert_eq!(decoded["from_owner"], key_b().to_string());
    }

    #[test]
    fn system_transfer_with_seed_truncated_skips_missing_fields() {
        let mut data = bincode::serialize(&SystemInstruction::TransferWithSeed {
            lamports: 99,
            from_seed: "seed".to_string(),
            from_owner: key_b(),
        })
        .unwrap();
        data.truncate(20); // keep discriminant + lamports + seed length prefix only
        let (name, decoded) = decode_instruction_data(SYSTEM_PROGRAM_ID, &data, None);
        assert_eq!(name.as_deref(), Some("TransferWithSeed"));
        assert_eq!(decoded["lamports"].as_u64(), Some(99));
        assert!(decoded.get("from_seed").is_none());
        assert!(decoded.get("from_owner").is_none());
    }

    #[test]
    fn system_upgrade_nonce_account_round_trip() {
        let (name, decoded) = decode_system(&SystemInstruction::UpgradeNonceAccount);
        assert_eq!(name.as_deref(), Some("UpgradeNonceAccount"));
        assert!(decoded.is_null());
    }

    #[test]
    fn system_create_account_allow_prefund_round_trip() {
        let (name, decoded) = decode_system(&SystemInstruction::CreateAccountAllowPrefund {
            lamports: 1_000_000,
            space: 128,
            owner: key_a(),
        });
        assert_eq!(name.as_deref(), Some("CreateAccountAllowPrefund"));
        assert_eq!(decoded["lamports"].as_u64(), Some(1_000_000));
        assert_eq!(decoded["space"].as_u64(), Some(128));
        assert_eq!(decoded["owner"], key_a().to_string());
    }

    #[test]
    fn system_advance_nonce_account_regression() {
        let (name, decoded) = decode_system(&SystemInstruction::AdvanceNonceAccount);
        assert_eq!(name.as_deref(), Some("AdvanceNonceAccount"));
        assert!(decoded.is_null());
    }

    #[test]
    fn system_create_account_regression() {
        let (name, decoded) =
            decode_system(&SystemInstruction::CreateAccount { lamports: 42, space: 64, owner: key_a() });
        assert_eq!(name.as_deref(), Some("CreateAccount"));
        assert_eq!(decoded["lamports"].as_u64(), Some(42));
        assert_eq!(decoded["space"].as_u64(), Some(64));
        assert_eq!(decoded["owner"], key_a().to_string());
    }

    /// `ComputeBudgetInstruction` is not reachable from any crate in the pinned tree
    /// (solana-sdk 4.0.1 has no compute_budget module and solana-compute-budget-interface
    /// is absent from Cargo.lock), so build the on-chain bytes by hand: 1-byte tag
    /// followed by little-endian payload, matching the decoder (and the on-chain format).
    fn decode_compute_budget(data: &[u8]) -> (Option<String>, serde_json::Value) {
        decode_instruction_data(COMPUTE_BUDGET_PROGRAM_ID, data, None)
    }

    #[test]
    fn compute_budget_request_units_round_trip() {
        let mut data = vec![0u8];
        data.extend_from_slice(&200_000u32.to_le_bytes());
        data.extend_from_slice(&5u32.to_le_bytes());
        let (name, decoded) = decode_compute_budget(&data);
        assert_eq!(name.as_deref(), Some("RequestUnits"));
        assert_eq!(decoded["units"].as_u64(), Some(200_000));
        assert_eq!(decoded["additional_fee"].as_u64(), Some(5));
    }

    #[test]
    fn compute_budget_request_heap_frame_round_trip() {
        let mut data = vec![1u8];
        data.extend_from_slice(&131_072u32.to_le_bytes());
        let (name, decoded) = decode_compute_budget(&data);
        assert_eq!(name.as_deref(), Some("RequestHeapFrame"));
        assert_eq!(decoded["bytes"].as_u64(), Some(131_072));
    }

    #[test]
    fn compute_budget_set_compute_unit_limit_round_trip() {
        let mut data = vec![2u8];
        data.extend_from_slice(&1_400_000u32.to_le_bytes());
        let (name, decoded) = decode_compute_budget(&data);
        assert_eq!(name.as_deref(), Some("SetComputeUnitLimit"));
        assert_eq!(decoded["units"].as_u64(), Some(1_400_000));
    }

    #[test]
    fn compute_budget_set_compute_unit_price_round_trip() {
        let mut data = vec![3u8];
        data.extend_from_slice(&123_456_789u64.to_le_bytes());
        let (name, decoded) = decode_compute_budget(&data);
        assert_eq!(name.as_deref(), Some("SetComputeUnitPrice"));
        assert_eq!(decoded["micro_lamports"].as_u64(), Some(123_456_789));
    }

    #[test]
    fn compute_budget_set_loaded_accounts_data_size_limit_round_trip() {
        let mut data = vec![4u8];
        data.extend_from_slice(&64_512u32.to_le_bytes());
        let (name, decoded) = decode_compute_budget(&data);
        assert_eq!(name.as_deref(), Some("SetLoadedAccountsDataSizeLimit"));
        assert_eq!(decoded["bytes"].as_u64(), Some(64_512));
    }
}
