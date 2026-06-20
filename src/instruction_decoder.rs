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
            (Some("ResizeNonceAccount".into()), serde_json::json!({ "authorized": authorized }))
        }
        8 if data.len() >= 36 => {
            let authorized =
                Pubkey::try_from(&data[4..36]).map(|k| k.to_string()).unwrap_or_else(|_| "invalid".to_string());
            (Some("AuthorizeNonceAccount".into()), serde_json::json!({ "authorized": authorized }))
        }
        9 if data.len() >= 12 => {
            let space = u64::from_le_bytes(data[4..12].try_into().unwrap());
            (Some("Allocate".into()), serde_json::json!({ "space": space }))
        }
        10 => {
            let mut map = serde_json::Map::new();
            if data.len() > 36
                && let Ok(base) = Pubkey::try_from(&data[4..36])
            {
                map.insert("base".into(), serde_json::Value::String(base.to_string()));
            }
            if data.len() > 68 {
                map.insert("space".into(), serde_json::json!(u64::from_le_bytes(data[36..44].try_into().unwrap())));
                if let Ok(owner) = Pubkey::try_from(&data[44..76]) {
                    map.insert("owner".into(), serde_json::Value::String(owner.to_string()));
                }
            }
            (Some("AllocateWithSeed".into()), serde_json::Value::Object(map))
        }
        11 => {
            let mut map = serde_json::Map::new();
            if data.len() > 36
                && let Ok(base) = Pubkey::try_from(&data[4..36])
            {
                map.insert("base".into(), serde_json::Value::String(base.to_string()));
            }
            if let Ok(owner) = Pubkey::try_from(&data[36..68]) {
                map.insert("owner".into(), serde_json::Value::String(owner.to_string()));
            }
            (Some("AssignWithSeed".into()), serde_json::Value::Object(map))
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
        22 if is_token22 => (Some("InitializeImmutableOwner".into()), serde_json::Value::Null),
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
        31 if is_token22 => {
            let mut map = serde_json::Map::new();
            if payload.len() >= 33
                && let Ok(delegate) = Pubkey::try_from(&payload[0..32])
            {
                map.insert("delegate".into(), serde_json::Value::String(delegate.to_string()));
            }
            (Some("InitializePermanentDelegate".into()), serde_json::Value::Object(map))
        }
        37 if is_token22 => (Some("ConfidentialTransferFeeExtension".into()), serde_json::Value::Null),
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
        Some(0) if data.len() >= 5 => {
            let limit = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            (Some("RequestUnits".into()), serde_json::json!({ "units": limit, "additional_fee": 0 }))
        }
        Some(1) if data.len() >= 5 => {
            let limit = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            (Some("SetComputeUnitLimit".into()), serde_json::json!({ "units": limit }))
        }
        Some(3) if data.len() >= 9 => {
            let price = u64::from_le_bytes([data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8]]);
            (Some("SetComputeUnitPrice".into()), serde_json::json!({ "micro_lamports": price }))
        }
        _ => (None, serde_json::Value::String(hex::encode(data))),
    }
}
