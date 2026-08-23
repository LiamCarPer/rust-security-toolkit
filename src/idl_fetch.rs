use std::io::Read;

use solana_sdk::{pubkey, pubkey::Pubkey};

use crate::simulator::{fetch_account_data, fetch_account_owner};
use crate::types::IdlJson;

pub const PMP_PROGRAM_ID: Pubkey = pubkey!("ProgM6JCCvbYkfKqJYHePx4xxSUSqJp7rh8Lyv7nk7S");
pub const LEGACY_IDL_SEED: &str = "anchor:idl";
pub const LEGACY_PDA_SEED: &str = "anchor-idl";
const METADATA_SEED: &[u8] = b"idl";
const METADATA_SEED_SIZE: usize = 16;

const LEGACY_DISCRIMINATOR_INTERNAL: [u8; 8] = [0x18, 0x46, 0x62, 0xbf, 0x3a, 0x90, 0x7b, 0x9e];
const LEGACY_DISCRIMINATOR_PLAIN: [u8; 8] = [0x8c, 0x24, 0xa6, 0x02, 0x67, 0xc5, 0x21, 0xa4];

const LEGACY_HEADER_LEN: usize = 44;
const PMP_DISCRIMINATOR_METADATA: u8 = 2;
const PMP_FORMAT_JSON: u8 = 1;
const PMP_DATA_SOURCE_DIRECT: u8 = 0;
const PMP_COMPRESSION_NONE: u8 = 0;
const PMP_COMPRESSION_GZIP: u8 = 1;
const PMP_COMPRESSION_ZLIB: u8 = 2;
const PMP_ENCODING_UTF8: u8 = 1;
const PMP_ENCODING_BASE58: u8 = 2;
const PMP_ENCODING_BASE64: u8 = 3;
const PMP_HEADER_LEN: usize = 96;

const MAX_IDL_BYTES: usize = 4 * 1024 * 1024;

pub fn derive_legacy_idl_address(program_id: &Pubkey) -> Pubkey {
    let base = Pubkey::find_program_address(&[], program_id).0;
    Pubkey::create_with_seed(&base, LEGACY_IDL_SEED, program_id).unwrap_or_default()
}

pub fn derive_legacy_pda_address(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[LEGACY_PDA_SEED.as_bytes(), program_id.as_ref()], program_id).0
}

pub fn derive_metadata_idl_address(program_id: &Pubkey) -> Pubkey {
    let mut padded = [0u8; METADATA_SEED_SIZE];
    padded[..METADATA_SEED.len()].copy_from_slice(METADATA_SEED);
    Pubkey::find_program_address(&[program_id.as_ref(), &[], &padded], &PMP_PROGRAM_ID).0
}

pub async fn fetch_idl(rpc_url: &str, program_id: &Pubkey) -> anyhow::Result<Option<IdlJson>> {
    let client = reqwest::Client::new();

    let legacy = derive_legacy_idl_address(program_id);
    if let Some(idl) = try_legacy_account(&client, rpc_url, program_id, &legacy).await? {
        return Ok(Some(idl));
    }

    let pda_fallback = derive_legacy_pda_address(program_id);
    if pda_fallback != legacy
        && let Some(idl) = try_legacy_account(&client, rpc_url, program_id, &pda_fallback).await?
    {
        return Ok(Some(idl));
    }

    let metadata = derive_metadata_idl_address(program_id);
    let Some(data) = fetch_account_data(&client, rpc_url, &metadata.to_string()).await? else {
        return Ok(None);
    };
    if data.len() > MAX_IDL_BYTES {
        return Ok(None);
    }
    let owner = fetch_account_owner(&client, rpc_url, &metadata.to_string()).await?;
    match owner.as_deref() {
        Some(o) if o == PMP_PROGRAM_ID.to_string() => Ok(parse_metadata_idl_bytes(&data, program_id)),
        _ => Ok(None),
    }
}

async fn try_legacy_account(
    client: &reqwest::Client,
    rpc_url: &str,
    program_id: &Pubkey,
    idl_address: &Pubkey,
) -> anyhow::Result<Option<IdlJson>> {
    let address = idl_address.to_string();
    let Some(data) = fetch_account_data(client, rpc_url, &address).await? else {
        return Ok(None);
    };
    if data.len() > MAX_IDL_BYTES {
        return Ok(None);
    }
    let Some(owner) = fetch_account_owner(client, rpc_url, &address).await? else {
        return Ok(None);
    };
    if owner != program_id.to_string() {
        return Ok(None);
    }
    Ok(parse_legacy_idl_bytes(&data))
}

pub fn parse_legacy_idl_bytes(data: &[u8]) -> Option<IdlJson> {
    if data.len() < LEGACY_HEADER_LEN || data.len() > MAX_IDL_BYTES {
        return None;
    }
    if data[0..8] != LEGACY_DISCRIMINATOR_INTERNAL && data[0..8] != LEGACY_DISCRIMINATOR_PLAIN {
        return None;
    }
    let len = u32::from_le_bytes(data[40..44].try_into().ok()?) as usize;
    if len == 0 || LEGACY_HEADER_LEN + len > data.len() {
        return None;
    }
    let payload = &data[LEGACY_HEADER_LEN..LEGACY_HEADER_LEN + len];
    let json_bytes = decompress_zlib_bounded(payload).unwrap_or_else(|| payload.to_vec());
    parse_idl_json(&json_bytes)
}

pub fn parse_metadata_idl_bytes(data: &[u8], expected_program: &Pubkey) -> Option<IdlJson> {
    if data.len() < PMP_HEADER_LEN || data[0] != PMP_DISCRIMINATOR_METADATA {
        return None;
    }
    if data[1..33] != expected_program.to_bytes()[..] {
        return None;
    }
    if &data[67..70] != METADATA_SEED || data[70..83].iter().any(|b| *b != 0) {
        return None;
    }
    let encoding = data[83];
    let compression = data[84];
    if data[85] != PMP_FORMAT_JSON || data[86] != PMP_DATA_SOURCE_DIRECT {
        return None;
    }
    let len = u32::from_le_bytes(data[87..91].try_into().ok()?) as usize;
    if data[91..96].iter().any(|b| *b != 0) || len == 0 || PMP_HEADER_LEN + len > data.len() {
        return None;
    }
    let payload = &data[PMP_HEADER_LEN..PMP_HEADER_LEN + len];
    let raw = match compression {
        PMP_COMPRESSION_NONE => payload.to_vec(),
        PMP_COMPRESSION_ZLIB => decompress_zlib_bounded(payload)?,
        PMP_COMPRESSION_GZIP => decompress_gzip_bounded(payload)?,
        _ => return None,
    };
    let json_bytes = match encoding {
        PMP_ENCODING_UTF8 => raw,
        PMP_ENCODING_BASE58 => bs58::decode(&raw).into_vec().ok()?,
        PMP_ENCODING_BASE64 => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.decode(&raw).ok()?
        }
        _ => raw,
    };
    let value: serde_json::Value = serde_json::from_slice(trim_json_frame(&json_bytes)).ok()?;
    IdlJson::from_value(normalize_idl_value(value))
}

fn decompress_zlib_bounded(payload: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = flate2::read::ZlibDecoder::new(payload);
    read_bounded(&mut decoder)
}

fn decompress_gzip_bounded(payload: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = flate2::read::GzDecoder::new(payload);
    read_bounded(&mut decoder)
}

fn read_bounded<R: Read>(decoder: &mut R) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    decoder.take(MAX_IDL_BYTES as u64 + 1).read_to_end(&mut out).ok()?;
    if out.len() > MAX_IDL_BYTES { None } else { Some(out) }
}

fn trim_json_frame(bytes: &[u8]) -> &[u8] {
    let start = match bytes.iter().position(|b| *b == b'{') {
        Some(i) => i,
        None => return bytes,
    };
    match bytes.iter().rposition(|b| *b == b'}') {
        Some(end) if end > start => &bytes[start..=end],
        _ => bytes,
    }
}

fn parse_idl_json(json_bytes: &[u8]) -> Option<IdlJson> {
    let value: serde_json::Value = serde_json::from_slice(trim_json_frame(json_bytes)).ok()?;
    IdlJson::from_value(normalize_idl_value(value))
}

fn validate_idl(idl: IdlJson) -> Option<IdlJson> {
    if idl.instructions.is_empty() { None } else { Some(idl) }
}

impl IdlJson {
    fn from_value(value: serde_json::Value) -> Option<Self> {
        serde_json::from_value(value).ok().and_then(validate_idl)
    }
}

fn normalize_idl_value(mut value: serde_json::Value) -> serde_json::Value {
    if value.get("version").is_some() && value.get("name").is_some() {
        return value;
    }
    let Some(metadata) = value.get("metadata").cloned() else { return value };
    if let Some(obj) = value.as_object_mut() {
        obj.insert("version".into(), metadata.get("version").cloned().unwrap_or_default());
        obj.insert("name".into(), metadata.get("name").cloned().unwrap_or_default());
        if let Some(instructions) = obj.get_mut("instructions").and_then(|v| v.as_array_mut()) {
            for ix in instructions.iter_mut() {
                normalize_spec_instruction(ix);
            }
        }
        if let Some(accounts) = obj.get_mut("accounts").and_then(|v| v.as_array_mut()) {
            for account in accounts.iter_mut() {
                if let Some(a) = account.as_object_mut() {
                    a.remove("discriminator");
                }
            }
        }
    }
    value
}

fn normalize_spec_instruction(ix: &mut serde_json::Value) {
    let Some(accounts) = ix.get("accounts").and_then(|v| v.as_array().cloned()) else { return };
    let mut flat = Vec::with_capacity(accounts.len());
    for item in accounts {
        if let Some(group) = item.get("accounts").and_then(|v| v.as_array()) {
            flat.extend(group.iter().cloned());
        } else {
            flat.push(item);
        }
    }
    for item in flat.iter_mut() {
        if let Some(account) = item.as_object_mut() {
            let writable = account.get("writable").and_then(|v| v.as_bool()).unwrap_or(false);
            let signer = account.get("signer").and_then(|v| v.as_bool()).unwrap_or(false);
            account.entry("isMut".to_string()).or_insert(serde_json::Value::Bool(writable));
            account.entry("isSigner".to_string()).or_insert(serde_json::Value::Bool(signer));
            account.remove("optional");
            account.remove("relations");
        }
    }
    if let Some(obj) = ix.as_object_mut() {
        obj.insert("accounts".into(), serde_json::Value::Array(flat));
    }
}
