use sha2::{Digest, Sha256};

use crate::types::IdlArg;

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

/// Decode Anchor instruction arguments from raw bytes using IDL type definitions.
pub fn decode_anchor_args(data: &[u8], args: &[IdlArg]) -> serde_json::Value {
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
                (serde_json::json!(u16::from_le_bytes([data[offset], data[offset + 1]])), 2)
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
                if let Ok(pk) = solana_sdk::pubkey::Pubkey::try_from(&data[offset..offset + 32]) {
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
