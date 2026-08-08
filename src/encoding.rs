use anyhow::{Context, Result};

use crate::types::Encoding;

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
pub fn decode_from_encoding(input: &str, encoding: Encoding) -> Result<Vec<u8>> {
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

/// Decode a transaction input that may be text (Base58, Base64, Hex) or raw
/// binary bytes. Valid UTF-8 inputs go through encoding detection; anything
/// else is treated as raw transaction bytes and returned untouched.
pub fn decode_input_bytes(input: &[u8]) -> Result<Vec<u8>> {
    if let Ok(text) = std::str::from_utf8(input) {
        let trimmed = text.trim();
        let encoding = detect_encoding(trimmed);
        decode_from_encoding(trimmed, encoding)
    } else {
        Ok(input.to_vec())
    }
}
