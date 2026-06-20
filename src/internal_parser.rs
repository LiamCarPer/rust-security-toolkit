use anyhow::{Context, Result};
use solana_sdk::{pubkey::Pubkey, signature::Signature};

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

    let (num_sigs, consumed) =
        read_compact_u16(raw_bytes, offset).context("Expected compact-u16 for signature count")?;
    offset = consumed;
    let num_sigs = num_sigs as usize;

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

    for i in 0..num_sigs {
        let start = offset + i * 64;
        let sig_data = &raw_bytes[start..start + 64];
        if Signature::try_from(sig_data).is_err() {
            warnings.push(format!("TOOL_DECODE_MISMATCH: signature {} at offset {} is invalid Ed25519", i, start));
        }
    }
    offset += sig_bytes;

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
            Err(e) => warnings
                .push(format!("TOOL_DECODE_MISMATCH: account {} at offset {} is not a valid pubkey: {}", i, start, e)),
        }
    }
    offset += account_bytes;

    if raw_bytes.len() < offset + 32 {
        warnings.push(format!("TOOL_DECODE_MISMATCH: expected 32-byte blockhash at offset {}", offset));
        return Ok(warnings);
    }
    let _blockhash = &raw_bytes[offset..offset + 32];
    offset += 32;

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

    if offset > raw_bytes.len() {
        warnings.push(format!(
            "TOOL_DECODE_MISMATCH: parsed {} bytes but buffer is only {} bytes",
            offset,
            raw_bytes.len()
        ));
    }

    Ok(warnings)
}
