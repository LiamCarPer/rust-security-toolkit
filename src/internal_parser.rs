use anyhow::{Context, Result};
use solana_sdk::{pubkey::Pubkey, signature::Signature};

use crate::types::TransactionReport;

/// Read a compact-u16 (Solana short_vec length) from bytes.
///
/// LEB128-style encoding: 7-bit little-endian groups with a 0x80 continuation
/// bit, at most 3 bytes. Values that do not fit in a u16 are invalid.
fn read_compact_u16(data: &[u8], offset: usize) -> Result<(u16, usize)> {
    let mut value: u32 = 0;
    let mut shift: u32 = 0;
    let mut i = 0usize;
    loop {
        if offset + i >= data.len() {
            anyhow::bail!("Buffer exhausted while reading compact-u16");
        }
        let byte = data[offset + i];
        i += 1;
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            if value > u32::from(u16::MAX) {
                anyhow::bail!("compact-u16 value {} exceeds u16::MAX", value);
            }
            return Ok((value as u16, offset + i));
        }
        shift += 7;
        if shift > 14 {
            anyhow::bail!("compact-u16 encoded in more than 3 bytes");
        }
    }
}

/// Internal byte-level parser for `--validate-decoding`.
/// Returns a list of mismatch warnings, or an empty vec if the internal parser
/// agrees with the solana-sdk output.
///
/// Every count the parser extracts is cross-checked against the SDK-decoded
/// `report` (same bytes, same transaction), so any structural disagreement is
/// surfaced as a `TOOL_DECODE_MISMATCH:` warning.
pub fn validate_decoding(raw_bytes: &[u8], report: &TransactionReport) -> Result<Vec<String>> {
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

    if num_sigs != report.signatures.len() {
        warnings.push(format!(
            "TOOL_DECODE_MISMATCH: parser found {} signatures but SDK report has {}",
            num_sigs,
            report.signatures.len()
        ));
    }

    // Versioned messages carry a 1-byte version prefix (0x80 = v0) directly
    // after the signatures; legacy messages have no prefix byte.
    let is_v0 = if offset < raw_bytes.len() && raw_bytes[offset] == 0x80 {
        offset += 1;
        true
    } else {
        false
    };
    let report_is_v0 = report.message_version == Some(0);
    if is_v0 != report_is_v0 {
        warnings.push(format!(
            "TOOL_DECODE_MISMATCH: parser detected a {} message but SDK report message_version is {:?}",
            if is_v0 { "v0" } else { "legacy" },
            report.message_version
        ));
    }

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

    if num_accounts != report.accounts.len() {
        warnings.push(format!(
            "TOOL_DECODE_MISMATCH: parser found {} static accounts but SDK report has {}",
            num_accounts,
            report.accounts.len()
        ));
    }

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

    // In v0 messages, compiled instruction account indices are global
    // (static + ALT-loaded), so out-of-range checks must wait until the
    // address table lookups have been parsed. Legacy messages have no
    // dynamic accounts, and the check reduces to the static count.
    let mut deferred_ix_account_warnings: Vec<(usize, usize)> = Vec::new();

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
                deferred_ix_account_warnings.push((i, acct_idx));
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

    if num_ixs != report.instructions.len() {
        warnings.push(format!(
            "TOOL_DECODE_MISMATCH: parser found {} instructions but SDK report has {}",
            num_ixs,
            report.instructions.len()
        ));
    }

    let mut total_accounts = num_accounts;

    if is_v0 {
        let (num_alts, consumed) =
            read_compact_u16(raw_bytes, offset).context("Expected compact-u16 for address table lookup count")?;
        offset = consumed;
        let num_alts = num_alts as usize;

        for alt_idx in 0..num_alts {
            if raw_bytes.len() < offset + 32 {
                warnings.push(format!(
                    "TOOL_DECODE_MISMATCH: expected 32-byte address lookup table key at offset {}",
                    offset
                ));
                return Ok(warnings);
            }
            if let Err(e) = Pubkey::try_from(&raw_bytes[offset..offset + 32]) {
                warnings.push(format!(
                    "TOOL_DECODE_MISMATCH: address lookup table {} at offset {} is not a valid pubkey: {}",
                    alt_idx, offset, e
                ));
            }
            offset += 32;

            let (num_writable, consumed) = read_compact_u16(raw_bytes, offset).with_context(|| {
                format!("Expected compact-u16 for writable index count in address table lookup {}", alt_idx)
            })?;
            offset = consumed;
            let num_writable = num_writable as usize;
            for _ in 0..num_writable {
                if raw_bytes.len() <= offset {
                    warnings.push(format!(
                        "TOOL_DECODE_MISMATCH: buffer exhausted reading address table lookup {} writable index",
                        alt_idx
                    ));
                    break;
                }
                offset += 1;
            }

            let (num_readonly, consumed) = read_compact_u16(raw_bytes, offset).with_context(|| {
                format!("Expected compact-u16 for readonly index count in address table lookup {}", alt_idx)
            })?;
            offset = consumed;
            let num_readonly = num_readonly as usize;
            for _ in 0..num_readonly {
                if raw_bytes.len() <= offset {
                    warnings.push(format!(
                        "TOOL_DECODE_MISMATCH: buffer exhausted reading address table lookup {} readonly index",
                        alt_idx
                    ));
                    break;
                }
                offset += 1;
            }

            total_accounts += num_writable + num_readonly;

            if let Some(alt) = report.address_lookup_tables.get(alt_idx) {
                let report_len = alt.resolved_accounts.len();
                if num_writable + num_readonly != report_len {
                    warnings.push(format!(
                        "TOOL_DECODE_MISMATCH: address table lookup {} has {} writable + {} readonly indices but SDK report has {} resolved accounts",
                        alt_idx, num_writable, num_readonly, report_len
                    ));
                }
            }
        }

        if num_alts != report.address_lookup_tables.len() {
            warnings.push(format!(
                "TOOL_DECODE_MISMATCH: parser found {} address table lookups but SDK report has {}",
                num_alts,
                report.address_lookup_tables.len()
            ));
        }
    }

    // Instruction account indices are global (static + ALT-loaded) in v0;
    // only now is the full account range known.
    for (i, acct_idx) in deferred_ix_account_warnings {
        if acct_idx >= total_accounts {
            warnings
                .push(format!("TOOL_DECODE_MISMATCH: instruction {} references account {} out of range", i, acct_idx));
        }
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
