//! Bytecode fallback for IDL-less programs: fetch the on-chain ELF and
//! analyze it with the external `sol-azy` disassembler. Enrichment only.
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::simulator::fetch_account_data;
use crate::types::ProgramAnalysis;

const MAX_ELF_BYTES: usize = 10 * 1024 * 1024;
const SOL_AZY_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_STRINGS: usize = 50;

pub fn sol_azy_binary() -> String {
    std::env::var("RTS_SOL_AZY").unwrap_or_else(|_| "sol-azy".to_string())
}

pub fn is_available(binary: &str) -> bool {
    Command::new(binary).arg("--help").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok()
}

pub async fn fetch_program_elf(rpc_url: &str, program_id: &str) -> Result<Option<(Vec<u8>, String, Option<String>)>> {
    use solana_loader_v3_interface::state::UpgradeableLoaderState;

    let client = reqwest::Client::new();
    let Some(data) = fetch_account_data(&client, rpc_url, program_id).await? else {
        return Ok(None);
    };

    if let Some(elf) = extract_elf(&data) {
        return Ok(Some((elf, "deprecated".to_string(), None)));
    }

    let programdata_address = match bincode::deserialize::<UpgradeableLoaderState>(&data) {
        Ok(UpgradeableLoaderState::Program { programdata_address }) => programdata_address,
        Ok(UpgradeableLoaderState::ProgramData { upgrade_authority_address, .. }) => {
            return Ok(extract_elf(&data)
                .map(|elf| (elf, "upgradeable".to_string(), upgrade_authority_address.map(|p| p.to_string()))));
        }
        _ => return Ok(None),
    };

    let Some(pd_data) = fetch_account_data(&client, rpc_url, &programdata_address.to_string()).await? else {
        return Ok(None);
    };
    let authority = match bincode::deserialize::<UpgradeableLoaderState>(&pd_data) {
        Ok(UpgradeableLoaderState::ProgramData { upgrade_authority_address, .. }) => {
            upgrade_authority_address.map(|p| p.to_string())
        }
        _ => None,
    };
    Ok(extract_elf(&pd_data).map(|elf| (elf, "upgradeable".to_string(), authority)))
}

fn extract_elf(data: &[u8]) -> Option<Vec<u8>> {
    let start = data.windows(4).position(|w| w == b"\x7fELF")?;
    let elf = &data[start..];
    if elf.len() > MAX_ELF_BYTES {
        return None;
    }
    Some(elf.to_vec())
}

pub struct ReverseOutput {
    pub disassembly: String,
    pub immediate_table: String,
}

pub fn run_reverse(binary: &str, elf: &[u8], out_dir: &Path) -> Result<ReverseOutput> {
    std::fs::create_dir_all(out_dir).context("failed to create disassembly output directory")?;
    let so_path = out_dir.join("program.so");
    std::fs::write(&so_path, elf).context("failed to write program ELF")?;

    let mut child = Command::new(binary)
        .arg("reverse")
        .arg("--mode")
        .arg("both")
        .arg("--out-dir")
        .arg(out_dir)
        .arg("--bytecodes-file")
        .arg(&so_path)
        .arg("--labeling")
        .arg("--reduced")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!("failed to run '{}' (install: cargo install --git https://github.com/FuzzingLabs/sol-azy)", binary)
        })?;

    let deadline = Instant::now() + SOL_AZY_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    let mut stderr = String::new();
                    if let Some(mut handle) = child.stderr.take() {
                        use std::io::Read;
                        let _ = handle.read_to_string(&mut stderr);
                    }
                    anyhow::bail!("sol-azy exited with {}: {}", status, stderr.lines().next().unwrap_or(""));
                }
                break;
            }
            Ok(None) if Instant::now() > deadline => {
                let _ = child.kill();
                anyhow::bail!("sol-azy timed out after {}s", SOL_AZY_TIMEOUT.as_secs());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(200)),
            Err(e) => anyhow::bail!("failed waiting for sol-azy: {}", e),
        }
    }

    let disassembly = std::fs::read_to_string(out_dir.join("disassembly.out")).unwrap_or_default();
    let immediate_table = std::fs::read_to_string(out_dir.join("immediate_data_table")).unwrap_or_default();
    Ok(ReverseOutput { disassembly, immediate_table })
}

pub fn parse_syscalls(disassembly: &str) -> Vec<String> {
    const SYSCALLS: &[&str] = &[
        "sol_invoke_signed_c",
        "sol_invoke_signed_rust",
        "sol_log_",
        "sol_log_pubkey",
        "sol_log_compute_units_",
        "sol_log_data",
        "sol_memcpy_",
        "sol_memmove_",
        "sol_memcmp_",
        "sol_memset_",
        "sol_sha256",
        "sol_keccak256",
        "sol_secp256k1_recover",
        "sol_blake3",
        "sol_create_program_address",
        "sol_try_find_program_address",
        "sol_get_clock_sysvar",
        "sol_get_rent_sysvar",
        "sol_get_epoch_schedule_sysvar",
        "sol_get_return_data",
        "sol_set_return_data",
        "sol_alloc_free_",
        "sol_remaining_compute_units",
        "sol_get_processed_sibling_instruction",
        "sol_get_stack_height",
        "sol_alt_bn128",
        "sol_curve_validate_point",
        "sol_curve_group_op",
        "sol_curve_multiscalar_mul",
    ];
    let mut found: Vec<String> = SYSCALLS
        .iter()
        .filter(|name| {
            let mut start = 0;
            while let Some(pos) = disassembly[start..].find(**name) {
                let abs = start + pos;
                let after = disassembly[abs + name.len()..].chars().next();
                if !after.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
                    return true;
                }
                start = abs + name.len();
            }
            false
        })
        .map(|name| name.to_string())
        .collect();
    found.sort();
    found.dedup();
    found
}

pub fn parse_immediate_strings(immediate_table: &str) -> Vec<String> {
    let mut strings: Vec<String> = Vec::new();
    for line in immediate_table.lines() {
        let Some(start) = line.find("b\"") else { continue };
        let rest = &line[start + 2..];
        let content = match rest.find('"') {
            Some(end) => &rest[..end],
            None => rest,
        };
        if content.len() < 4 || content.len() > 160 {
            continue;
        }
        if !content.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            continue;
        }
        let noise = content.contains("library/")
            || content.contains("rustc")
            || content.contains("src/")
            || content.contains(".rs")
            || content.contains("core::")
            || content.contains("alloc::");
        if noise {
            continue;
        }
        if !strings.iter().any(|s| s == content) {
            strings.push(content.to_string());
        }
        if strings.len() >= MAX_STRINGS {
            break;
        }
    }
    strings
}

pub fn parse_lddw_candidates(disassembly: &str) -> Vec<u64> {
    let mut candidates: Vec<u64> = Vec::new();
    for line in disassembly.lines() {
        let Some(pos) = line.find("lddw") else { continue };
        let rest = &line[pos + 4..];
        let Some(hex_start) = rest.find("0x") else { continue };
        let hex_end = rest[hex_start + 2..]
            .find(|c: char| !c.is_ascii_hexdigit())
            .map(|i| hex_start + 2 + i)
            .unwrap_or(rest.len());
        let Ok(value) = u64::from_str_radix(&rest[hex_start + 2..hex_end], 16) else { continue };
        if value < 0x1_0000_0000 {
            continue;
        }
        if (0x1_0000_0000..0x4_0000_0000).contains(&value) {
            continue;
        }
        if !candidates.contains(&value) {
            candidates.push(value);
        }
        if candidates.len() >= 4096 {
            break;
        }
    }
    candidates
}

pub fn match_dispatch_prefix(data_hex: &str, candidates: &[u64]) -> Option<String> {
    let bytes = hex::decode(data_hex).ok()?;
    if bytes.len() < 8 {
        return None;
    }
    let prefix = u64::from_le_bytes(bytes[..8].try_into().ok()?);
    if candidates.contains(&prefix) { Some(hex::encode(&bytes[..8])) } else { None }
}

pub struct AnalyzeOptions {
    pub binary: String,
    pub artifact_dir: Option<PathBuf>,
}

pub async fn analyze_programs(
    rpc_url: &str,
    report: &mut crate::types::TransactionReport,
    targets: &[solana_sdk::pubkey::Pubkey],
    options: &AnalyzeOptions,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if targets.is_empty() {
        return warnings;
    }
    if !is_available(&options.binary) {
        warnings.push(
            "bytecode fallback: sol-azy is not installed (cargo install --git https://github.com/FuzzingLabs/sol-azy)"
                .to_string(),
        );
        return warnings;
    }

    for program_id in targets {
        let program_id_str = program_id.to_string();
        let fetched = match fetch_program_elf(rpc_url, &program_id_str).await {
            Ok(Some(elf)) => elf,
            Ok(None) => {
                warnings.push(format!("bytecode fallback: no program ELF found for {}", program_id_str));
                continue;
            }
            Err(e) => {
                warnings.push(format!("bytecode fallback: failed to fetch ELF for {}: {}", program_id_str, e));
                continue;
            }
        };
        let (elf, loader, upgrade_authority) = fetched;

        let artifact_dir = match &options.artifact_dir {
            Some(base) => {
                let dir = base.join(short_key(&program_id_str));
                Some(dir)
            }
            None => Some(std::env::temp_dir().join(format!("rts-solazy-{}", short_key(&program_id_str)))),
        };
        let Some(artifact_dir) = artifact_dir else { continue };

        let reverse = match run_reverse(&options.binary, &elf, &artifact_dir) {
            Ok(output) => output,
            Err(e) => {
                warnings.push(format!("bytecode fallback: sol-azy failed for {}: {}", program_id_str, e));
                continue;
            }
        };

        let syscalls = parse_syscalls(&reverse.disassembly);
        let strings = parse_immediate_strings(&reverse.immediate_table);
        let lddw = parse_lddw_candidates(&reverse.disassembly);

        let mut dispatch_candidates: Vec<String> = Vec::new();
        let mut matched_instructions: Vec<u8> = Vec::new();
        for ix in report.instructions.iter_mut() {
            if ix.program_id != program_id_str || ix.instruction_name.is_some() {
                continue;
            }
            if let Some(prefix) = match_dispatch_prefix(&ix.raw_data_hex, &lddw) {
                ix.instruction_name = Some(format!("dispatch:0x{}", prefix));
                dispatch_candidates.push(prefix);
                matched_instructions.push(ix.index);
            }
        }
        dispatch_candidates.sort();
        dispatch_candidates.dedup();

        if options.artifact_dir.is_none() {
            let _ = std::fs::remove_dir_all(&artifact_dir);
        }

        let elf_sha256 = hex::encode(Sha256::digest(&elf));
        report.program_analyses.push(ProgramAnalysis {
            program_id: program_id_str,
            loader,
            elf_size: elf.len(),
            elf_sha256,
            upgrade_authority,
            syscalls,
            strings,
            dispatch_candidates,
            matched_instructions,
            artifact_dir: options.artifact_dir.as_ref().map(|_| artifact_dir.to_string_lossy().to_string()),
        });
    }
    warnings
}

fn short_key(key: &str) -> String {
    if key.len() > 8 { key[..8].to_string() } else { key.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_elf_finds_magic_after_header() {
        let mut data = vec![0u8; 45];
        data.extend_from_slice(b"\x7fELFrest");
        let elf = extract_elf(&data).expect("elf found");
        assert_eq!(elf, b"\x7fELFrest");
    }

    #[test]
    fn extract_elf_rejects_oversized() {
        let mut data = vec![0u8; 8];
        data.extend_from_slice(b"\x7fELF");
        data.resize(MAX_ELF_BYTES + 100, 0);
        assert!(extract_elf(&data).is_none());
    }

    #[test]
    fn parse_syscalls_detects_and_boundaries() {
        let disassembly = "\
call sol_invoke_signed_c
call sol_log_
call sol_log_data
call sol_sha256
lddw r1, 0x1
";
        let syscalls = parse_syscalls(disassembly);
        assert!(syscalls.contains(&"sol_invoke_signed_c".to_string()));
        assert!(syscalls.contains(&"sol_log_".to_string()));
        assert!(syscalls.contains(&"sol_sha256".to_string()));
    }

    #[test]
    fn parse_syscalls_ignores_partial_matches() {
        let syscalls = parse_syscalls("sol_invoke_signed_custom_fn");
        assert!(syscalls.is_empty());
    }

    #[test]
    fn parse_immediate_strings_filters_noise() {
        let table = "\
0x1000043e0 (+ 0x43e0): b\"You win!\"
0x1000043f4 (+ 0x43f4): b\"Not enough data\"
0x1000044a8 (+ 0x44a8): b\"library/alloc/src/raw_vec.rs\"
0x1000044b2 (+ 0x44b2): b\"ab\"
";
        let strings = parse_immediate_strings(table);
        assert_eq!(strings, vec!["You win!".to_string(), "Not enough data".to_string()]);
    }

    #[test]
    fn parse_lddw_candidates_filters_low_and_pointer_range() {
        let disassembly = "\
lddw r1, 0x1
lddw r2, 0x2a
lddw r3, 0x1000021f8
lddw r4, 0xdeadbeefcafebabe
lddw r5, 0xdeadbeefcafebabe
";
        let candidates = parse_lddw_candidates(disassembly);
        assert_eq!(candidates, vec![0xdead_beef_cafe_babe]);
    }

    #[test]
    fn match_dispatch_prefix_matches_le_bytes() {
        let value: u64 = 0xdead_beef_cafe_babe;
        let mut data = value.to_le_bytes().to_vec();
        data.extend_from_slice(&[1, 2]);
        let hex_data = hex::encode(&data);
        assert_eq!(match_dispatch_prefix(&hex_data, &[value]), Some(hex::encode(value.to_le_bytes())));
        assert!(match_dispatch_prefix(&hex_data, &[]).is_none());
        assert!(match_dispatch_prefix("0102", &[value]).is_none());
    }
}
