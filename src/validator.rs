use crate::types::{
    IdlJson, IdlPda, KNOWN_PROGRAM_IDS, KNOWN_SYSVAR_IDS, RiskCategory, RiskFlag, RiskSeverity, TransactionReport,
};

/// Run all structural risk validations against a decoded transaction report.
pub fn validate(report: &mut TransactionReport, idl: Option<&IdlJson>) {
    let mut flags: Vec<RiskFlag> = Vec::new();

    if let Some(idl) = idl {
        validate_pda_seeds_tier1(idl, &mut flags);
        validate_pda_seeds_tier2(report, idl, &mut flags);
        validate_missing_signers(report, idl, &mut flags);
    }

    validate_writable_entities(report, &mut flags);
    validate_compute_budget(report, &mut flags);
    validate_alt_integrity(report, &mut flags);

    report.risk_flags = flags;
}

// ── Tier 1: PDA Well-Formedness (IDL-only) ───────────────────────────────────

fn validate_pda_seeds_tier1(idl: &IdlJson, flags: &mut Vec<RiskFlag>) {
    for ix in &idl.instructions {
        for account in ix.accounts.iter() {
            if let Some(ref pda) = account.pda {
                if pda.seeds.is_empty() {
                    flags.push(RiskFlag {
                        severity: RiskSeverity::Warning,
                        category: RiskCategory::PdaWellFormedness,
                        instruction_index: None,
                        message: format!(
                            "Instruction '{}': account '{}' declares PDA with empty seeds array",
                            ix.name, account.name
                        ),
                        details: "Empty seeds arrays should be verified against program source code.".to_string(),
                    });
                }

                for (seed_idx, seed) in pda.seeds.iter().enumerate() {
                    match seed.kind.as_str() {
                        "account" => {
                            if seed.account.is_none() && seed.path.is_none() {
                                flags.push(RiskFlag {
                                    severity: RiskSeverity::Warning,
                                    category: RiskCategory::PdaWellFormedness,
                                    instruction_index: None,
                                    message: format!(
                                        "Instruction '{}': account '{}' PDA seed #{} of kind 'account' has no path/account reference",
                                        ix.name, account.name, seed_idx
                                    ),
                                    details: "Account-reference seeds must specify which account to use.".to_string(),
                                });
                            }
                        }
                        "arg" => {
                            if seed.path.is_none() {
                                flags.push(RiskFlag {
                                    severity: RiskSeverity::Info,
                                    category: RiskCategory::PdaWellFormedness,
                                    instruction_index: None,
                                    message: format!(
                                        "Instruction '{}': account '{}' PDA seed #{} of kind 'arg' has no path reference; argument-resolved seeds require runtime values",
                                        ix.name, account.name, seed_idx
                                    ),
                                    details: "Argument seeds cannot be statically verified at the transaction layer.".to_string(),
                                });
                            }
                        }
                        "const" => {
                            if seed.value.as_ref().is_none_or(|v| v.is_empty()) {
                                flags.push(RiskFlag {
                                    severity: RiskSeverity::Warning,
                                    category: RiskCategory::PdaWellFormedness,
                                    instruction_index: None,
                                    message: format!(
                                        "Instruction '{}': account '{}' PDA seed #{} of kind 'const' has empty value",
                                        ix.name, account.name, seed_idx
                                    ),
                                    details: "Empty const seeds produce trivial PDAs.".to_string(),
                                });
                            }
                        }
                        other => {
                            flags.push(RiskFlag {
                                severity: RiskSeverity::Info,
                                category: RiskCategory::PdaWellFormedness,
                                instruction_index: None,
                                message: format!(
                                    "Instruction '{}': account '{}' PDA seed #{} has unrecognized kind '{}'",
                                    ix.name, account.name, seed_idx, other
                                ),
                                details: "Only 'const', 'account', and 'arg' seed kinds are analyzed.".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
}

// ── Tier 2: Runtime PDA Seed Verification (requires tx + IDL) ─────────────────

fn validate_pda_seeds_tier2(report: &mut TransactionReport, idl: &IdlJson, flags: &mut Vec<RiskFlag>) {
    use solana_sdk::pubkey::Pubkey;
    use std::str::FromStr;

    for decoded_ix in &report.instructions {
        let ix_name = match &decoded_ix.instruction_name {
            Some(name) => name,
            None => continue,
        };

        let idl_ix = match idl.find_instruction(ix_name) {
            Some(ix) => ix,
            None => continue,
        };

        let program_id = match Pubkey::from_str(&decoded_ix.program_id) {
            Ok(pk) => pk,
            Err(_) => continue,
        };

        for (acc_idx, idl_account) in idl_ix.accounts.iter().enumerate() {
            let pda = match &idl_account.pda {
                Some(pda) => pda,
                None => continue,
            };

            let mapped = match decoded_ix.accounts.get(acc_idx) {
                Some(a) => a,
                None => continue,
            };

            let actual_pubkey = match Pubkey::from_str(&mapped.pubkey) {
                Ok(pk) => pk,
                Err(_) => continue,
            };

            match try_find_pda(pda, report, decoded_ix, &program_id) {
                Ok((expected_pubkey, bump)) => {
                    if let Some(account) = report.accounts.get_mut(mapped.account_index as usize) {
                        account.pda_info = Some(crate::types::PdaInfo {
                            seeds_declared: describe_seeds_vec(pda),
                            bump: Some(bump),
                            expected_address: Some(expected_pubkey.to_string()),
                        });
                    }
                    if expected_pubkey != actual_pubkey {
                        flags.push(RiskFlag {
                            severity: RiskSeverity::Critical,
                            category: RiskCategory::PdaSeedMismatch,
                            instruction_index: Some(decoded_ix.index),
                            message: format!(
                                "Instruction '{}': PDA Seed Mismatch for account '{}' (Account #{})",
                                ix_name, idl_account.name, mapped.account_index
                            ),
                            details: format!(
                                "Expected PDA {} derived from seeds [{}], but transaction contains {}.\n\
                                 Possible account substitution or seed manipulation.",
                                expected_pubkey,
                                describe_seeds(pda),
                                actual_pubkey
                            ),
                        });
                    }
                }
                Err(e) => {
                    flags.push(RiskFlag {
                        severity: RiskSeverity::Warning,
                        category: RiskCategory::PdaSeedMismatch,
                        instruction_index: Some(decoded_ix.index),
                        message: format!(
                            "Instruction '{}': Cannot verify PDA for account '{}'",
                            ix_name, idl_account.name
                        ),
                        details: e,
                    });
                }
            }
        }
    }
}

fn try_find_pda(
    pda: &IdlPda,
    report: &TransactionReport,
    ix: &crate::types::DecodedInstruction,
    program_id: &solana_sdk::pubkey::Pubkey,
) -> Result<(solana_sdk::pubkey::Pubkey, u8), String> {
    use solana_sdk::pubkey::Pubkey;

    let mut seed_bytes: Vec<Vec<u8>> = Vec::new();
    for seed in &pda.seeds {
        match seed.kind.as_str() {
            "const" => {
                let val = seed.value.as_ref().ok_or("const seed missing value")?;
                seed_bytes.push(val.clone());
            }
            "account" => {
                let path = seed
                    .path
                    .as_ref()
                    .or(seed.account.as_ref())
                    .ok_or("account seed missing path/account reference")?;
                let account_pubkey = resolve_account_path(path, report, ix)?;
                seed_bytes.push(account_pubkey.to_bytes().to_vec());
            }
            "arg" => {
                return Err(format!(
                    "Cannot resolve arg seed '{}' without runtime argument values",
                    seed.path.as_deref().unwrap_or("unknown")
                ));
            }
            _ => {
                return Err(format!("Unsupported seed kind: {}", seed.kind));
            }
        }
    }

    let seed_slices: Vec<&[u8]> = seed_bytes.iter().map(|v| v.as_slice()).collect();
    let (pk, bump) = Pubkey::find_program_address(&seed_slices, program_id);
    Ok((pk, bump))
}

fn resolve_account_path(
    path: &str,
    report: &TransactionReport,
    ix: &crate::types::DecodedInstruction,
) -> Result<solana_sdk::pubkey::Pubkey, String> {
    use solana_sdk::pubkey::Pubkey;
    use std::str::FromStr;

    for account in &ix.accounts {
        if account.name.as_deref() == Some(path) {
            return Pubkey::from_str(&account.pubkey)
                .map_err(|e| format!("Invalid pubkey in account '{}': {}", path, e));
        }
    }

    for account in &report.accounts {
        if account.role.as_deref() == Some(path) || account.role.as_deref() == Some(&format!("signer+{}", path)) {
            return Pubkey::from_str(&account.pubkey)
                .map_err(|e| format!("Invalid pubkey in account '{}': {}", path, e));
        }
    }

    Err(format!("Could not resolve account reference '{}'", path))
}

fn describe_seeds(pda: &IdlPda) -> String {
    describe_seeds_vec(pda).join(", ")
}

fn describe_seeds_vec(pda: &IdlPda) -> Vec<String> {
    pda.seeds
        .iter()
        .map(|s| match s.kind.as_str() {
            "const" => {
                let val = s.value.as_ref().map(|v| String::from_utf8(v.clone()).unwrap_or_else(|_| hex::encode(v)));
                format!("\"{}\"", val.as_deref().unwrap_or("?"))
            }
            "account" => format!("account({})", s.path.as_deref().or(s.account.as_deref()).unwrap_or("?")),
            "arg" => format!("arg({})", s.path.as_deref().unwrap_or("?")),
            other => format!("{}(?)", other),
        })
        .collect()
}

// ── Missing Signer Check ─────────────────────────────────────────────────────

fn validate_missing_signers(report: &TransactionReport, idl: &IdlJson, flags: &mut Vec<RiskFlag>) {
    for decoded_ix in &report.instructions {
        let ix_name = match &decoded_ix.instruction_name {
            Some(name) => name,
            None => continue,
        };

        let idl_ix = match idl.find_instruction(ix_name) {
            Some(ix) => ix,
            None => continue,
        };

        for (acc_idx, idl_account) in idl_ix.accounts.iter().enumerate() {
            if !idl_account.is_signer {
                continue;
            }

            let mapped = match decoded_ix.accounts.get(acc_idx) {
                Some(a) => a,
                None => continue,
            };

            if !mapped.is_signer {
                flags.push(RiskFlag {
                    severity: RiskSeverity::Critical,
                    category: RiskCategory::MissingSigner,
                    instruction_index: Some(decoded_ix.index),
                    message: format!(
                        "Instruction '{}': Missing Signer — account '{}' (Account #{}) is declared \
                         as requiring a signature in the IDL, but appears as a non-signer in the \
                         transaction message header.",
                        ix_name, idl_account.name, mapped.account_index
                    ),
                    details: format!(
                        "IDL declares account '{}' as isSigner=true, but tx header shows it as non-signer. \
                         This may indicate a signer privilege escalation or a misconfigured transaction.",
                        idl_account.name
                    ),
                });
            }
        }
    }
}

// ── Insecure Writable Entities ───────────────────────────────────────────────

fn validate_writable_entities(report: &TransactionReport, flags: &mut Vec<RiskFlag>) {
    for account in &report.accounts {
        if !account.is_writable {
            continue;
        }

        let pubkey = &account.pubkey;

        if KNOWN_SYSVAR_IDS.contains(&pubkey.as_str()) {
            flags.push(RiskFlag {
                severity: RiskSeverity::Critical,
                category: RiskCategory::InsecureWritable,
                instruction_index: None,
                message: format!(
                    "Insecure Writable Account: sysvar '{}' (Account #{}) is marked writable. \
                     Sysvar accounts must be read-only.",
                    pubkey, account.index
                ),
                details: "Writing to sysvars is a known fee-locking and account-hijacking vector. \
                          This transaction should be flagged for audit review."
                    .to_string(),
            });
        }

        if KNOWN_PROGRAM_IDS.contains(&pubkey.as_str()) {
            flags.push(RiskFlag {
                severity: RiskSeverity::Critical,
                category: RiskCategory::InsecureWritable,
                instruction_index: None,
                message: format!(
                    "Insecure Writable Account: known program '{}' (Account #{}) is marked writable. \
                     Program executable accounts must be read-only.",
                    pubkey, account.index
                ),
                details: "The transaction marks a program executable as writable. \
                          This is a strong indicator of a fee-locking attack or account hijacking attempt."
                    .to_string(),
            });
        }
    }
}

// ── Compute Budget Analysis ──────────────────────────────────────────────────

fn validate_compute_budget(report: &TransactionReport, flags: &mut Vec<RiskFlag>) {
    let cb = match &report.compute_budget {
        Some(cb) => cb,
        None => {
            flags.push(RiskFlag {
                severity: RiskSeverity::Warning,
                category: RiskCategory::MissingComputeUnitLimit,
                instruction_index: None,
                message: "Missing Compute Budget: no explicit CU limit set. \
                         Transaction defaults to 200k CU per instruction — a potential spam/DoS vector."
                    .to_string(),
                details: "Without an explicit SetComputeUnitLimit, the transaction uses the default \
                          200k CU per instruction, which may be exploited for resource exhaustion."
                    .to_string(),
            });
            return;
        }
    };

    if !cb.compute_unit_limit_set {
        flags.push(RiskFlag {
            severity: RiskSeverity::Warning,
            category: RiskCategory::MissingComputeUnitLimit,
            instruction_index: None,
            message: "Missing Compute Budget: no explicit CU limit set.".to_string(),
            details: "Without an explicit SetComputeUnitLimit, the transaction may exceed expected CU bounds."
                .to_string(),
        });
    }

    if cb.is_reordered {
        for &pos in &cb.compute_budget_positions {
            if pos > 0 {
                flags.push(RiskFlag {
                    severity: RiskSeverity::Warning,
                    category: RiskCategory::ComputeBudgetReordering,
                    instruction_index: Some(pos as u8),
                    message: format!(
                        "Compute Budget Reordering: ComputeBudget instruction at index #{} (expected at index #0). \
                         Fee/limit manipulation may affect execution priority.",
                        pos
                    ),
                    details: "Attackers can inject reordered ComputeBudget instructions to manipulate \
                              priority fees or trigger frontrunning. All ComputeBudget instructions \
                              should be at the start of the transaction."
                        .to_string(),
                });
            }
        }
    }

    for &ix_idx in &cb.high_cu_instructions {
        flags.push(RiskFlag {
            severity: RiskSeverity::Warning,
            category: RiskCategory::HighComputeUnitUsage,
            instruction_index: Some(ix_idx),
            message: format!(
                "High Compute Unit Usage: Instruction #{} estimated CU cost exceeds threshold. \
                 This may indicate an expensive operation or potential resource exhaustion vector.",
                ix_idx
            ),
            details: "Instructions consuming a disproportionate share of the CU budget should be \
                      reviewed for necessity and potential optimization or abuse."
                .to_string(),
        });
    }
}

// ── ALT Integrity Validation ─────────────────────────────────────────────────

fn validate_alt_integrity(report: &TransactionReport, flags: &mut Vec<RiskFlag>) {
    for alt in &report.address_lookup_tables {
        if alt.resolved_accounts.is_empty() {
            flags.push(RiskFlag {
                severity: RiskSeverity::Warning,
                category: RiskCategory::AltIntegrity,
                instruction_index: None,
                message: format!(
                    "ALT Integrity: lookup table '{}' resolves zero accounts. \
                     The table may be empty, closed, or not properly loaded.",
                    alt.table_address
                ),
                details: "Empty ALT entries can cause transaction landing failures or be exploited \
                          for account resolution attacks."
                    .to_string(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    #[test]
    fn test_empty_seeds_flag() {
        let idl = IdlJson {
            version: "0.1.0".into(),
            name: "test_program".into(),
            instructions: vec![IdlInstruction {
                name: "test_ix".into(),
                accounts: vec![IdlAccountItem {
                    name: "vault".into(),
                    is_mut: true,
                    is_signer: false,
                    pda: Some(IdlPda { seeds: vec![] }),
                    desc: None,
                }],
                args: vec![],
            }],
            accounts: vec![],
            types: vec![],
        };

        let mut flags = Vec::new();
        validate_pda_seeds_tier1(&idl, &mut flags);
        assert!(!flags.is_empty());
        assert_eq!(flags[0].category, RiskCategory::PdaWellFormedness);
    }

    #[test]
    fn test_missing_signer_flag() {
        let idl = IdlJson {
            version: "0.1.0".into(),
            name: "test_program".into(),
            instructions: vec![IdlInstruction {
                name: "transfer".into(),
                accounts: vec![IdlAccountItem {
                    name: "authority".into(),
                    is_mut: false,
                    is_signer: true,
                    pda: None,
                    desc: None,
                }],
                args: vec![],
            }],
            accounts: vec![],
            types: vec![],
        };

        let report = TransactionReport {
            status: "OK".into(),
            fee_payer: "11111111111111111111111111111111".into(),
            signatures: vec![],
            recent_blockhash: "11111111111111111111111111111111".into(),
            message_version: None,
            accounts: vec![],
            instructions: vec![DecodedInstruction {
                index: 0,
                program_id: "11111111111111111111111111111111".into(),
                program_name: "System Program".into(),
                instruction_name: Some("transfer".into()),
                accounts: vec![MappedAccount {
                    name: Some("authority".into()),
                    pubkey: "11111111111111111111111111111111".into(),
                    account_index: 0,
                    is_signer: false,
                    is_writable: true,
                }],
                data: serde_json::Value::Null,
                raw_data_hex: String::new(),
            }],
            address_lookup_tables: vec![],
            compute_budget: None,
            risk_flags: vec![],
            simulation: None,
            warnings: vec![],
        };

        let mut flags = Vec::new();
        validate_missing_signers(&report, &idl, &mut flags);
        assert!(!flags.is_empty());
        assert_eq!(flags[0].category, RiskCategory::MissingSigner);
    }

    #[test]
    fn test_writable_sysvar_flag() {
        let report = TransactionReport {
            status: "OK".into(),
            fee_payer: "11111111111111111111111111111111".into(),
            signatures: vec![],
            recent_blockhash: "11111111111111111111111111111111".into(),
            message_version: None,
            accounts: vec![AccountInfo {
                index: 0,
                pubkey: "SysvarRent111111111111111111111111111111111".into(),
                is_signer: false,
                is_writable: true,
                role: Some("writable".into()),
                pda_info: None,
            }],
            instructions: vec![],
            address_lookup_tables: vec![],
            compute_budget: None,
            risk_flags: vec![],
            simulation: None,
            warnings: vec![],
        };

        let mut flags = Vec::new();
        validate_writable_entities(&report, &mut flags);
        assert!(!flags.is_empty());
        assert_eq!(flags[0].category, RiskCategory::InsecureWritable);
    }

    #[test]
    fn test_no_issues_on_clean_report() {
        let mut report = TransactionReport {
            status: "OK".into(),
            fee_payer: "11111111111111111111111111111111".into(),
            signatures: vec![],
            recent_blockhash: "11111111111111111111111111111111".into(),
            message_version: None,
            accounts: vec![AccountInfo {
                index: 0,
                pubkey: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".into(),
                is_signer: false,
                is_writable: false,
                role: Some("readonly".into()),
                pda_info: None,
            }],
            instructions: vec![],
            address_lookup_tables: vec![],
            compute_budget: Some(ComputeBudgetInfo {
                compute_unit_limit: 150_000,
                compute_unit_price: 0,
                compute_unit_limit_set: true,
                compute_budget_positions: vec![0],
                is_reordered: false,
                high_cu_instructions: vec![],
            }),
            risk_flags: vec![],
            simulation: None,
            warnings: vec![],
        };

        validate(&mut report, None);
        assert!(report.risk_flags.is_empty());
    }
}
