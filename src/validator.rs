use crate::types::{
    ExpectationsDoc, IdlJson, IdlPda, KNOWN_PROGRAM_IDS, KNOWN_SYSVAR_IDS, ProgramSchema, RiskCategory, RiskFlag,
    RiskSeverity, TransactionReport,
};

/// Run all structural risk validations against a decoded transaction report.
pub fn validate(report: &mut TransactionReport, schema: Option<&ProgramSchema>) {
    let mut flags: Vec<RiskFlag> = Vec::new();

    match schema {
        Some(ProgramSchema::Idl(idl)) => {
            validate_pda_seeds_tier1(idl, &mut flags);
            validate_pda_seeds_tier2(report, idl, &mut flags);
            validate_missing_signers(report, idl, &mut flags);
            validate_idl_account_counts(report, idl, &mut flags);
        }
        Some(ProgramSchema::Native(exp)) => {
            validate_native_pda_seeds_tier1(exp, &mut flags);
            validate_native_pda_seeds_tier2(report, exp, &mut flags);
            validate_native_missing_signers(report, exp, &mut flags);
            validate_native_writable_roles(report, exp, &mut flags);
            validate_native_account_counts(report, exp, &mut flags);
        }
        None => {}
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

// ── IDL Account Count Consistency ────────────────────────────────────────────

/// Flag instructions whose compiled account list is longer than the IDL's
/// declared account list (accounting for the program id that Anchor appends as
/// the final account meta). Positional IDL-to-transaction account mapping is
/// unreliable in this case, so signer/PDA checks may point at the wrong
/// accounts. Shorter compiled lists are legitimate (duplicate-key dedup).
fn validate_idl_account_counts(report: &TransactionReport, idl: &IdlJson, flags: &mut Vec<RiskFlag>) {
    for decoded_ix in &report.instructions {
        let ix_name = match &decoded_ix.instruction_name {
            Some(name) => name,
            None => continue,
        };
        let idl_ix = match idl.find_instruction(ix_name) {
            Some(ix) => ix,
            None => continue,
        };

        let idl_count = idl_ix.accounts.len();
        let compiled_count = decoded_ix.accounts.len();
        let has_appended_program_id =
            decoded_ix.accounts.last().map(|a| a.pubkey == decoded_ix.program_id).unwrap_or(false);
        let expected = idl_count + usize::from(has_appended_program_id);

        if compiled_count > expected {
            flags.push(RiskFlag {
                severity: RiskSeverity::Warning,
                category: RiskCategory::IdlAccountMismatch,
                instruction_index: Some(decoded_ix.index),
                message: format!(
                    "Instruction '{}': transaction lists {} accounts but the IDL declares {} — \
                     positional account mapping may be misaligned",
                    ix_name, compiled_count, idl_count
                ),
                details: "The compiled instruction account list is longer than the IDL's declared \
                          accounts (accounting for the appended program id). Account-role and PDA \
                          checks for this instruction may map to the wrong accounts."
                    .to_string(),
            });
        }
    }
}

// ── Native expectations: PDA Well-Formedness (tier 1) ─────────────────────────

fn validate_native_pda_seeds_tier1(exp: &ExpectationsDoc, flags: &mut Vec<RiskFlag>) {
    for ix in &exp.instructions {
        for account in ix.accounts.iter().filter(|a| a.pda.is_some()) {
            let pda = account.pda.as_ref().unwrap();
            if pda.seeds.is_empty() && pda.dynamic_seed_count == 0 {
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
        }
    }
}

// ── Native expectations: Runtime PDA Seed Verification (tier 2) ───────────────

fn validate_native_pda_seeds_tier2(report: &mut TransactionReport, exp: &ExpectationsDoc, flags: &mut Vec<RiskFlag>) {
    use solana_sdk::pubkey::Pubkey;
    use std::str::FromStr;

    for decoded_ix in &report.instructions {
        let ix_name = match &decoded_ix.instruction_name {
            Some(name) => name,
            None => continue,
        };
        let exp_ix = match exp.find_instruction(ix_name) {
            Some(ix) => ix,
            None => continue,
        };
        let program_id = match Pubkey::from_str(&decoded_ix.program_id) {
            Ok(pk) => pk,
            Err(_) => continue,
        };

        for exp_account in &exp_ix.accounts {
            let pda = match &exp_account.pda {
                Some(pda) => pda,
                None => continue,
            };
            let mapped = match decoded_ix.accounts.get(exp_account.index) {
                Some(a) => a,
                None => continue,
            };
            let actual_pubkey = match Pubkey::from_str(&mapped.pubkey) {
                Ok(pk) => pk,
                Err(_) => continue,
            };

            if pda.dynamic_seed_count > 0 {
                flags.push(RiskFlag {
                    severity: RiskSeverity::Warning,
                    category: RiskCategory::PdaSeedMismatch,
                    instruction_index: Some(decoded_ix.index),
                    message: format!(
                        "Instruction '{}': Cannot fully verify PDA for account '{}' — {} seed(s) depend on runtime values",
                        ix_name, exp_account.name, pda.dynamic_seed_count
                    ),
                    details: "Only literal seeds are exported by sat's expectations; argument/key-derived \
                              seeds can only be verified on-chain at execution time."
                        .to_string(),
                });
            }

            if pda.seeds.is_empty() {
                continue;
            }

            let seed_bytes: Vec<Vec<u8>> = pda.seeds.iter().map(|s| s.as_bytes().to_vec()).collect();
            let seed_slices: Vec<&[u8]> = seed_bytes.iter().map(|v| v.as_slice()).collect();
            let (expected_pubkey, bump) = Pubkey::find_program_address(&seed_slices, &program_id);

            if let Some(account) = report.accounts.get_mut(mapped.account_index as usize) {
                account.pda_info = Some(crate::types::PdaInfo {
                    seeds_declared: pda.seeds.clone(),
                    bump: Some(bump),
                    expected_address: Some(expected_pubkey.to_string()),
                });
            }
            if expected_pubkey != actual_pubkey {
                let note = if pda.seeds.iter().any(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())) {
                    " (note: numeric literal seeds are exported by sat as strings; derivation assumes UTF-8 bytes)"
                } else {
                    ""
                };
                flags.push(RiskFlag {
                    severity: RiskSeverity::Critical,
                    category: RiskCategory::PdaSeedMismatch,
                    instruction_index: Some(decoded_ix.index),
                    message: format!(
                        "Instruction '{}': PDA Seed Mismatch for account '{}' (Account #{})",
                        ix_name, exp_account.name, mapped.account_index
                    ),
                    details: format!(
                        "Expected PDA {} derived from seeds [{}], but transaction contains {}.{}",
                        expected_pubkey,
                        pda.seeds.join(", "),
                        actual_pubkey,
                        note
                    ),
                });
            }
        }
    }
}

// ── Native expectations: Missing Signer ──────────────────────────────────────

fn validate_native_missing_signers(report: &TransactionReport, exp: &ExpectationsDoc, flags: &mut Vec<RiskFlag>) {
    for decoded_ix in &report.instructions {
        let ix_name = match &decoded_ix.instruction_name {
            Some(name) => name,
            None => continue,
        };
        let exp_ix = match exp.find_instruction(ix_name) {
            Some(ix) => ix,
            None => continue,
        };
        for exp_account in &exp_ix.accounts {
            if !exp_account.is_signer_expected {
                continue;
            }
            let mapped = match decoded_ix.accounts.get(exp_account.index) {
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
                         as requiring a signature in the program expectations, but appears as a \
                         non-signer in the transaction message header.",
                        ix_name, exp_account.name, mapped.account_index
                    ),
                    details: format!(
                        "SAT-native expectations declare account '{}' as signer-expected, but tx header \
                         shows it as non-signer. This may indicate a signer privilege escalation or a \
                         misconfigured transaction.",
                        exp_account.name
                    ),
                });
            }
        }
    }
}

// ── Native expectations: Writable Role Mismatch ──────────────────────────────

fn validate_native_writable_roles(report: &TransactionReport, exp: &ExpectationsDoc, flags: &mut Vec<RiskFlag>) {
    for decoded_ix in &report.instructions {
        let ix_name = match &decoded_ix.instruction_name {
            Some(name) => name,
            None => continue,
        };
        let exp_ix = match exp.find_instruction(ix_name) {
            Some(ix) => ix,
            None => continue,
        };
        for exp_account in &exp_ix.accounts {
            if !exp_account.is_writable_expected {
                continue;
            }
            let mapped = match decoded_ix.accounts.get(exp_account.index) {
                Some(a) => a,
                None => continue,
            };
            if !mapped.is_writable {
                flags.push(RiskFlag {
                    severity: RiskSeverity::Warning,
                    category: RiskCategory::WritableMismatch,
                    instruction_index: Some(decoded_ix.index),
                    message: format!(
                        "Instruction '{}': account '{}' (Account #{}) is expected to be writable per \
                         program expectations but is read-only in the transaction.",
                        ix_name, exp_account.name, mapped.account_index
                    ),
                    details: "The program source marks this account as written; a read-only account in \
                              the message would fail at runtime or indicate a misconfigured transaction."
                        .to_string(),
                });
            }
        }
    }
}

// ── Native expectations: Account Count Consistency ───────────────────────────

fn validate_native_account_counts(report: &TransactionReport, exp: &ExpectationsDoc, flags: &mut Vec<RiskFlag>) {
    for decoded_ix in &report.instructions {
        let ix_name = match &decoded_ix.instruction_name {
            Some(name) => name,
            None => continue,
        };
        let exp_ix = match exp.find_instruction(ix_name) {
            Some(ix) => ix,
            None => continue,
        };
        let exp_count = exp_ix.accounts.len();
        let compiled_count = decoded_ix.accounts.len();
        if compiled_count > exp_count {
            flags.push(RiskFlag {
                severity: RiskSeverity::Warning,
                category: RiskCategory::NativeAccountMismatch,
                instruction_index: Some(decoded_ix.index),
                message: format!(
                    "Instruction '{}': transaction lists {} accounts but the expectations declare {} — \
                     positional account mapping may be misaligned",
                    ix_name, compiled_count, exp_count
                ),
                details: "The compiled instruction account list is longer than the expectations document's \
                          declared accounts. Account-role and PDA checks for this instruction may map to \
                          the wrong accounts."
                    .to_string(),
            });
        }
    }
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
        for (prefix_idx, &pos) in cb.compute_budget_positions.iter().enumerate() {
            if pos != prefix_idx {
                flags.push(RiskFlag {
                    severity: RiskSeverity::Warning,
                    category: RiskCategory::ComputeBudgetReordering,
                    instruction_index: Some(pos as u8),
                    message: format!(
                        "Compute Budget Reordering: ComputeBudget instruction at index #{} appears \
                         after non-ComputeBudget instructions. ComputeBudget instructions must be \
                         the first instructions in the message.",
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
                token_amount: None,
            }],
            address_lookup_tables: vec![],
            compute_budget: None,
            risk_flags: vec![],
            simulation: None,
            warnings: vec![],
            signature_verification: vec![],
            inner_instructions: vec![],
            balance_changes_sol: vec![],
            token_balance_changes: vec![],
            oracle_feeds: Vec::new(),
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
            signature_verification: vec![],
            inner_instructions: vec![],
            balance_changes_sol: vec![],
            token_balance_changes: vec![],
            oracle_feeds: Vec::new(),
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
                priority_fee_lamports: 0,
                priority_fee_actual: None,
            }),
            risk_flags: vec![],
            simulation: None,
            warnings: vec![],
            signature_verification: vec![],
            inner_instructions: vec![],
            balance_changes_sol: vec![],
            token_balance_changes: vec![],
            oracle_feeds: Vec::new(),
        };

        validate(&mut report, None);
        assert!(report.risk_flags.is_empty());
    }

    // ── Native expectations checks ────────────────────────────────────────────

    const NATIVE_EXPECTATIONS: &str = r#"{
      "program_name": "program",
      "program_id": "MangoPid1111111111111111111111111111111111",
      "source": "native",
      "instructions": [
        {
          "name": "WithdrawMsrm",
          "discriminator_hex": "24",
          "handler": "withdraw_msrm",
          "accounts": [
            {"name": "mango_group_ai", "index": 0, "is_signer_expected": false, "is_writable_expected": false, "pda": null},
            {"name": "owner_ai", "index": 2, "is_signer_expected": true, "is_writable_expected": false, "pda": null},
            {"name": "vault_ai", "index": 3, "is_signer_expected": false, "is_writable_expected": true, "pda": null}
          ]
        },
        {
          "name": "withdraw_escrow",
          "discriminator_hex": "25",
          "handler": "withdraw_escrow",
          "accounts": [
            {"name": "escrow", "index": 0, "is_signer_expected": false, "is_writable_expected": true,
             "pda": {"seeds": ["escrow"], "dynamic_seed_count": 0}},
            {"name": "authority", "index": 1, "is_signer_expected": true, "is_writable_expected": false, "pda": null}
          ]
        },
        {
          "name": "withdraw_dynamic",
          "discriminator_hex": "26",
          "handler": "withdraw_dynamic",
          "accounts": [
            {"name": "escrow", "index": 0, "is_signer_expected": false, "is_writable_expected": false,
             "pda": {"seeds": ["escrow"], "dynamic_seed_count": 1}}
          ]
        }
      ]
    }"#;

    fn native_exp() -> ExpectationsDoc {
        serde_json::from_str(NATIVE_EXPECTATIONS).expect("parse native expectations")
    }

    fn native_mapped(pubkey: String, account_index: u8, is_signer: bool, is_writable: bool) -> MappedAccount {
        MappedAccount { name: None, pubkey, account_index, is_signer, is_writable }
    }

    fn native_report(program_id: String, name: &str, accounts: Vec<MappedAccount>) -> TransactionReport {
        let report_accounts: Vec<AccountInfo> = accounts
            .iter()
            .enumerate()
            .map(|(i, a)| AccountInfo {
                index: i as u8,
                pubkey: a.pubkey.clone(),
                is_signer: a.is_signer,
                is_writable: a.is_writable,
                role: None,
                pda_info: None,
            })
            .collect();
        TransactionReport {
            status: "OK".into(),
            fee_payer: "11111111111111111111111111111111".into(),
            signatures: vec![],
            recent_blockhash: "11111111111111111111111111111111".into(),
            message_version: None,
            accounts: report_accounts,
            instructions: vec![DecodedInstruction {
                index: 0,
                program_id,
                program_name: "Mango".into(),
                instruction_name: Some(name.to_string()),
                accounts,
                data: serde_json::Value::Null,
                raw_data_hex: String::new(),
                token_amount: None,
            }],
            address_lookup_tables: vec![],
            compute_budget: None,
            risk_flags: vec![],
            simulation: None,
            warnings: vec![],
            signature_verification: vec![],
            inner_instructions: vec![],
            balance_changes_sol: vec![],
            token_balance_changes: vec![],
            oracle_feeds: Vec::new(),
        }
    }

    #[test]
    fn native_missing_signer_flags_critical() {
        let exp = native_exp();
        let report = native_report(
            "MangoPid1111111111111111111111111111111111".into(),
            "WithdrawMsrm",
            vec![
                native_mapped("pk0".into(), 0, false, false),
                native_mapped("pk1".into(), 1, false, false),
                native_mapped("pk2".into(), 2, false, false),
                native_mapped("pk3".into(), 3, false, false),
            ],
        );
        let mut flags = Vec::new();
        validate_native_missing_signers(&report, &exp, &mut flags);
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].category, RiskCategory::MissingSigner);
        assert_eq!(flags[0].severity, RiskSeverity::Critical);
        assert!(flags[0].message.contains("owner_ai"));
    }

    #[test]
    fn native_clean_signer_no_flag() {
        let exp = native_exp();
        let report = native_report(
            "MangoPid1111111111111111111111111111111111".into(),
            "WithdrawMsrm",
            vec![
                native_mapped("pk0".into(), 0, false, false),
                native_mapped("pk1".into(), 1, false, false),
                native_mapped("pk2".into(), 2, true, false),
                native_mapped("pk3".into(), 3, false, true),
            ],
        );
        let mut flags = Vec::new();
        validate_native_missing_signers(&report, &exp, &mut flags);
        assert!(flags.is_empty());
    }

    #[test]
    fn native_pda_tier2_mismatch_critical() {
        use solana_sdk::pubkey::Pubkey;
        let exp = native_exp();
        let program_id = Pubkey::new_unique();
        let (expected, _) = Pubkey::find_program_address(&[b"escrow"], &program_id);
        let mut report = native_report(
            program_id.to_string(),
            "withdraw_escrow",
            vec![
                native_mapped(Pubkey::new_unique().to_string(), 0, false, true),
                native_mapped(Pubkey::new_unique().to_string(), 1, true, false),
            ],
        );
        let mut flags = Vec::new();
        validate_native_pda_seeds_tier2(&mut report, &exp, &mut flags);
        let pda = report.accounts[0].pda_info.as_ref().expect("pda_info populated");
        assert_eq!(pda.expected_address.as_deref(), Some(expected.to_string().as_str()));
        assert!(pda.bump.is_some());
        assert!(
            flags.iter().any(|f| f.category == RiskCategory::PdaSeedMismatch && f.severity == RiskSeverity::Critical)
        );
    }

    #[test]
    fn native_pda_tier2_match_no_flag() {
        use solana_sdk::pubkey::Pubkey;
        let exp = native_exp();
        let program_id = Pubkey::new_unique();
        let (expected, _) = Pubkey::find_program_address(&[b"escrow"], &program_id);
        let mut report = native_report(
            program_id.to_string(),
            "withdraw_escrow",
            vec![
                native_mapped(expected.to_string(), 0, false, true),
                native_mapped(Pubkey::new_unique().to_string(), 1, true, false),
            ],
        );
        let mut flags = Vec::new();
        validate_native_pda_seeds_tier2(&mut report, &exp, &mut flags);
        assert!(
            !flags.iter().any(|f| f.category == RiskCategory::PdaSeedMismatch && f.severity == RiskSeverity::Critical)
        );
        assert!(report.accounts[0].pda_info.is_some());
    }

    #[test]
    fn native_dynamic_seeds_warning() {
        use solana_sdk::pubkey::Pubkey;
        let exp = native_exp();
        let program_id = Pubkey::new_unique();
        let (expected, _) = Pubkey::find_program_address(&[b"escrow"], &program_id);
        let mut report = native_report(
            program_id.to_string(),
            "withdraw_dynamic",
            vec![native_mapped(expected.to_string(), 0, false, false)],
        );
        let mut flags = Vec::new();
        validate_native_pda_seeds_tier2(&mut report, &exp, &mut flags);
        assert!(
            flags.iter().any(|f| f.category == RiskCategory::PdaSeedMismatch && f.severity == RiskSeverity::Warning)
        );
        assert!(flags[0].message.contains("runtime values"));
        assert!(!flags.iter().any(|f| f.severity == RiskSeverity::Critical));
    }

    #[test]
    fn native_writable_mismatch_warning() {
        let exp = native_exp();
        let report = native_report(
            "MangoPid1111111111111111111111111111111111".into(),
            "WithdrawMsrm",
            vec![
                native_mapped("pk0".into(), 0, false, false),
                native_mapped("pk1".into(), 1, false, false),
                native_mapped("pk2".into(), 2, true, false),
                native_mapped("pk3".into(), 3, false, false),
            ],
        );
        let mut flags = Vec::new();
        validate_native_writable_roles(&report, &exp, &mut flags);
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].category, RiskCategory::WritableMismatch);
        assert_eq!(flags[0].severity, RiskSeverity::Warning);
        assert!(flags[0].message.contains("vault_ai"));
    }

    #[test]
    fn native_account_count_mismatch_warning() {
        let exp = native_exp();
        let report = native_report(
            "MangoPid1111111111111111111111111111111111".into(),
            "WithdrawMsrm",
            (0..5).map(|i| native_mapped(format!("pk{i}"), i as u8, false, false)).collect(),
        );
        let mut flags = Vec::new();
        validate_native_account_counts(&report, &exp, &mut flags);
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].category, RiskCategory::NativeAccountMismatch);
        assert!(flags[0].message.contains("5 accounts but the expectations declare 3"));
    }

    #[test]
    fn validate_entry_native_runs_checks() {
        use solana_sdk::pubkey::Pubkey;
        let exp = native_exp();
        let mut report = native_report(
            "MangoPid1111111111111111111111111111111111".into(),
            "WithdrawMsrm",
            vec![
                native_mapped(Pubkey::new_unique().to_string(), 0, false, false),
                native_mapped(Pubkey::new_unique().to_string(), 1, false, false),
                native_mapped(Pubkey::new_unique().to_string(), 2, false, false),
                native_mapped(Pubkey::new_unique().to_string(), 3, false, false),
            ],
        );
        validate(&mut report, Some(&ProgramSchema::Native(exp)));
        assert!(
            report
                .risk_flags
                .iter()
                .any(|f| f.category == RiskCategory::MissingSigner && f.severity == RiskSeverity::Critical)
        );
    }
}
