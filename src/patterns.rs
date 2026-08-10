use crate::inner_instructions::{AnyInstructionRef, all_instructions};
use crate::types::{
    MappedAccount, PatternConfig, RiskCategory, RiskFlag, RiskSeverity, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID,
    TOKEN_PROGRAM_ID, TransactionReport,
};
use std::collections::{BTreeMap, BTreeSet};

const RULE_APPROVE_THEN_TRANSFER: &str = "approve_then_transfer";
const RULE_NONSIGNER_TRANSFER_AUTHORITY: &str = "nonsigner_transfer_authority";
const RULE_FEE_PAYER_RECIPIENT: &str = "fee_payer_recipient";
const RULE_REPEATED_DESTINATION: &str = "repeated_destination";
const RULE_MINT_AUTHORITY_TAKEOVER: &str = "mint_authority_takeover";

const KNOWN_RULE_KEYS: [&str; 5] = [
    RULE_APPROVE_THEN_TRANSFER,
    RULE_NONSIGNER_TRANSFER_AUTHORITY,
    RULE_FEE_PAYER_RECIPIENT,
    RULE_REPEATED_DESTINATION,
    RULE_MINT_AUTHORITY_TAKEOVER,
];

pub fn detect_patterns(report: &TransactionReport) -> Vec<RiskFlag> {
    detect_patterns_with_config(report, &PatternConfig::default())
}

pub fn detect_patterns_with_config(report: &TransactionReport, config: &PatternConfig) -> Vec<RiskFlag> {
    let mut flags = Vec::new();
    if let Some(severity) = rule_severity(config, RULE_APPROVE_THEN_TRANSFER, RiskSeverity::Warning) {
        detect_approve_then_transfer(report, severity, &mut flags);
    }
    if let Some(severity) = rule_severity(config, RULE_NONSIGNER_TRANSFER_AUTHORITY, RiskSeverity::Warning) {
        detect_nonsigner_transfer_authority(report, severity, &mut flags);
    }
    if let Some(severity) = rule_severity(config, RULE_FEE_PAYER_RECIPIENT, RiskSeverity::Info) {
        detect_fee_payer_recipient(report, severity, &mut flags);
    }
    if let Some(severity) = rule_severity(config, RULE_REPEATED_DESTINATION, RiskSeverity::Info) {
        detect_repeated_destination(report, severity, &mut flags);
    }
    if let Some(severity) = rule_severity(config, RULE_MINT_AUTHORITY_TAKEOVER, RiskSeverity::Warning) {
        detect_mint_authority_takeover(report, severity, &mut flags);
    }
    flags
}

pub fn parse_pattern_config(json: &str) -> anyhow::Result<PatternConfig> {
    let config: PatternConfig = serde_json::from_str(json)?;
    for (key, rule) in &config.rules {
        if !KNOWN_RULE_KEYS.contains(&key.as_str()) {
            anyhow::bail!("unknown pattern rule key: {}", key);
        }
        if let Some(severity) = &rule.severity
            && parse_severity(severity).is_none()
        {
            anyhow::bail!("invalid pattern severity: {}", severity);
        }
    }
    Ok(config)
}

fn parse_severity(s: &str) -> Option<RiskSeverity> {
    match s {
        "info" => Some(RiskSeverity::Info),
        "warning" => Some(RiskSeverity::Warning),
        "critical" => Some(RiskSeverity::Critical),
        _ => None,
    }
}

fn rule_severity(config: &PatternConfig, key: &str, default: RiskSeverity) -> Option<RiskSeverity> {
    let Some(rule) = config.rules.get(key) else {
        return Some(default);
    };
    if rule.enabled == Some(false) {
        return None;
    }
    Some(rule.severity.as_deref().and_then(parse_severity).unwrap_or(default))
}

fn is_token_program(program_id: &str) -> bool {
    program_id == TOKEN_PROGRAM_ID || program_id == TOKEN_2022_PROGRAM_ID
}

fn role_account<'a>(accounts: &'a [MappedAccount], role: &str, fallback: usize) -> Option<&'a MappedAccount> {
    accounts.iter().find(|a| a.name.as_deref() == Some(role)).or_else(|| accounts.get(fallback))
}

fn pattern_flag(severity: RiskSeverity, index: u8, message: String, details: &str) -> RiskFlag {
    RiskFlag {
        severity,
        category: RiskCategory::PatternDetection,
        instruction_index: Some(index),
        message,
        details: details.to_string(),
    }
}

fn ix_program_id<'a>(ix: &AnyInstructionRef<'a>) -> &'a str {
    match ix {
        AnyInstructionRef::Top(top) => &top.program_id,
        AnyInstructionRef::Inner(inner) => &inner.program_id,
    }
}

fn ix_instruction_name<'a>(ix: &AnyInstructionRef<'a>) -> Option<&'a str> {
    match ix {
        AnyInstructionRef::Top(top) => top.instruction_name.as_deref(),
        AnyInstructionRef::Inner(inner) => inner.instruction_name.as_deref(),
    }
}

fn ix_accounts<'a>(ix: &AnyInstructionRef<'a>) -> &'a [MappedAccount] {
    match ix {
        AnyInstructionRef::Top(top) => &top.accounts,
        AnyInstructionRef::Inner(inner) => &inner.accounts,
    }
}

fn ix_data<'a>(ix: &AnyInstructionRef<'a>) -> &'a serde_json::Value {
    match ix {
        AnyInstructionRef::Top(top) => &top.data,
        AnyInstructionRef::Inner(inner) => &inner.data,
    }
}

fn ix_flag_index(ix: &AnyInstructionRef) -> u8 {
    match ix {
        AnyInstructionRef::Top(top) => top.index,
        AnyInstructionRef::Inner(inner) => inner.parent_instruction_index,
    }
}

fn ix_ref(ix: &AnyInstructionRef) -> String {
    match ix {
        AnyInstructionRef::Top(top) => format!("#{}", top.index),
        AnyInstructionRef::Inner(inner) => format!(
            "#{} (inner #{} of instruction #{})",
            inner.parent_instruction_index, inner.inner_index, inner.parent_instruction_index
        ),
    }
}

fn instruction_identity(ix: &AnyInstructionRef) -> (bool, u8, u32) {
    match ix {
        AnyInstructionRef::Top(top) => (false, top.index, 0),
        AnyInstructionRef::Inner(inner) => (true, inner.parent_instruction_index, inner.inner_index),
    }
}

fn same_instruction(a: &AnyInstructionRef, b: &AnyInstructionRef) -> bool {
    match (a, b) {
        (AnyInstructionRef::Top(x), AnyInstructionRef::Top(y)) => x.index == y.index,
        (AnyInstructionRef::Inner(x), AnyInstructionRef::Inner(y)) => {
            x.parent_instruction_index == y.parent_instruction_index && x.inner_index == y.inner_index
        }
        _ => false,
    }
}

fn same_lineage(a: &AnyInstructionRef, b: &AnyInstructionRef) -> bool {
    match (a, b) {
        (AnyInstructionRef::Top(_), AnyInstructionRef::Top(_)) => true,
        (AnyInstructionRef::Inner(ai), AnyInstructionRef::Inner(bi)) => {
            ai.parent_instruction_index == bi.parent_instruction_index
        }
        (AnyInstructionRef::Top(top), AnyInstructionRef::Inner(inner))
        | (AnyInstructionRef::Inner(inner), AnyInstructionRef::Top(top)) => inner.parent_instruction_index == top.index,
    }
}

fn execution_key(ix: &AnyInstructionRef) -> (u32, u32) {
    match ix {
        AnyInstructionRef::Top(top) => (u32::from(top.index) * 2, 0),
        AnyInstructionRef::Inner(inner) => (u32::from(inner.parent_instruction_index) * 2 + 1, inner.inner_index),
    }
}

fn detect_approve_then_transfer(report: &TransactionReport, severity: RiskSeverity, flags: &mut Vec<RiskFlag>) {
    let mut emitted: BTreeSet<(bool, u8, u32)> = BTreeSet::new();
    for approve_ix in all_instructions(report) {
        let Some(approve_name) = ix_instruction_name(&approve_ix) else { continue };
        if approve_name != "Approve" && approve_name != "ApproveChecked" {
            continue;
        }
        if !is_token_program(ix_program_id(&approve_ix)) {
            continue;
        }
        let delegate_pos = if approve_name == "Approve" { 1 } else { 2 };
        let Some(delegate) = role_account(ix_accounts(&approve_ix), "delegate", delegate_pos) else {
            continue;
        };
        for transfer_ix in all_instructions(report) {
            if !same_lineage(&approve_ix, &transfer_ix) {
                continue;
            }
            if execution_key(&transfer_ix) <= execution_key(&approve_ix) {
                continue;
            }
            let Some(transfer_name) = ix_instruction_name(&transfer_ix) else { continue };
            if transfer_name != "Transfer" && transfer_name != "TransferChecked" {
                continue;
            }
            let same_program_ok = ix_program_id(&transfer_ix) == ix_program_id(&approve_ix);
            let any_token_program_ok = is_token_program(ix_program_id(&transfer_ix));
            if !(same_program_ok || any_token_program_ok) {
                continue;
            }
            let Some(authority) = role_account(ix_accounts(&transfer_ix), "authority", 0) else { continue };
            if authority.pubkey != delegate.pubkey {
                continue;
            }
            if !emitted.insert(instruction_identity(&transfer_ix)) {
                continue;
            }
            flags.push(pattern_flag(
                severity.clone(),
                ix_flag_index(&transfer_ix),
                format!(
                    "Instruction {} {} authorizes delegate {} then {} {} spends from it in the same transaction",
                    ix_ref(&approve_ix),
                    approve_name,
                    delegate.pubkey,
                    ix_ref(&transfer_ix),
                    transfer_name
                ),
                "The approve grants the delegate spend rights over the source account; an immediate transfer using \
                 the same authority in one transaction means the owner signature effectively authorizes a delegate \
                 drain of the approved balance.",
            ));
        }
    }
}

fn detect_nonsigner_transfer_authority(report: &TransactionReport, severity: RiskSeverity, flags: &mut Vec<RiskFlag>) {
    for ix in all_instructions(report) {
        let Some(name) = ix_instruction_name(&ix) else { continue };
        let (role, pos) = match (ix_program_id(&ix), name) {
            (pid, "Transfer") if is_token_program(pid) => ("authority", 2),
            (pid, "TransferChecked") if is_token_program(pid) => ("authority", 3),
            (SYSTEM_PROGRAM_ID, "TransferWithSeed") => ("from", 0),
            _ => continue,
        };
        let Some(authority) = role_account(ix_accounts(&ix), role, pos) else { continue };
        if authority.is_signer {
            continue;
        }
        flags.push(pattern_flag(
            severity.clone(),
            ix_flag_index(&ix),
            format!("transfer authority does not sign the transaction on instruction {}", ix_ref(&ix)),
            "The authority of a token transfer must sign the transaction; a non-signing authority means the \
             delegate or an attacker-controlled signer drives the movement of funds.",
        ));
    }
}

fn detect_fee_payer_recipient(report: &TransactionReport, severity: RiskSeverity, flags: &mut Vec<RiskFlag>) {
    for ix in all_instructions(report) {
        let Some(recipient) = transfer_of_money(&ix) else { continue };
        if recipient.pubkey != report.fee_payer {
            continue;
        }
        flags.push(pattern_flag(
            severity.clone(),
            ix_flag_index(&ix),
            format!("fee payer {} is the recipient of instruction {}", report.fee_payer, ix_ref(&ix)),
            "The fee payer of the transaction also receives funds from the same transaction; verify that the fee \
             payer recycling funds is intentional and not a funding loop.",
        ));
    }
}

fn detect_repeated_destination(report: &TransactionReport, severity: RiskSeverity, flags: &mut Vec<RiskFlag>) {
    let mut destinations: BTreeMap<&str, Vec<(bool, u8, u32)>> = BTreeMap::new();
    for ix in all_instructions(report) {
        let Some(recipient) = transfer_of_money(&ix) else { continue };
        destinations.entry(recipient.pubkey.as_str()).or_default().push(instruction_identity(&ix));
    }
    for (pubkey, occurrences) in destinations {
        if occurrences.len() < 2 {
            continue;
        }
        let listed = occurrences.iter().map(identity_ref).collect::<Vec<_>>().join(", ");
        flags.push(pattern_flag(
            severity.clone(),
            occurrences[0].1,
            format!("destination {} receives funds in multiple instructions: {}", pubkey, listed),
            "The same account is the recipient of several money-moving instructions (transfers/mints) in one \
             transaction; a single fan-in recipient may indicate a sweep, consolidation, or fee-settlement \
             pattern that deserves manual review.",
        ));
    }
}

fn detect_mint_authority_takeover(report: &TransactionReport, severity: RiskSeverity, flags: &mut Vec<RiskFlag>) {
    let mut emitted: BTreeSet<(bool, u8, u32)> = BTreeSet::new();
    for set_ix in all_instructions(report) {
        if !is_token_program(ix_program_id(&set_ix)) {
            continue;
        }
        if ix_instruction_name(&set_ix) != Some("SetAuthority") {
            continue;
        }
        if ix_data(&set_ix).get("authority_type").and_then(serde_json::Value::as_u64) != Some(0) {
            continue;
        }
        let Some(new_authority) = ix_data(&set_ix).get("new_authority").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(mint) = role_account(ix_accounts(&set_ix), "account", 0) else { continue };
        for mint_ix in all_instructions(report) {
            if same_instruction(&set_ix, &mint_ix) {
                continue;
            }
            if !same_lineage(&set_ix, &mint_ix) {
                continue;
            }
            let Some(mint_name) = ix_instruction_name(&mint_ix) else { continue };
            if mint_name != "MintTo" && mint_name != "MintToChecked" {
                continue;
            }
            if !is_token_program(ix_program_id(&mint_ix)) {
                continue;
            }
            let Some(mint_account) = role_account(ix_accounts(&mint_ix), "mint", 0) else { continue };
            if mint_account.pubkey != mint.pubkey {
                continue;
            }
            let Some(mint_authority) = role_account(ix_accounts(&mint_ix), "authority", 2) else { continue };
            if mint_authority.pubkey != new_authority {
                continue;
            }
            if !emitted.insert(instruction_identity(&set_ix)) {
                continue;
            }
            flags.push(pattern_flag(
                severity.clone(),
                ix_flag_index(&set_ix),
                format!(
                    "mint authority takeover: instruction {} SetAuthority re-points the authority of mint {} \
                     to {}; then {} mints tokens with the new authority",
                    ix_ref(&set_ix),
                    mint.pubkey,
                    new_authority,
                    ix_ref(&mint_ix)
                ),
                "SetAuthority on the mint (authority_type 0 = MintTokens) transfers the mint authority and the \
                 same transaction mints tokens under the newly appointed authority; the new authority can mint \
                 an arbitrary supply, so the takeover is a supply-injection pattern in one transaction.",
            ));
        }
    }
}

fn transfer_of_money<'a>(ix: &AnyInstructionRef<'a>) -> Option<&'a MappedAccount> {
    let name = ix_instruction_name(ix)?;
    let (role, pos) = match (ix_program_id(ix), name) {
        (pid, "Transfer") if is_token_program(pid) => ("destination", 1),
        (pid, "TransferChecked") if is_token_program(pid) => ("destination", 2),
        (pid, "MintTo" | "MintToChecked") if is_token_program(pid) => ("to", 1),
        (SYSTEM_PROGRAM_ID, "Transfer") => ("to", 1),
        (SYSTEM_PROGRAM_ID, "WithdrawNonceAccount") => ("to", 2),
        _ => return None,
    };
    role_account(ix_accounts(ix), role, pos)
}

fn identity_ref(identity: &(bool, u8, u32)) -> String {
    let (is_inner, index, inner_index) = *identity;
    if is_inner {
        format!("#{} (inner #{} of instruction #{})", index, inner_index, index)
    } else {
        format!("#{}", index)
    }
}
