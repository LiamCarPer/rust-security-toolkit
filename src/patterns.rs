use crate::types::{
    DecodedInstruction, MappedAccount, RiskCategory, RiskFlag, RiskSeverity, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID,
    TOKEN_PROGRAM_ID, TransactionReport,
};
use std::collections::BTreeMap;

pub fn detect_patterns(report: &TransactionReport) -> Vec<RiskFlag> {
    let mut flags = Vec::new();
    detect_approve_then_transfer(report, &mut flags);
    detect_nonsigner_transfer_authority(report, &mut flags);
    detect_fee_payer_recipient(report, &mut flags);
    detect_repeated_destination(report, &mut flags);
    detect_mint_authority_takeover(report, &mut flags);
    flags
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

fn detect_approve_then_transfer(report: &TransactionReport, flags: &mut Vec<RiskFlag>) {
    for approve_ix in &report.instructions {
        let Some(approve_name) = approve_ix.instruction_name.as_deref() else { continue };
        if approve_name != "Approve" && approve_name != "ApproveChecked" {
            continue;
        }
        if !is_token_program(&approve_ix.program_id) {
            continue;
        }
        let delegate_pos = if approve_name == "Approve" { 1 } else { 2 };
        let Some(delegate) = role_account(&approve_ix.accounts, "delegate", delegate_pos) else {
            continue;
        };
        for transfer_ix in &report.instructions {
            if transfer_ix.index <= approve_ix.index {
                continue;
            }
            let Some(transfer_name) = transfer_ix.instruction_name.as_deref() else { continue };
            if transfer_name != "Transfer" && transfer_name != "TransferChecked" {
                continue;
            }
            let same_program_ok = transfer_ix.program_id == approve_ix.program_id;
            let any_token_program_ok = is_token_program(&transfer_ix.program_id);
            if !(same_program_ok || any_token_program_ok) {
                continue;
            }
            let Some(authority) = role_account(&transfer_ix.accounts, "authority", 0) else { continue };
            if authority.pubkey != delegate.pubkey {
                continue;
            }
            flags.push(pattern_flag(
                RiskSeverity::Warning,
                transfer_ix.index,
                format!(
                    "Instruction #{} {} authorizes delegate {} then #{} {} spends from it in the same transaction",
                    approve_ix.index, approve_name, delegate.pubkey, transfer_ix.index, transfer_name
                ),
                "The approve grants the delegate spend rights over the source account; an immediate transfer using \
                 the same authority in one transaction means the owner signature effectively authorizes a delegate \
                 drain of the approved balance.",
            ));
        }
    }
}

fn detect_nonsigner_transfer_authority(report: &TransactionReport, flags: &mut Vec<RiskFlag>) {
    for ix in &report.instructions {
        let Some(name) = ix.instruction_name.as_deref() else { continue };
        let (role, pos) = match (ix.program_id.as_str(), name) {
            (pid, "Transfer") if is_token_program(pid) => ("authority", 2),
            (pid, "TransferChecked") if is_token_program(pid) => ("authority", 3),
            (SYSTEM_PROGRAM_ID, "TransferWithSeed") => ("from", 0),
            _ => continue,
        };
        let Some(authority) = role_account(&ix.accounts, role, pos) else { continue };
        if authority.is_signer {
            continue;
        }
        flags.push(pattern_flag(
            RiskSeverity::Warning,
            ix.index,
            format!("transfer authority does not sign the transaction on instruction #{}", ix.index),
            "The authority of a token transfer must sign the transaction; a non-signing authority means the \
             delegate or an attacker-controlled signer drives the movement of funds.",
        ));
    }
}

fn detect_fee_payer_recipient(report: &TransactionReport, flags: &mut Vec<RiskFlag>) {
    for ix in &report.instructions {
        let Some(recipient) = transfer_of_money(ix) else { continue };
        if recipient.pubkey != report.fee_payer {
            continue;
        }
        flags.push(pattern_flag(
            RiskSeverity::Info,
            ix.index,
            format!("fee payer {} is the recipient of instruction #{}", report.fee_payer, ix.index),
            "The fee payer of the transaction also receives funds from the same transaction; verify that the fee \
             payer recycling funds is intentional and not a funding loop.",
        ));
    }
}

fn detect_repeated_destination(report: &TransactionReport, flags: &mut Vec<RiskFlag>) {
    let mut destinations: BTreeMap<&str, Vec<u8>> = BTreeMap::new();
    for ix in &report.instructions {
        let Some(recipient) = transfer_of_money(ix) else { continue };
        destinations.entry(recipient.pubkey.as_str()).or_default().push(ix.index);
    }
    for (pubkey, indices) in destinations {
        if indices.len() < 2 {
            continue;
        }
        let listed = indices.iter().map(|i| format!("#{}", i)).collect::<Vec<_>>().join(", ");
        flags.push(pattern_flag(
            RiskSeverity::Info,
            indices[0],
            format!("destination {} receives funds in multiple instructions: {}", pubkey, listed),
            "The same account is the recipient of several money-moving instructions (transfers/mints) in one \
             transaction; a single fan-in recipient may indicate a sweep, consolidation, or fee-settlement \
             pattern that deserves manual review.",
        ));
    }
}

fn detect_mint_authority_takeover(report: &TransactionReport, flags: &mut Vec<RiskFlag>) {
    for set_ix in &report.instructions {
        if !is_token_program(&set_ix.program_id) {
            continue;
        }
        if set_ix.instruction_name.as_deref() != Some("SetAuthority") {
            continue;
        }
        if set_ix.data.get("authority_type").and_then(serde_json::Value::as_u64) != Some(0) {
            continue;
        }
        let Some(new_authority) = set_ix.data.get("new_authority").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(mint) = role_account(&set_ix.accounts, "account", 0) else { continue };
        for mint_ix in &report.instructions {
            if mint_ix.index == set_ix.index {
                continue;
            }
            let Some(mint_name) = mint_ix.instruction_name.as_deref() else { continue };
            if mint_name != "MintTo" && mint_name != "MintToChecked" {
                continue;
            }
            if !is_token_program(&mint_ix.program_id) {
                continue;
            }
            let Some(mint_account) = role_account(&mint_ix.accounts, "mint", 0) else { continue };
            if mint_account.pubkey != mint.pubkey {
                continue;
            }
            let Some(mint_authority) = role_account(&mint_ix.accounts, "authority", 2) else { continue };
            if mint_authority.pubkey != new_authority {
                continue;
            }
            flags.push(pattern_flag(
                RiskSeverity::Warning,
                set_ix.index,
                format!(
                    "mint authority takeover: instruction #{} SetAuthority re-points the authority of mint {} \
                     to {}; then #{} mints tokens with the new authority",
                    set_ix.index, mint.pubkey, new_authority, mint_ix.index
                ),
                "SetAuthority on the mint (authority_type 0 = MintTokens) transfers the mint authority and the \
                 same transaction mints tokens under the newly appointed authority; the new authority can mint \
                 an arbitrary supply, so the takeover is a supply-injection pattern in one transaction.",
            ));
        }
    }
}

fn transfer_of_money(ix: &DecodedInstruction) -> Option<&MappedAccount> {
    let name = ix.instruction_name.as_deref()?;
    let (role, pos) = match (ix.program_id.as_str(), name) {
        (pid, "Transfer") if is_token_program(pid) => ("destination", 1),
        (pid, "TransferChecked") if is_token_program(pid) => ("destination", 2),
        (pid, "MintTo" | "MintToChecked") if is_token_program(pid) => ("to", 1),
        (SYSTEM_PROGRAM_ID, "Transfer") => ("to", 1),
        (SYSTEM_PROGRAM_ID, "WithdrawNonceAccount") => ("to", 2),
        _ => return None,
    };
    role_account(&ix.accounts, role, pos)
}
