//! Markdown bounty-report renderer: findings with evidence blocks, ready to
//! paste into a submission.

use crate::types::{RiskSeverity, TransactionReport};

fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

fn severity_label(severity: &RiskSeverity) -> &'static str {
    match severity {
        RiskSeverity::Critical => "Critical",
        RiskSeverity::Warning => "Warning",
        RiskSeverity::Info => "Info",
    }
}

pub fn render_markdown(report: &TransactionReport) -> String {
    let mut out = String::new();

    out.push_str("# Transaction Analysis Report\n\n");
    out.push_str(&format!("**Status:** {}\n\n", report.status));
    out.push_str(&format!("**Fee payer:** `{}`\n\n", report.fee_payer));
    if let Some(sig) = report.signatures.first() {
        out.push_str(&format!("**Signature:** `{}`\n\n", sig));
    }
    if let Some(ref source) = report.idl_source {
        out.push_str(&format!("**IDL source:** {}\n\n", source));
    }

    let critical = report.risk_flags.iter().filter(|f| f.severity == RiskSeverity::Critical).count();
    let warning = report.risk_flags.iter().filter(|f| f.severity == RiskSeverity::Warning).count();
    let info = report.risk_flags.iter().filter(|f| f.severity == RiskSeverity::Info).count();
    out.push_str("## Findings Summary\n\n");
    out.push_str("| Severity | Count |\n|---|---|\n");
    out.push_str(&format!("| Critical | {} |\n", critical));
    out.push_str(&format!("| Warning | {} |\n", warning));
    out.push_str(&format!("| Info | {} |\n\n", info));

    if !report.risk_flags.is_empty() {
        out.push_str("## Findings\n\n");
        for (index, flag) in report.risk_flags.iter().enumerate() {
            let location = flag
                .instruction_index
                .map(|i| format!("instruction #{}", i))
                .unwrap_or_else(|| "transaction".to_string());
            out.push_str(&format!(
                "### F{} — {} ({}, {})\n\n",
                index + 1,
                cell(&flag.message),
                severity_label(&flag.severity),
                location
            ));
            out.push_str(&format!("{}\n\n", flag.details));
        }
    }

    let has_balance = !report.balance_changes_sol.is_empty() || !report.token_balance_changes.is_empty();
    if has_balance {
        out.push_str("## Evidence — Balance Changes\n\n");
        out.push_str("| Account | Asset | Delta |\n|---|---|---|\n");
        for change in &report.balance_changes_sol {
            out.push_str(&format!("| `{}` | SOL | {:+} |\n", cell(&change.pubkey), change.delta));
        }
        for change in &report.token_balance_changes {
            out.push_str(&format!(
                "| `{}` | `{}` | {} |\n",
                cell(&change.pubkey),
                cell(&change.mint),
                cell(&change.delta_human)
            ));
        }
        out.push('\n');
    }

    if !report.events.is_empty() {
        out.push_str("## Evidence — Decoded Events\n\n");
        for event in &report.events {
            out.push_str(&format!(
                "- **{}** (program `{}`): `{}`\n",
                cell(&event.name),
                cell(&event.program_id),
                cell(&serde_json::to_string(&event.fields).unwrap_or_default())
            ));
        }
        out.push('\n');
    }

    let failed_signatures = report.signature_verification.iter().filter(|check| !check.verified).collect::<Vec<_>>();
    if !failed_signatures.is_empty() {
        out.push_str("## Evidence — Signature Verification\n\n");
        for check in failed_signatures {
            out.push_str(&format!("- `{}` ({})\n", cell(&check.pubkey), cell(&check.note)));
        }
        out.push('\n');
    }

    if !report.instructions.is_empty() {
        out.push_str("## Appendix — Instruction Sequence\n\n");
        for ix in &report.instructions {
            let name = ix.instruction_name.as_deref().unwrap_or(&ix.program_name);
            out.push_str(&format!(
                "{}. {} — {} (`{}`)\n",
                ix.index,
                cell(&ix.program_name),
                cell(name),
                cell(&ix.program_id)
            ));
        }
        out.push('\n');
    }

    if !report.warnings.is_empty() {
        out.push_str("## Appendix — Decoder Warnings\n\n");
        for warning in &report.warnings {
            out.push_str(&format!("- {}\n", cell(warning)));
        }
        out.push('\n');
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{RiskCategory, RiskFlag, TokenBalanceChange};

    fn report_with(flags: Vec<RiskFlag>) -> TransactionReport {
        TransactionReport {
            status: "DECODED SUCCESSFULLY".to_string(),
            fee_payer: "FeePayer111111111111111111111111111111111".to_string(),
            signatures: vec!["Sig111".to_string()],
            recent_blockhash: String::new(),
            message_version: None,
            accounts: Vec::new(),
            instructions: Vec::new(),
            address_lookup_tables: Vec::new(),
            compute_budget: None,
            risk_flags: flags,
            simulation: None,
            warnings: Vec::new(),
            signature_verification: Vec::new(),
            inner_instructions: Vec::new(),
            balance_changes_sol: Vec::new(),
            token_balance_changes: Vec::new(),
            oracle_feeds: Vec::new(),
            idl_source: None,
            logs: Vec::new(),
            events: Vec::new(),
        }
    }

    fn flag(severity: RiskSeverity) -> RiskFlag {
        RiskFlag {
            severity,
            category: RiskCategory::PatternDetection,
            instruction_index: Some(1),
            message: "approve then transfer".to_string(),
            details: "drain risk".to_string(),
        }
    }

    #[test]
    fn contains_findings_and_summary() {
        let report = report_with(vec![flag(RiskSeverity::Critical), flag(RiskSeverity::Info)]);
        let md = render_markdown(&report);
        assert!(md.contains("# Transaction Analysis Report"));
        assert!(md.contains("## Findings Summary"));
        assert!(md.contains("| Critical | 1 |"));
        assert!(md.contains("### F1 — approve then transfer (Critical, instruction #1)"));
    }

    #[test]
    fn escapes_pipes_in_findings() {
        let mut report = report_with(vec![flag(RiskSeverity::Warning)]);
        report.risk_flags[0].message = "a | b".to_string();
        let md = render_markdown(&report);
        assert!(md.contains("a \\| b"));
    }

    #[test]
    fn balance_evidence_rendered() {
        let mut report = report_with(Vec::new());
        report.token_balance_changes.push(TokenBalanceChange {
            account_index: 2,
            pubkey: "Acct111".to_string(),
            mint: "Mint111".to_string(),
            pre: None,
            post: None,
            delta_raw: -500,
            delta_human: "-0.5".to_string(),
        });
        let md = render_markdown(&report);
        assert!(md.contains("## Evidence — Balance Changes"));
        assert!(md.contains("| `Acct111` | `Mint111` | -0.5 |"));
    }

    #[test]
    fn empty_report_has_no_findings_section() {
        let md = render_markdown(&report_with(Vec::new()));
        assert!(!md.contains("## Findings\n"));
        assert!(md.contains("| Critical | 0 |"));
    }
}
