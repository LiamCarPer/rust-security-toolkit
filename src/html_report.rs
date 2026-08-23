use crate::types::{RiskSeverity, TransactionReport};

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

fn badge(severity: &RiskSeverity) -> String {
    let (class, label) = match severity {
        RiskSeverity::Critical => ("critical", "CRITICAL"),
        RiskSeverity::Warning => ("warning", "WARNING"),
        RiskSeverity::Info => ("info", "INFO"),
    };
    format!(r#"<span class="badge {}">{}</span>"#, class, label)
}

pub fn render_html(report: &TransactionReport) -> String {
    let mut out = String::new();
    out.push_str("<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>Solana Transaction Forensics Report</title>\n<style>\n");
    out.push_str("body{font-family:monospace;margin:2rem;background:#111;color:#ddd}\n");
    out.push_str("h1{color:#fff}h2{color:#8ab;border-bottom:1px solid #456;padding-bottom:.3rem}\n");
    out.push_str("table{border-collapse:collapse;width:100%;margin-bottom:1.5rem}\n");
    out.push_str(
        "td,th{border:1px solid #444;padding:.35rem .5rem;text-align:left;font-size:.85rem;word-break:break-all}\n",
    );
    out.push_str("th{background:#222;color:#9cf}\n");
    out.push_str(".badge{padding:.15rem .5rem;border-radius:.3rem;font-weight:bold}\n");
    out.push_str(".badge.critical{background:#a00;color:#fff}.badge.warning{background:#a80;color:#000}.badge.info{background:#06c;color:#fff}\n");
    out.push_str(".ok{color:#4c4}.bad{color:#f66}\npre{background:#181818;padding:.6rem;overflow-x:auto}\n");
    out.push_str("</style>\n</head>\n<body>\n");
    out.push_str(&format!("<h1>{}</h1>\n", esc(&report.status)));
    out.push_str(&format!(
        "<p>Fee payer: <code>{}</code> &mdash; blockhash <code>{}</code></p>\n",
        esc(&report.fee_payer),
        esc(&report.recent_blockhash)
    ));

    if !report.signatures.is_empty() {
        out.push_str("<h2>Signatures</h2>\n<table><tr><th>#</th><th>Signature</th><th>Verified</th></tr>\n");
        for check in &report.signature_verification {
            let state = if check.verified {
                r#"<span class="ok">OK</span>"#.to_string()
            } else {
                format!(r#"<span class="bad">FAIL ({})</span>"#, esc(&check.note))
            };
            out.push_str(&format!(
                "<tr><td>{}</td><td><code>{}</code></td><td>{}</td></tr>\n",
                check.index,
                esc(&check.pubkey),
                state
            ));
        }
        out.push_str("</table>\n");
    }

    out.push_str(
        "<h2>Accounts</h2>\n<table><tr><th>#</th><th>Pubkey</th><th>Signer</th><th>Writable</th><th>Role</th></tr>\n",
    );
    for account in &report.accounts {
        out.push_str(&format!(
            "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            account.index,
            esc(&account.pubkey),
            account.is_signer,
            account.is_writable,
            account.role.as_deref().map(esc).unwrap_or_default()
        ));
    }
    out.push_str("</table>\n");

    out.push_str("<h2>Instructions</h2>\n<table><tr><th>#</th><th>Program</th><th>Name</th><th>Data</th></tr>\n");
    for ix in &report.instructions {
        let name = ix.instruction_name.as_deref().unwrap_or(&ix.program_name);
        let data = if ix.data.is_null() {
            esc(&ix.raw_data_hex)
        } else {
            esc(&serde_json::to_string(&ix.data).unwrap_or_default())
        };
        out.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td><pre>{}</pre></td></tr>\n",
            ix.index,
            esc(&ix.program_name),
            esc(name),
            data
        ));
    }
    out.push_str("</table>\n");

    if !report.inner_instructions.is_empty() {
        out.push_str("<h2>Inner Instructions (CPI)</h2>\n<table><tr><th>Parent</th><th>#</th><th>Program</th><th>Name</th><th>Data</th></tr>\n");
        for inner in &report.inner_instructions {
            let name = inner.instruction_name.as_deref().unwrap_or(&inner.program_name);
            let data = if inner.data.is_null() {
                esc(&inner.raw_data_hex)
            } else {
                esc(&serde_json::to_string(&inner.data).unwrap_or_default())
            };
            out.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><pre>{}</pre></td></tr>\n",
                inner.parent_instruction_index,
                inner.inner_index,
                esc(&inner.program_name),
                esc(name),
                data
            ));
        }
        out.push_str("</table>\n");
    }

    out.push_str("<h2>Risk Flags</h2>\n<table><tr><th>Severity</th><th>Category</th><th>Instruction</th><th>Message</th><th>Details</th></tr>\n");
    for flag in &report.risk_flags {
        out.push_str(&format!(
            "<tr><td>{}</td><td>{:?}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            badge(&flag.severity),
            flag.category,
            flag.instruction_index.map(|i| i.to_string()).unwrap_or_else(|| "-".into()),
            esc(&flag.message),
            esc(&flag.details)
        ));
    }
    out.push_str("</table>\n");

    if !report.balance_changes_sol.is_empty() || !report.token_balance_changes.is_empty() {
        out.push_str("<h2>Balance Changes</h2>\n<table><tr><th>Account</th><th>Mint/Token</th><th>Delta</th></tr>\n");
        for change in &report.balance_changes_sol {
            out.push_str(&format!(
                "<tr><td><code>{}</code></td><td>SOL</td><td>{:+}</td></tr>\n",
                esc(&change.pubkey),
                change.delta
            ));
        }
        for change in &report.token_balance_changes {
            out.push_str(&format!(
                "<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>\n",
                esc(&change.pubkey),
                esc(&change.mint),
                esc(&change.delta_human)
            ));
        }
        out.push_str("</table>\n");
    }

    if !report.warnings.is_empty() {
        out.push_str("<h2>Warnings</h2>\n<ul>\n");
        for warning in &report.warnings {
            out.push_str(&format!("<li>{}</li>\n", esc(warning)));
        }
        out.push_str("</ul>\n");
    }

    out.push_str("</body>\n</html>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_sections() {
        let report = TransactionReport {
            status: "DECODED SUCCESSFULLY".into(),
            fee_payer: "FP".into(),
            signatures: vec![],
            recent_blockhash: "BH".into(),
            message_version: None,
            accounts: vec![],
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
            oracle_feeds: vec![],
        };
        let html = render_html(&report);
        assert!(html.contains("Accounts"));
        assert!(html.contains("Instructions"));
        assert!(html.contains("Risk Flags"));
    }

    #[test]
    fn escapes_html_in_data() {
        let mut report = TransactionReport {
            status: "S".into(),
            fee_payer: String::new(),
            signatures: vec![],
            recent_blockhash: String::new(),
            message_version: None,
            accounts: vec![],
            instructions: vec![],
            address_lookup_tables: vec![],
            compute_budget: None,
            risk_flags: vec![],
            simulation: None,
            warnings: vec![r#"<script>alert("x")</script>"#.into()],
            signature_verification: vec![],
            inner_instructions: vec![],
            balance_changes_sol: vec![],
            token_balance_changes: vec![],
            oracle_feeds: vec![],
        };
        report.warnings.push(String::from("&<>"));
        let html = render_html(&report);
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&amp;&lt;&gt;"));
    }

    #[test]
    fn no_panics_on_minimal_report() {
        let report = TransactionReport {
            status: String::new(),
            fee_payer: String::new(),
            signatures: vec![],
            recent_blockhash: String::new(),
            message_version: None,
            accounts: vec![],
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
            oracle_feeds: vec![],
        };
        let _ = render_html(&report);
    }

    #[test]
    fn severity_badges_present() {
        use crate::types::{RiskCategory, RiskFlag};
        let mut report = TransactionReport {
            status: String::new(),
            fee_payer: String::new(),
            signatures: vec![],
            recent_blockhash: String::new(),
            message_version: None,
            accounts: vec![],
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
            oracle_feeds: vec![],
        };
        for severity in [RiskSeverity::Critical, RiskSeverity::Warning, RiskSeverity::Info] {
            report.risk_flags.push(RiskFlag {
                severity,
                category: RiskCategory::InsecureWritable,
                instruction_index: None,
                message: String::new(),
                details: String::new(),
            });
        }
        let html = render_html(&report);
        assert!(html.contains("badge critical"));
        assert!(html.contains("badge warning"));
        assert!(html.contains("badge info"));
    }
}
