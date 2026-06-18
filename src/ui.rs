use colored::*;

use crate::types::{RiskSeverity, TransactionReport};

/// Render the ANSI-styled terminal dashboard.
pub fn render_terminal(report: &TransactionReport, show_network_banner: bool) {
    let border = "═".repeat(76);

    println!();
    println!(
        "{}",
        format!("╔{}╗", format!("{:^76}", "SOLANA TRANSACTION FORENSICS REPORT (v0)").bold().white()).bold().white()
    );
    println!("{}", format!("╚{}╝", border).bold().white());

    let status_color = if report.status.contains("SUCCESSFULLY") { Color::Green } else { Color::Red };
    println!("[+] Status: {}", report.status.color(status_color).bold());

    if let Some(ref sim) = report.simulation {
        let sim_status = if sim.success {
            format!("WOULD SUCCEED ({} CU consumed)", sim.units_consumed).green()
        } else {
            format!("WOULD FAIL: {}", sim.error.as_deref().unwrap_or("unknown")).red()
        };
        println!("[+] Simulation: {}", sim_status);
    }

    println!("[+] Fee Payer: {} (Account #0)", truncate_key(&report.fee_payer));
    if let Some(ref cb) = report.compute_budget {
        let limit_label = if cb.compute_unit_limit_set {
            format!("{} CU (Custom Limit Set)", cb.compute_unit_limit)
        } else {
            format!("{} CU (Default)", cb.compute_unit_limit)
        };
        println!("[+] Compute Limit: {}", limit_label);
        if cb.compute_unit_price > 0 {
            println!("[+] Priority Fee: {} micro-lamports/CU", cb.compute_unit_price);
        }
    }

    // ── Account Keys & Roles ────────────────────────────────────────────────
    println!();
    println!("{}", "┌── Account Keys & Roles ────────────────────────────────────────────────────────┐".bold());
    for account in &report.accounts {
        let signer = if account.is_signer { "Signer".bold() } else { "Signer".normal() };
        let writable = if account.is_writable { "Writable".yellow() } else { "Read-only".dimmed() };
        print!("│ #{:<2}: {:<15} [{}, {}]", account.index, truncate_key(&account.pubkey), signer, writable);
        if let Some(ref pda) = account.pda_info {
            print!(" (PDA: {})", pda.seeds_declared.join(" + "));
        }
        println!();
    }
    println!("{}", "└────────────────────────────────────────────────────────────────────────────────┘".bold());

    // ── ALT Resolution ──────────────────────────────────────────────────────
    if !report.address_lookup_tables.is_empty() {
        println!();
        println!("{}", "┌── Address Lookup Table (ALT) Resolution ───────────────────────────────────────┐".bold());
        for alt in &report.address_lookup_tables {
            println!(
                "│ Table: {} ({} account{})",
                truncate_key(&alt.table_address),
                alt.resolved_accounts.len(),
                if alt.resolved_accounts.len() == 1 { "" } else { "s" }
            );
            for resolved in &alt.resolved_accounts {
                let writable = if resolved.is_writable { "Writable".yellow() } else { "Read-only".dimmed() };
                println!(
                    "│   └── Mapped Account #{}: {} ({})",
                    resolved.index_in_tx,
                    truncate_key(&resolved.pubkey),
                    writable
                );
            }
        }
        println!("{}", "└────────────────────────────────────────────────────────────────────────────────┘".bold());
    }

    // ── Instructions Breakdown ──────────────────────────────────────────────
    println!();
    println!("{}", "┌── Instructions Breakdown ──────────────────────────────────────────────────────┐".bold());
    for ix in &report.instructions {
        let name = ix.instruction_name.as_deref().unwrap_or(&ix.program_name);
        println!("│ [Instruction #{}] {}: {}", ix.index, ix.program_name.bold(), name.cyan());
        println!("│   ├── Program: {}", ix.program_id.dimmed());

        for account in &ix.accounts {
            let label = account.name.as_deref().unwrap_or("account");
            let missing = if !account.is_signer
                && report.risk_flags.iter().any(|f| {
                    f.instruction_index == Some(ix.index)
                        && f.message.contains(label)
                        && f.message.contains("Missing Signer")
                }) {
                "← MISSING SIGNATURE".red().bold()
            } else {
                "".normal()
            };
            println!(
                "│   │   ├── {:<12}: {:<15} (Account #{}) {}",
                format!("{}:", label),
                truncate_key(&account.pubkey),
                account.account_index,
                missing
            );
        }

        if ix.data != serde_json::Value::Null {
            let data_str = serde_json::to_string_pretty(&ix.data).unwrap_or_else(|_| ix.raw_data_hex.clone());
            let lines: Vec<&str> = data_str.lines().collect();
            if lines.len() == 1 {
                println!("│   └── Mapped Data: {}", lines[0].dimmed());
            } else {
                println!("│   └── Mapped Data:");
                for line in lines {
                    println!("│        {}", line.dimmed());
                }
            }
        } else if !ix.raw_data_hex.is_empty() {
            println!("│   └── Raw Data: {}", ix.raw_data_hex.dimmed());
        }
    }
    println!("{}", "└────────────────────────────────────────────────────────────────────────────────┘".bold());

    // ── Structural Risk Flags ───────────────────────────────────────────────
    if !report.risk_flags.is_empty() {
        println!();
        println!("{}", "┌── Structural Risk Flags ───────────────────────────────────────────────────────┐".bold());
        for flag in &report.risk_flags {
            let (icon, color) = match flag.severity {
                RiskSeverity::Critical => ("CRITICAL", Color::Red),
                RiskSeverity::Warning => ("WARNING", Color::Yellow),
                RiskSeverity::Info => ("INFO", Color::Cyan),
            };
            let prefix =
                if let Some(idx) = flag.instruction_index { format!("Instruction #{}: ", idx) } else { String::new() };
            println!(
                "│ {} [{}] {}{}",
                match flag.severity {
                    RiskSeverity::Critical => "🔴",
                    RiskSeverity::Warning => "🟡",
                    RiskSeverity::Info => "🔵",
                },
                icon.color(color).bold(),
                prefix,
                flag.message
            );
            for detail_line in wrap_text(&flag.details, 68) {
                println!("│    {}", detail_line);
            }
            println!("│ {:76}", "");
        }
        println!("{}", "└────────────────────────────────────────────────────────────────────────────────┘".bold());
    }

    // ── Warnings ────────────────────────────────────────────────────────────
    if !report.warnings.is_empty() {
        println!();
        println!("{}", "┌── Decoder Warnings ────────────────────────────────────────────────────────────┐".bold());
        for warning in &report.warnings {
            println!("│ {}", warning.yellow());
        }
        println!("{}", "└────────────────────────────────────────────────────────────────────────────────┘".bold());
    }

    if !show_network_banner {
        println!();
        println!("{}", "╔════════════════════════════════════════════════════════════════════════════════╗".yellow());
        println!("{}", "║  --no-network: Skipped simulation, program ownership, and verified build checks ║".yellow());
        println!("{}", "╚════════════════════════════════════════════════════════════════════════════════╝".yellow());
    }

    println!();
}

/// Export a JSON report to stdout.
pub fn render_json(report: &TransactionReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
}

/// Export the transaction report for `sat` consumption.
pub fn render_tx_report(report: &TransactionReport) -> String {
    let sat_report = serde_json::json!({
        "schema_version": "1.0",
        "transaction": {
            "signatures": report.signatures,
            "fee_payer": report.fee_payer,
            "recent_blockhash": report.recent_blockhash,
            "message_version": report.message_version,
        },
        "accounts": report.accounts.iter().map(|a| {
            serde_json::json!({
                "index": a.index,
                "pubkey": a.pubkey,
                "is_signer": a.is_signer,
                "is_writable": a.is_writable,
                "role": a.role,
                "pda": a.pda_info.as_ref().map(|p| {
                    serde_json::json!({
                        "seeds_declared": p.seeds_declared,
                        "expected_address": p.expected_address,
                    })
                }),
            })
        }).collect::<Vec<_>>(),
        "instructions": report.instructions.iter().map(|ix| {
            serde_json::json!({
                "index": ix.index,
                "program_id": ix.program_id,
                "instruction_name": ix.instruction_name,
                "accounts": ix.accounts.iter().map(|a| {
                    serde_json::json!({
                        "name": a.name,
                        "pubkey": a.pubkey,
                        "account_index": a.account_index,
                        "is_signer": a.is_signer,
                        "is_writable": a.is_writable,
                    })
                }).collect::<Vec<_>>(),
                "data": ix.data,
            })
        }).collect::<Vec<_>>(),
        "risk_flags": report.risk_flags.iter().map(|f| {
            serde_json::json!({
                "severity": f.severity,
                "category": f.category,
                "instruction_index": f.instruction_index,
                "message": f.message,
            })
        }).collect::<Vec<_>>(),
        "simulation": report.simulation.as_ref().map(|s| {
            serde_json::json!({
                "success": s.success,
                "error": s.error,
                "units_consumed": s.units_consumed,
            })
        }),
    });

    serde_json::to_string_pretty(&sat_report).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
}

fn truncate_key(key: &str) -> String {
    if key.len() > 12 { format!("{}...{}", &key[..6], &key[key.len() - 6..]) } else { key.to_string() }
}

fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut remaining = text;

    while remaining.len() > width {
        let mut split_at = width;
        while split_at > 0 && !remaining.as_bytes()[split_at].is_ascii_whitespace() {
            split_at -= 1;
        }
        if split_at == 0 {
            split_at = width;
        }
        lines.push(remaining[..split_at].trim_end().to_string());
        remaining = remaining[split_at..].trim_start();
    }
    if !remaining.is_empty() {
        lines.push(remaining.to_string());
    }
    lines
}
