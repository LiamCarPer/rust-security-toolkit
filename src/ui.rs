use colored::*;

use crate::known_addresses::KnownAddresses;
use crate::types::{RiskSeverity, TransactionReport};

fn display_key(key: &str, known: Option<&KnownAddresses>) -> String {
    match known.and_then(|k| k.name(key)).or_else(|| crate::labels::label(key)) {
        Some(name) => format!("{} ({})", name, truncate_key(key)),
        None => truncate_key(key),
    }
}

/// Render the ANSI-styled terminal dashboard.
pub fn render_terminal(report: &TransactionReport, show_network_banner: bool) {
    render_terminal_with_known(report, show_network_banner, None);
}

/// Render the ANSI-styled terminal dashboard with a known-address registry.
pub fn render_terminal_with_known(
    report: &TransactionReport,
    show_network_banner: bool,
    known: Option<&KnownAddresses>,
) {
    let border = "═".repeat(76);

    println!();
    println!(
        "{}",
        format!("╔{}╗", format!("{:^76}", "SOLANA TRANSACTION FORENSICS REPORT (v0)").bold().white()).bold().white()
    );
    println!("{}", format!("╚{}╝", border).bold().white());

    let status_color = if report.status.contains("SUCCESSFULLY") { Color::Green } else { Color::Red };
    println!("[+] Status: {}", report.status.color(status_color).bold());

    if let Some(ref src) = report.idl_source {
        println!("[+] IDL Source: {}", src.cyan());
    }

    if let Some(ref sim) = report.simulation {
        let sim_status = if sim.success {
            format!("WOULD SUCCEED ({} CU consumed)", sim.units_consumed).green()
        } else {
            let detail = match (&sim.error_code, sim.error_instruction_index) {
                (Some(code), Some(idx)) => format!("{} at instruction #{}", code, idx),
                (Some(code), None) => code.clone(),
                _ => sim.error.clone().unwrap_or_else(|| "unknown".to_string()),
            };
            format!("WOULD FAIL: {}", detail).red()
        };
        println!("[+] Simulation: {}", sim_status);
    }

    println!("[+] Fee Payer: {} (Account #0)", display_key(&report.fee_payer, known));
    if !report.signature_verification.is_empty() {
        println!("[+] Signatures:");
        for check in &report.signature_verification {
            let (icon, color) = if check.verified { ("[OK]", Color::Green) } else { ("[FAIL]", Color::Red) };
            println!(
                "    {} #{}: {} ({})",
                icon.color(color).bold(),
                check.index,
                truncate_key(&check.pubkey),
                check.note
            );
        }
    }
    if let Some(ref cb) = report.compute_budget {
        let limit_label = if cb.compute_unit_limit_set {
            format!("{} CU (Custom Limit Set)", cb.compute_unit_limit)
        } else {
            format!("{} CU (Default)", cb.compute_unit_limit)
        };
        println!("[+] Compute Limit: {}", limit_label);
        if cb.compute_unit_price > 0 {
            println!("[+] Priority Fee: {} micro-lamports/CU", cb.compute_unit_price);
            println!(
                "[+] Priority Fee Total: {} lamports (≈ {:.6} SOL, worst case at the CU limit)",
                cb.priority_fee_lamports,
                cb.priority_fee_lamports as f64 / 1e9
            );
            if let Some(actual) = cb.priority_fee_actual {
                println!(
                    "[+] Priority Fee Actual: {} lamports (≈ {:.6} SOL, from simulation units consumed)",
                    actual,
                    actual as f64 / 1e9
                );
            }
        }
    }

    // ── Account Keys & Roles ────────────────────────────────────────────────
    println!();
    println!("{}", "┌── Account Keys & Roles ────────────────────────────────────────────────────────┐".bold());
    for account in &report.accounts {
        let signer = if account.is_signer { "Signer".bold() } else { "Signer".normal() };
        let writable = if account.is_writable { "Writable".yellow() } else { "Read-only".dimmed() };
        print!("│ #{:<2}: {:<15} [{}, {}]", account.index, display_key(&account.pubkey, known), signer, writable);
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
            let resolved_label =
                if alt.resolved { "".to_string() } else { " (unresolved — run with --rpc)".yellow().to_string() };
            println!(
                "│ Table: {} ({} account{}){}",
                truncate_key(&alt.table_address),
                alt.resolved_accounts.len(),
                if alt.resolved_accounts.len() == 1 { "" } else { "s" },
                resolved_label
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

    // ── Instructions Breakdown (CPI tree) ───────────────────────────────────
    println!();
    println!("{}", "┌── Instructions Breakdown ──────────────────────────────────────────────────────┐".bold());
    let failed_index = report.simulation.as_ref().and_then(|s| s.error_instruction_index);
    let failed_code = report.simulation.as_ref().and_then(|s| s.error_code.as_deref());
    for ix in &report.instructions {
        let name = ix.instruction_name.as_deref().unwrap_or(&ix.program_name);
        let failed = failed_index == Some(ix.index);
        let marker = if failed {
            format!(" ← FAILED{}", failed_code.map(|c| format!(": {}", c)).unwrap_or_default()).red().bold()
        } else {
            "".normal()
        };
        println!("│ [Instruction #{}] {}: {}{}", ix.index, ix.program_name.bold(), name.cyan(), marker);
        println!("│   ├── Program: {}", ix.program_id.dimmed());

        if let Some(ref sim) = report.simulation
            && let Some(cu) = sim.instruction_cu.iter().find(|cu| cu.instruction_index == ix.index)
        {
            println!("│   ├── CU Consumed: {} (limit {})", cu.units_consumed, cu.cu_limit);
        }

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
                display_key(&account.pubkey, known),
                account.account_index,
                missing
            );
        }

        for inner in report.inner_instructions.iter().filter(|i| i.parent_instruction_index == ix.index) {
            let inner_name = inner.instruction_name.as_deref().unwrap_or(&inner.program_name);
            println!("│   ├── CPI [{}] {}: {}", inner.inner_index, inner.program_name.dimmed(), inner_name.cyan());
            for account in &inner.accounts {
                let label = account.name.as_deref().unwrap_or("account");
                println!(
                    "│   │   ├── {:<12}: {:<15} (Account #{})",
                    format!("{}:", label),
                    display_key(&account.pubkey, known),
                    account.account_index
                );
            }
            if inner.data != serde_json::Value::Null {
                let data_str = serde_json::to_string(&inner.data).unwrap_or_else(|_| inner.raw_data_hex.clone());
                println!("│   │   └── Data: {}", data_str.dimmed());
            } else if !inner.raw_data_hex.is_empty() {
                println!("│   │   └── Raw Data: {}", inner.raw_data_hex.dimmed());
            }
            if let Some(ta) = &inner.token_amount {
                println!("│   │   └── Token Amount: {} (raw {}, {} decimals)", ta.human, ta.raw, ta.decimals);
            }
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

        if let Some(ta) = &ix.token_amount {
            println!("│   └── Token Amount: {} (raw {}, {} decimals)", ta.human, ta.raw, ta.decimals);
        }
    }
    println!("{}", "└────────────────────────────────────────────────────────────────────────────────┘".bold());

    // ── Decoded Events (Anchor `Program data:`) ─────────────────────────────
    if !report.events.is_empty() {
        println!();
        println!("{}", "┌── Decoded Events ───────────────────────────────────────────────────────────────┐".bold());
        for event in &report.events {
            let fields = serde_json::to_string(&event.fields).unwrap_or_default();
            println!("│ {} [{}] {}", event.name.cyan().bold(), truncate_key(&event.program_id), fields.dimmed());
        }
        println!("{}", "└────────────────────────────────────────────────────────────────────────────────┘".bold());
    }

    // ── Per-Instruction Compute Units ───────────────────────────────────────
    if let Some(ref sim) = report.simulation
        && !sim.instruction_cu.is_empty()
    {
        println!();
        println!("{}", "┌── Per-Instruction Compute Units (from simulation logs) ─────────────────────────┐".bold());
        for cu in &sim.instruction_cu {
            let name = report
                .instructions
                .iter()
                .find(|ix| ix.index == cu.instruction_index)
                .map(|ix| ix.instruction_name.as_deref().unwrap_or(&ix.program_name))
                .unwrap_or("unknown");
            println!(
                "│ Instruction #{} ({}): {} CU (limit {})",
                cu.instruction_index, name, cu.units_consumed, cu.cu_limit
            );
        }
        println!("{}", "└────────────────────────────────────────────────────────────────────────────────┘".bold());
    }

    // ── Balance Changes (from RPC meta) ─────────────────────────────────────
    if !report.balance_changes_sol.is_empty() || !report.token_balance_changes.is_empty() {
        println!();
        println!("{}", "┌── Balance Changes (from RPC meta) ───────────────────────────────────────────────┐".bold());
        for change in &report.balance_changes_sol {
            let color = if change.delta < 0 { Color::Red } else { Color::Green };
            println!(
                "│ SOL {:<6}: {} lamports → {} ({:+} lamports)",
                display_key(&change.pubkey, known),
                change.pre,
                change.post,
                change.delta.to_string().color(color)
            );
        }
        for change in &report.token_balance_changes {
            let color = if change.delta_raw < 0 { Color::Red } else { Color::Green };
            println!(
                "│ TOKEN {:<6}: {} (mint {})",
                display_key(&change.pubkey, known),
                change.delta_human.color(color),
                display_key(&change.mint, known)
            );
        }
        println!("{}", "└────────────────────────────────────────────────────────────────────────────────┘".bold());
    }

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
    let mut value = serde_json::to_value(report).unwrap_or(serde_json::Value::Null);
    if let Some(obj) = value.as_object_mut() {
        obj.insert("schema_version".to_string(), serde_json::json!("1.0"));
    }
    serde_json::to_string_pretty(&value).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
}

/// Render a terminal batch summary: one line per transaction with its exit code.
pub fn render_batch_summary(entries: &[(usize, String, u8)]) {
    println!();
    println!("{}", "┌── Batch Summary ─────────────────────────────────────────────────────────────────┐".bold());
    for (index, signature, exit_code) in entries {
        let color = match exit_code {
            0 => Color::Green,
            1 => Color::Yellow,
            _ => Color::Red,
        };
        println!("│ #{:<3} {} exit={}", index, truncate_key(signature), exit_code.to_string().color(color));
    }
    println!("{}", "└────────────────────────────────────────────────────────────────────────────────┘".bold());
}

/// Export the transaction report for `sat` consumption.
///
/// The shape follows the contract in sat's `tx_report.rs` (`name` per
/// instruction, `pda_info` per account, top-level `program_name`); extra keys
/// are ignored by sat's serde deserialization.
pub fn render_tx_report(report: &TransactionReport, program_name: &str) -> String {
    let sat_report = serde_json::json!({
        "schema_version": "1.0",
        "program_name": program_name,
        "idl_source": report.idl_source,
        "events": report.events.iter().map(|e| {
            serde_json::json!({
                "name": e.name,
                "program_id": e.program_id,
                "fields": e.fields,
            })
        }).collect::<Vec<_>>(),
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
                "name": ix.instruction_name,
                "instruction_name": ix.instruction_name,
                "accounts": ix.accounts.iter().map(|a| {
                    let pda = report.accounts.get(a.account_index as usize).and_then(|acc| acc.pda_info.as_ref());
                    serde_json::json!({
                        "name": a.name,
                        "pubkey": a.pubkey,
                        "account_index": a.account_index,
                        "is_signer": a.is_signer,
                        "is_writable": a.is_writable,
                        "pda_info": pda.map(|p| {
                            serde_json::json!({
                                "seeds_declared": p.seeds_declared,
                                "bump": p.bump,
                                "expected_address": p.expected_address,
                            })
                        }),
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
        "oracle_feeds": report.oracle_feeds.iter().map(|f| {
            serde_json::json!({
                "pubkey": f.pubkey,
                "program": f.program,
                "price": f.price,
                "expo": f.expo,
                "conf": f.conf,
                "status": f.status,
                "publish_time": f.publish_time,
            })
        }).collect::<Vec<_>>(),
        "simulation": report.simulation.as_ref().map(|s| {
            serde_json::json!({
                "success": s.success,
                "error": s.error,
                "units_consumed": s.units_consumed,
                "error_code": s.error_code,
                "error_instruction_index": s.error_instruction_index,
            })
        }),
        "address_lookup_tables": report.address_lookup_tables.iter().map(|alt| {
            serde_json::json!({
                "table_address": alt.table_address,
                "resolved": alt.resolved,
                "resolved_accounts": alt.resolved_accounts.iter().map(|r| {
                    serde_json::json!({
                        "index_in_tx": r.index_in_tx,
                        "pubkey": r.pubkey,
                        "is_writable": r.is_writable,
                    })
                }).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
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
