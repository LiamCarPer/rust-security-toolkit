use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;

use rust_security_toolkit::types::{ExpectationsDoc, IdlJson, ProgramSchema, RiskSeverity, TransactionReport};
use rust_security_toolkit::{
    balance_changes, batch, bytecode, decoder, event_decoder, html_report, idl_fetch, inner_instructions,
    instruction_decoder, known_addresses, markdown_report, oracle, patterns, sarif, signature_verify, sim_crossref,
    simulator, types, ui, validator,
};

#[derive(Parser)]
#[command(
    name = "rts",
    version = env!("CARGO_PKG_VERSION"),
    about = "Rust Security Toolkit — Solana transaction forensics and IDL-aligned validation CLI for auditors.",
    long_about = "Decodes raw Solana transaction bytes from any source (explorer exports, RPC responses, \
                  block scrapers, hex dumps) into a human-readable audit report, then validates the \
                  decoded instructions against an Anchor IDL to flag structural risks and misconfigurations."
)]
struct Cli {
    /// Raw transaction bytes (Base58, Base64, Hex, or raw binary). Use '-' to read from stdin.
    #[arg(value_name = "TX_BYTES")]
    tx_input: Option<String>,

    /// Read transaction bytes from a file
    #[arg(short = 'f', long = "file", value_name = "PATH")]
    file: Option<PathBuf>,

    /// Anchor IDL JSON for named instruction decoding and validation
    #[arg(long = "idl", value_name = "PATH")]
    idl: Option<PathBuf>,

    /// Native program expectations JSON (sat --expectations export); mutually exclusive with --idl
    #[arg(long = "expectations", value_name = "PATH", conflicts_with = "idl")]
    expectations: Option<PathBuf>,

    /// RPC endpoint URL for simulation and on-chain verification
    #[arg(long = "rpc", value_name = "URL")]
    rpc: Option<String>,

    /// Verified build registry URL for dynamic program verification
    #[arg(
        long = "registry",
        value_name = "URL",
        default_value = rust_security_toolkit::simulator::VERIFIED_BUILD_REGISTRY
    )]
    registry: String,

    /// Output structured JSON instead of the terminal dashboard
    #[arg(long = "json")]
    json: bool,

    /// Export transaction execution report for sat integration
    #[arg(long = "output-tx-report", value_name = "PATH")]
    output_tx_report: Option<PathBuf>,

    /// Skip all RPC-dependent checks (simulation, owner lookups, verified build registry)
    #[arg(long = "no-network")]
    no_network: bool,

    /// Fetch the transaction by base58 signature from the RPC endpoint, then analyze it.
    #[arg(long = "signature", value_name = "BASE58", requires = "rpc", conflicts_with_all = ["tx_input", "file"])]
    signature: Option<String>,

    /// Pattern detection configuration JSON (per-rule severity overrides and toggles)
    #[arg(long = "patterns", value_name = "PATH")]
    patterns_config: Option<PathBuf>,

    /// Fetch the program's Anchor IDL from chain and validate against it;
    /// optional PROGRAM_ID targets a specific program (auto-detects otherwise)
    #[arg(
        long = "idl-auto",
        value_name = "PROGRAM_ID",
        num_args = 0..=1,
        default_missing_value = "",
        conflicts_with_all = ["idl", "expectations"],
        requires = "rpc"
    )]
    idl_auto: Option<String>,

    /// Decode multiple transactions from an NDJSON file (one transaction per line)
    #[arg(long = "batch", value_name = "PATH", conflicts_with_all = ["tx_input", "file", "signature"])]
    batch: Option<PathBuf>,

    /// Known-address registry JSON (pubkey -> display name)
    #[arg(long = "known-addresses", value_name = "PATH")]
    known_addresses: Option<PathBuf>,

    /// Only severities at or above this level count toward the exit code
    #[arg(long = "fail-on", value_name = "SEVERITY", value_parser = ["info", "warning", "critical"])]
    fail_on: Option<String>,

    /// Write a single-file HTML report
    #[arg(long = "output-html", value_name = "PATH")]
    output_html: Option<PathBuf>,

    /// Write a SARIF 2.1.0 report (GitHub code scanning compatible)
    #[arg(long = "output-sarif", value_name = "PATH")]
    output_sarif: Option<PathBuf>,

    /// Write a Markdown report (bounty-submission ready)
    #[arg(long = "output-markdown", value_name = "PATH")]
    output_markdown: Option<PathBuf>,

    /// Disassemble the target program's on-chain bytecode with sol-azy
    /// (fallback for IDL-less / closed-source programs)
    #[arg(long = "disassemble", value_name = "PROGRAM_ID", num_args = 0..=1, default_missing_value = "", requires = "rpc")]
    disassemble: Option<String>,

    /// Persist sol-azy disassembly artifacts under this directory
    #[arg(long = "output-disassembly", value_name = "DIR")]
    output_disassembly: Option<PathBuf>,

    /// Run internal byte-level parser alongside solana-sdk and flag any structural disagreements
    #[arg(long = "validate-decoding")]
    validate_decoding: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let min_severity = parse_fail_on(cli.fail_on.as_deref());
    let min_severity_for_batch = min_severity.clone();

    if let Some(ref batch_path) = cli.batch {
        let contents = std::fs::read_to_string(batch_path).context("Failed to read batch file")?;
        let lines = batch::parse_batch_input(&contents).map_err(|e| anyhow::anyhow!("Invalid batch input: {}", e))?;
        let mut entries: Vec<(usize, String, u8)> = Vec::new();
        let mut worst = 0u8;
        for (i, line) in lines.iter().enumerate() {
            match batch::decode_batch_line(line) {
                Ok((_, mut report)) => {
                    validator::validate(&mut report, None);
                    report.risk_flags.extend(patterns::detect_patterns(&report));
                    types::dedup_risk_flags(&mut report.risk_flags);
                    let code = worst_severity_exit_code(&report, min_severity_for_batch.clone());
                    worst = worst.max(code);
                    if cli.json {
                        println!("{}", ui::render_json(&report));
                    } else {
                        let sig = report.signatures.first().cloned().unwrap_or_default();
                        entries.push((i, sig, code));
                    }
                }
                Err(e) => {
                    eprintln!("batch line {} failed: {}", i, e);
                    worst = worst.max(1);
                }
            }
        }
        if !cli.json {
            ui::render_batch_summary(&entries);
        }
        std::process::exit(i32::from(worst));
    }

    // All input sources are read as bytes so raw binary transactions work
    // from stdin and --file; encoding detection applies to UTF-8 text.
    let mut fetched_meta = None;
    let input_bytes: Vec<u8> = if let Some(ref sig) = cli.signature {
        let rpc_url = cli.rpc.as_ref().context("--signature requires --rpc")?;
        let (bytes, meta) = simulator::fetch_transaction_with_meta(rpc_url, sig).await?;
        fetched_meta = meta;
        bytes
    } else {
        match (cli.tx_input, &cli.file) {
            (Some(input), _) if input == "-" => {
                use std::io::Read;
                let mut buffer = Vec::new();
                std::io::stdin().read_to_end(&mut buffer).context("Failed to read transaction from stdin")?;
                buffer
            }
            (Some(input), _) => input.into_bytes(),
            (None, Some(path)) => std::fs::read(path).context("Failed to read transaction file")?,
            (None, None) => {
                eprintln!(
                    "Error: No transaction input provided. Use TX_BYTES, --file, --signature, or pipe via stdin."
                );
                std::process::exit(1);
            }
        }
    };

    let idl: Option<IdlJson> = match &cli.idl {
        Some(path) => {
            let contents = std::fs::read_to_string(path).context("Failed to read IDL file")?;
            Some(serde_json::from_str(&contents).context("Failed to parse IDL JSON")?)
        }
        None => None,
    };

    let expectations: Option<ExpectationsDoc> = match &cli.expectations {
        Some(path) => {
            let contents = std::fs::read_to_string(path).context("Failed to read expectations file")?;
            let doc: ExpectationsDoc = serde_json::from_str(&contents).context("Failed to parse expectations JSON")?;
            if doc.source != "native" {
                anyhow::bail!(
                    "--expectations requires a native expectations document (source = \"native\", got {:?})",
                    doc.source
                );
            }
            Some(doc)
        }
        None => None,
    };

    let mut schema: Option<ProgramSchema> = match (idl, expectations) {
        (Some(idl), None) => Some(ProgramSchema::Idl(idl)),
        (None, Some(exp)) => Some(ProgramSchema::Native(exp)),
        (None, None) => None,
        (Some(_), Some(_)) => anyhow::bail!("--idl and --expectations are mutually exclusive"),
    };

    let known_addresses: Option<known_addresses::KnownAddresses> = match &cli.known_addresses {
        Some(path) => {
            let contents = std::fs::read_to_string(path).context("Failed to read known-addresses file")?;
            Some(
                known_addresses::parse(&contents)
                    .map_err(|e| anyhow::anyhow!("Invalid known-addresses JSON: {}", e))?,
            )
        }
        None => None,
    };

    let (raw_bytes_decoded, mut report) = decoder::decode_input(&input_bytes, schema.as_ref())?;

    // --idl-auto: fetch the target program's IDL from chain and re-decode with
    // full validation enabled. Only runs when no explicit schema was supplied.
    // --idl-auto: fetch on-chain IDLs for the target program(s) and re-decode
    // with full validation enabled. Only runs when no explicit schema exists.
    let mut idl_fetched_programs: Vec<String> = Vec::new();
    if cli.idl_auto.is_some()
        && schema.is_none()
        && let Some(rpc_url) = cli.rpc.clone()
    {
        let requested = cli.idl_auto.as_deref().filter(|s| !s.is_empty());
        let targets = collect_auto_targets(&report, requested);
        if targets.is_empty() {
            report.warnings.push("IDL auto-fetch: no non-builtin program found to fetch an IDL for".to_string());
        }
        let mut fetched: Vec<(String, types::IdlJson)> = Vec::new();
        for program_id in &targets {
            match idl_fetch::fetch_idl(&rpc_url, program_id).await {
                Ok(Some(idl)) => {
                    idl_fetched_programs.push(program_id.to_string());
                    fetched.push((program_id.to_string(), idl));
                }
                Ok(None) => report.warnings.push(format!("IDL auto-fetch: no on-chain IDL found for {}", program_id)),
                Err(e) => report.warnings.push(format!("IDL auto-fetch failed for {}: {}", program_id, e)),
            }
        }
        if let Some((_primary_program, primary_idl)) = fetched.first().cloned() {
            let primary_schema = ProgramSchema::Idl(primary_idl);
            match decoder::decode_input(&input_bytes, Some(&primary_schema)) {
                Ok((_, fresh)) => {
                    report = fresh;
                    report.idl_source = Some("on-chain".to_string());
                }
                Err(e) => report.warnings.push(format!("IDL auto-fetch re-decode failed: {}", e)),
            }
            schema = Some(primary_schema);
            for (program_id, idl) in fetched.iter().skip(1) {
                let secondary = ProgramSchema::Idl(idl.clone());
                let mut named = 0usize;
                for ix in report.instructions.iter_mut() {
                    if &ix.program_id != program_id || ix.instruction_name.is_some() {
                        continue;
                    }
                    if let Ok(bytes) = hex::decode(&ix.raw_data_hex) {
                        let (name, data) =
                            instruction_decoder::decode_instruction_data(&ix.program_id, &bytes, Some(&secondary));
                        if name.is_some() {
                            ix.instruction_name = name;
                            ix.data = data;
                            named += 1;
                        }
                    }
                }
                for inner in report.inner_instructions.iter_mut() {
                    if &inner.program_id != program_id || inner.instruction_name.is_some() {
                        continue;
                    }
                    if let Ok(bytes) = hex::decode(&inner.raw_data_hex) {
                        let (name, data) =
                            instruction_decoder::decode_instruction_data(&inner.program_id, &bytes, Some(&secondary));
                        if name.is_some() {
                            inner.instruction_name = name;
                            inner.data = data;
                            named += 1;
                        }
                    }
                }
                if named > 0 {
                    report.warnings.push(format!("IDL auto-fetch: named {} instruction(s) for {}", named, program_id));
                }
            }
        }
    }

    if schema.is_some() && report.idl_source.is_none() && cli.idl.is_some() {
        report.idl_source = Some("file".to_string());
    }

    // Bytecode fallback targets: explicit --disassemble wins; otherwise, with
    // --idl-auto, every target whose IDL could not be found on chain.
    let mut bytecode_targets: Vec<solana_sdk::pubkey::Pubkey> = Vec::new();
    if let Some(ref requested_disassemble) = cli.disassemble {
        let requested = Some(requested_disassemble.as_str()).filter(|s| !s.is_empty());
        bytecode_targets = collect_auto_targets(&report, requested);
    } else if cli.idl_auto.is_some() {
        let requested = cli.idl_auto.as_deref().filter(|s| !s.is_empty());
        for target in collect_auto_targets(&report, requested) {
            let id = target.to_string();
            if !idl_fetched_programs.contains(&id) {
                bytecode_targets.push(target);
            }
        }
    }

    validator::validate(&mut report, schema.as_ref());

    if let Some(meta) = fetched_meta {
        if !meta.logs.is_empty() {
            report.logs = meta.logs.clone();
        }
        let warnings = inner_instructions::annotate_report(&mut report, meta.clone());
        report.warnings.extend(warnings);
        let warnings = balance_changes::annotate_report(&mut report, meta);
        report.warnings.extend(warnings);
    }

    match bincode::deserialize::<solana_sdk::transaction::VersionedTransaction>(&raw_bytes_decoded) {
        Ok(tx) => {
            report.signature_verification = signature_verify::verify_transaction(&tx);
            let sig_flags = signature_verify::verify_report(&mut report);
            report.risk_flags.extend(sig_flags);
        }
        Err(e) => {
            report.warnings.push(format!("Signature verification skipped: {}", e));
        }
    }

    let pattern_flags = match &cli.patterns_config {
        Some(path) => {
            let contents = std::fs::read_to_string(path).context("Failed to read patterns config")?;
            let config = patterns::parse_pattern_config(&contents)?;
            patterns::detect_patterns_with_config(&report, &config)
        }
        None => patterns::detect_patterns(&report),
    };
    report.risk_flags.extend(pattern_flags);

    if cli.validate_decoding {
        match decoder::validate_decoding(&raw_bytes_decoded, &report) {
            Ok(warnings) => {
                for w in warnings {
                    report.warnings.push(w);
                }
            }
            Err(e) => {
                report.warnings.push(format!("TOOL_DECODE_MISMATCH: internal parser error: {}", e));
            }
        }
    }

    let use_network = !cli.no_network && cli.rpc.is_some();
    if use_network && let Some(ref rpc_url) = cli.rpc {
        let tx_base64 = {
            use base64::Engine;
            use base64::engine::general_purpose::STANDARD as B64;
            B64.encode(&raw_bytes_decoded)
        };

        match simulator::simulate_transaction(rpc_url, &tx_base64).await {
            Ok(sim_result) => {
                if report.logs.is_empty() {
                    report.logs = sim_result.logs.clone();
                }
                report.simulation = Some(sim_result);
            }
            Err(e) => {
                report.warnings.push(format!("Simulation failed: {}", e));
            }
        }

        // Dynamic program verification: ownership + verified build registry
        let prog_flags = simulator::verify_programs_with_registry(rpc_url, &cli.registry, &report).await;
        report.risk_flags.extend(prog_flags);

        // Resolve address lookup table pubkeys on-chain (v0 transactions)
        let alt_flags = simulator::resolve_address_lookup_tables(rpc_url, &mut report).await;
        report.risk_flags.extend(alt_flags);

        // Decode and validate referenced oracle price feeds (Pyth).
        let oracle_flags = oracle::run(rpc_url, &mut report).await.unwrap_or_default();
        report.risk_flags.extend(oracle_flags);

        // Blockhash freshness: can this transaction still land?
        if let Ok((current_height, last_valid_height)) = simulator::get_latest_blockhash(rpc_url).await
            && let Some(flag) =
                simulator::blockhash_flag(simulator::blockhash_freshness(current_height, last_valid_height))
        {
            report.risk_flags.push(flag);
        }

        // Bytecode fallback: disassemble IDL-less programs with sol-azy.
        if !bytecode_targets.is_empty() {
            let options = bytecode::AnalyzeOptions {
                binary: bytecode::sol_azy_binary(),
                artifact_dir: cli.output_disassembly.clone(),
            };
            let warnings = bytecode::analyze_programs(rpc_url, &mut report, &bytecode_targets, &options).await;
            report.warnings.extend(warnings);
        }
    }

    let crossref_flags = sim_crossref::cross_reference(&mut report);
    report.risk_flags.extend(crossref_flags);

    // Annotate token amounts (checked variants resolve offline; unchecked need RPC)
    simulator::resolve_token_amounts(cli.rpc.as_deref(), &mut report).await;

    if let Some(ProgramSchema::Idl(idl)) = schema.as_ref() {
        event_decoder::decode_events(&mut report, idl);
    }

    types::dedup_risk_flags(&mut report.risk_flags);

    if let Some(ref output_path) = cli.output_tx_report {
        let program_name = schema
            .as_ref()
            .map(|s| match s {
                ProgramSchema::Idl(idl) => idl.name.as_str(),
                ProgramSchema::Native(exp) => exp.program_name.as_str(),
            })
            .unwrap_or("");
        let report_json = ui::render_tx_report(&report, program_name);
        std::fs::write(output_path, report_json).context("Failed to write tx-report output")?;
    }

    if let Some(ref output_path) = cli.output_html {
        std::fs::write(output_path, html_report::render_html(&report)).context("Failed to write HTML report")?;
    }

    if let Some(ref output_path) = cli.output_sarif {
        std::fs::write(output_path, sarif::render_sarif(&report)).context("Failed to write SARIF report")?;
    }

    if let Some(ref output_path) = cli.output_markdown {
        std::fs::write(output_path, markdown_report::render_markdown(&report))
            .context("Failed to write Markdown report")?;
    }

    if cli.json {
        println!("{}", ui::render_json(&report));
    } else {
        ui::render_terminal_with_known(&report, use_network, known_addresses.as_ref());
    }

    std::process::exit(i32::from(worst_severity_exit_code(&report, min_severity)));
}

fn collect_auto_targets(report: &TransactionReport, requested: Option<&str>) -> Vec<solana_sdk::pubkey::Pubkey> {
    use std::str::FromStr;
    const BUILTIN: &[&str] = &[
        rust_security_toolkit::types::SYSTEM_PROGRAM_ID,
        rust_security_toolkit::types::TOKEN_PROGRAM_ID,
        rust_security_toolkit::types::TOKEN_2022_PROGRAM_ID,
        rust_security_toolkit::types::ASSOCIATED_TOKEN_PROGRAM_ID,
        rust_security_toolkit::types::COMPUTE_BUDGET_PROGRAM_ID,
        rust_security_toolkit::types::ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
        rust_security_toolkit::types::STAKE_PROGRAM_ID,
        rust_security_toolkit::types::VOTE_PROGRAM_ID,
    ];
    const MAX_TARGETS: usize = 8;
    if let Some(id) = requested.filter(|s| !s.is_empty()) {
        return solana_sdk::pubkey::Pubkey::from_str(id).ok().into_iter().collect();
    }
    let mut seen: Vec<&str> = Vec::new();
    for pid in report.instructions.iter().map(|ix| ix.program_id.as_str()) {
        if !BUILTIN.contains(&pid) && !seen.contains(&pid) {
            seen.push(pid);
        }
    }
    seen.iter().take(MAX_TARGETS).filter_map(|p| solana_sdk::pubkey::Pubkey::from_str(p).ok()).collect()
}

fn parse_fail_on(level: Option<&str>) -> RiskSeverity {
    match level {
        Some("warning") => RiskSeverity::Warning,
        Some("critical") => RiskSeverity::Critical,
        _ => RiskSeverity::Info,
    }
}

fn severity_rank(severity: &RiskSeverity) -> u8 {
    match severity {
        RiskSeverity::Critical => 2,
        RiskSeverity::Warning => 1,
        RiskSeverity::Info => 0,
    }
}

fn worst_severity_exit_code(report: &TransactionReport, min_severity: RiskSeverity) -> u8 {
    let min_rank = severity_rank(&min_severity);
    let mut worst = 0;
    for flag in &report.risk_flags {
        if severity_rank(&flag.severity) < min_rank {
            continue;
        }
        let code = match flag.severity {
            RiskSeverity::Critical => 2,
            RiskSeverity::Warning | RiskSeverity::Info => 1,
        };
        if code > worst {
            worst = code;
        }
    }
    worst
}

#[cfg(test)]
mod tests {
    use crate::worst_severity_exit_code;
    use rust_security_toolkit::types::{
        ExpectationsDoc, ProgramSchema, RiskCategory, RiskFlag, RiskSeverity, TransactionReport,
    };

    fn report_with_flags(severities: &[RiskSeverity]) -> TransactionReport {
        let risk_flags = severities
            .iter()
            .map(|severity| RiskFlag {
                severity: severity.clone(),
                category: RiskCategory::VerifiedBuild,
                instruction_index: None,
                message: String::new(),
                details: String::new(),
            })
            .collect();
        TransactionReport {
            status: String::new(),
            fee_payer: String::new(),
            signatures: Vec::new(),
            recent_blockhash: String::new(),
            message_version: None,
            accounts: Vec::new(),
            instructions: Vec::new(),
            address_lookup_tables: Vec::new(),
            compute_budget: None,
            risk_flags,
            simulation: None,
            warnings: Vec::new(),
            signature_verification: Vec::new(),
            inner_instructions: Vec::new(),
            balance_changes_sol: Vec::new(),
            token_balance_changes: Vec::new(),
            oracle_feeds: Vec::new(),
            idl_source: None,
            logs: vec![],
            events: vec![],
            program_analyses: Vec::new(),
        }
    }

    #[test]
    fn empty_flags_exit_zero() {
        assert_eq!(worst_severity_exit_code(&report_with_flags(&[]), RiskSeverity::Info), 0);
    }

    #[test]
    fn info_flag_exit_one() {
        assert_eq!(worst_severity_exit_code(&report_with_flags(&[RiskSeverity::Info]), RiskSeverity::Info), 1);
    }

    #[test]
    fn warning_flag_exit_one() {
        assert_eq!(worst_severity_exit_code(&report_with_flags(&[RiskSeverity::Warning]), RiskSeverity::Info), 1);
    }

    #[test]
    fn critical_flag_exit_two() {
        assert_eq!(worst_severity_exit_code(&report_with_flags(&[RiskSeverity::Critical]), RiskSeverity::Info), 2);
    }

    #[test]
    fn fail_on_warning_ignores_info_flags() {
        assert_eq!(worst_severity_exit_code(&report_with_flags(&[RiskSeverity::Info]), RiskSeverity::Warning), 0);
        assert_eq!(worst_severity_exit_code(&report_with_flags(&[RiskSeverity::Warning]), RiskSeverity::Warning), 1);
    }

    #[test]
    fn fail_on_critical_ignores_warnings() {
        assert_eq!(worst_severity_exit_code(&report_with_flags(&[RiskSeverity::Warning]), RiskSeverity::Critical), 0);
        assert_eq!(worst_severity_exit_code(&report_with_flags(&[RiskSeverity::Critical]), RiskSeverity::Critical), 2);
    }

    #[test]
    fn expectations_doc_source_validation() {
        let doc: ExpectationsDoc =
            serde_json::from_str(r#"{"program_name":"p","program_id":null,"source":"anchor","instructions":[]}"#)
                .expect("parse doc");
        assert_eq!(doc.source, "anchor");
    }

    #[test]
    fn program_schema_native_variant_roundtrip() {
        let exp: ExpectationsDoc = serde_json::from_str(
            r#"{"program_name":"p","program_id":null,"source":"native","instructions":[
                {"name":"DoThing","discriminator_hex":"42","handler":"do_thing","accounts":[]}
            ]}"#,
        )
        .expect("parse doc");
        let schema = ProgramSchema::Native(exp);
        let ProgramSchema::Native(exp) = &schema else {
            panic!("expected Native variant");
        };
        assert!(exp.find_instruction("DoThing").is_some());
        assert!(exp.find_instruction("Nope").is_none());
    }
}
