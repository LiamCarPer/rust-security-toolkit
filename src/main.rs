use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;

use rust_security_toolkit::types::{ExpectationsDoc, IdlJson, ProgramSchema, RiskSeverity, TransactionReport};
use rust_security_toolkit::{decoder, patterns, signature_verify, sim_crossref, simulator, ui, validator};

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

    /// Run internal byte-level parser alongside solana-sdk and flag any structural disagreements
    #[arg(long = "validate-decoding")]
    validate_decoding: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // All input sources are read as bytes so raw binary transactions work
    // from stdin and --file; encoding detection applies to UTF-8 text.
    let input_bytes: Vec<u8> = if let Some(ref sig) = cli.signature {
        let rpc_url = cli.rpc.as_ref().context("--signature requires --rpc")?;
        simulator::fetch_transaction_by_signature(rpc_url, sig).await?
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

    let schema: Option<ProgramSchema> = match (idl, expectations) {
        (Some(idl), None) => Some(ProgramSchema::Idl(idl)),
        (None, Some(exp)) => Some(ProgramSchema::Native(exp)),
        (None, None) => None,
        (Some(_), Some(_)) => anyhow::bail!("--idl and --expectations are mutually exclusive"),
    };

    let (raw_bytes_decoded, mut report) = decoder::decode_input(&input_bytes, schema.as_ref())?;
    validator::validate(&mut report, schema.as_ref());

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
    }

    let crossref_flags = sim_crossref::cross_reference(&mut report);
    report.risk_flags.extend(crossref_flags);

    // Annotate token amounts (checked variants resolve offline; unchecked need RPC)
    simulator::resolve_token_amounts(cli.rpc.as_deref(), &mut report).await;

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

    if cli.json {
        println!("{}", ui::render_json(&report));
    } else {
        ui::render_terminal(&report, use_network);
    }

    std::process::exit(i32::from(worst_severity_exit_code(&report)));
}

fn worst_severity_exit_code(report: &TransactionReport) -> u8 {
    let mut worst = 0;
    for flag in &report.risk_flags {
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
        }
    }

    #[test]
    fn empty_flags_exit_zero() {
        assert_eq!(worst_severity_exit_code(&report_with_flags(&[])), 0);
    }

    #[test]
    fn info_flag_exit_one() {
        assert_eq!(worst_severity_exit_code(&report_with_flags(&[RiskSeverity::Info])), 1);
    }

    #[test]
    fn warning_flag_exit_one() {
        assert_eq!(worst_severity_exit_code(&report_with_flags(&[RiskSeverity::Warning])), 1);
    }

    #[test]
    fn critical_flag_exit_two() {
        assert_eq!(worst_severity_exit_code(&report_with_flags(&[RiskSeverity::Critical])), 2);
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
