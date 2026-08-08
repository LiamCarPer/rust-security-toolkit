use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;

use rust_security_toolkit::types::{IdlJson, RiskSeverity, TransactionReport};
use rust_security_toolkit::{decoder, patterns, sim_crossref, simulator, ui, validator};

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

    /// Run internal byte-level parser alongside solana-sdk and flag any structural disagreements
    #[arg(long = "validate-decoding")]
    validate_decoding: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // All input sources are read as bytes so raw binary transactions work
    // from stdin and --file; encoding detection applies to UTF-8 text.
    let input_bytes: Vec<u8> = match (cli.tx_input, &cli.file) {
        (Some(input), _) if input == "-" => {
            use std::io::Read;
            let mut buffer = Vec::new();
            std::io::stdin().read_to_end(&mut buffer).context("Failed to read transaction from stdin")?;
            buffer
        }
        (Some(input), _) => input.into_bytes(),
        (None, Some(path)) => std::fs::read(path).context("Failed to read transaction file")?,
        (None, None) => {
            eprintln!("Error: No transaction input provided. Use TX_BYTES, --file, or pipe via stdin.");
            std::process::exit(1);
        }
    };

    let idl: Option<IdlJson> = match &cli.idl {
        Some(path) => {
            let contents = std::fs::read_to_string(path).context("Failed to read IDL file")?;
            Some(serde_json::from_str(&contents).context("Failed to parse IDL JSON")?)
        }
        None => None,
    };

    let (raw_bytes_decoded, mut report) = decoder::decode_input(&input_bytes, idl.as_ref())?;
    validator::validate(&mut report, idl.as_ref());
    let pattern_flags = patterns::detect_patterns(&report);
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
        let report_json = ui::render_tx_report(&report, idl.as_ref().map(|i| i.name.as_str()).unwrap_or(""));
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
    use rust_security_toolkit::types::{RiskCategory, RiskFlag, RiskSeverity, TransactionReport};

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
}
