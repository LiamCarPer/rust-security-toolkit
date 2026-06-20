mod decoder;
mod simulator;
mod types;
mod ui;
mod validator;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;

use crate::types::IdlJson;

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

    let tx_input = match (cli.tx_input, &cli.file) {
        (Some(input), _) if input == "-" => {
            use std::io::Read;
            let mut buffer = String::new();
            std::io::stdin().read_to_string(&mut buffer).context("Failed to read transaction from stdin")?;
            buffer.trim().to_string()
        }
        (Some(input), _) => input,
        (None, Some(path)) => {
            std::fs::read_to_string(path).context("Failed to read transaction file")?.trim().to_string()
        }
        (None, None) => {
            eprintln!("Error: No transaction input provided. Use TX_BYTES, --file, or pipe via stdin.");
            std::process::exit(1);
        }
    };

    if tx_input.is_empty() {
        anyhow::bail!("Transaction input is empty");
    }

    let idl: Option<IdlJson> = match &cli.idl {
        Some(path) => {
            let contents = std::fs::read_to_string(path).context("Failed to read IDL file")?;
            Some(serde_json::from_str(&contents).context("Failed to parse IDL JSON")?)
        }
        None => None,
    };

    let raw_bytes = decoder::detect_encoding(&tx_input);
    let raw_bytes_decoded = {
        use base64::Engine;
        let trimmed = tx_input.trim();
        match raw_bytes {
            types::Encoding::Base58 => bs58::decode(trimmed).into_vec().context("Failed to decode Base58 input")?,
            types::Encoding::Base64 => {
                base64::engine::general_purpose::STANDARD.decode(trimmed).context("Failed to decode Base64 input")?
            }
            types::Encoding::Hex => hex::decode(trimmed).context("Failed to decode Hex input")?,
            types::Encoding::Raw => trimmed.as_bytes().to_vec(),
        }
    };

    let mut report = decoder::decode_transaction(&tx_input, idl.as_ref())?;
    validator::validate(&mut report, idl.as_ref());

    if cli.validate_decoding {
        match decoder::validate_decoding(&raw_bytes_decoded) {
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
        let prog_flags = simulator::verify_programs(rpc_url, &report).await;
        report.risk_flags.extend(prog_flags);
    }

    if let Some(ref output_path) = cli.output_tx_report {
        let report_json = ui::render_tx_report(&report);
        std::fs::write(output_path, report_json).context("Failed to write tx-report output")?;
    }

    if cli.json {
        println!("{}", ui::render_json(&report));
    } else {
        ui::render_terminal(&report, use_network);
    }

    Ok(())
}
