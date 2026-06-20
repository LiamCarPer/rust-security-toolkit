# Rust Security Toolkit

[![CI](https://github.com/LiamCarPer/rust-security-toolkit/actions/workflows/test.yml/badge.svg)](https://github.com/LiamCarPer/rust-security-toolkit/actions/workflows/test.yml)
[![Security Audit](https://github.com/LiamCarPer/rust-security-toolkit/actions/workflows/security-audit.yml/badge.svg)](https://github.com/LiamCarPer/rust-security-toolkit/actions/workflows/security-audit.yml)

**Solana transaction forensics and IDL-aligned validation CLI for auditors.**

`rts` decodes raw transaction bytes — from explorer exports, RPC responses, block scrapers, or hex dumps — into a human-readable forensics report, then cross-references the decoded instructions against an Anchor IDL to flag structural risks, misconfigurations, and potential attack vectors at the transaction layer.

## Features

- **Multi-encoding decode** — Auto-detects and decodes Base58, Base64, hexadecimal, and raw binary transaction encodings. Supports legacy and v0 versioned transactions with Address Lookup Table (ALT) resolution.
- **Named instruction decoding** — Parses System Program, SPL Token, Token-2022 (including transfer fee, confidential transfer, permanent delegate, and mint close authority extensions), Associated Token Program, and Compute Budget instructions. Matches Anchor IDL 8-byte discriminators for custom programs.
- **IDL-aligned structural validation** — PDA seed verification (tier 1 well-formedness + tier 2 runtime seed cross-reference), missing signer detection, insecure writable account flagging, compute unit analysis (missing limits, reordering, high-CU detection), and ALT integrity checks.
- **Transaction simulation** — Calls `simulateTransaction` via RPC to check if the transaction would execute at the current chain tip, reporting CU consumption, program error logs, and custom error codes.
- **Dynamic program verification** — On-chain program ownership checks (BPFLoader, BPFLoaderUpgradeable) and Solana Verified Build Registry lookups to confirm deployed bytecode matches a public source repository.
- **Cross-tool integration** — Structured JSON export (`--output-tx-report`) consumable by the Solana Audit Toolkit (`sat`) for correlating runtime account configuration against static `#[derive(Accounts)]` analysis.
- **Internal correctness gate** — `--validate-decoding` runs a lightweight byte-level parser alongside `solana-sdk` to surface internal tooling bugs transparently.

## Installation

### Prerequisites

- Rust 1.80+ (edition 2024)
- Solana CLI (optional, for RPC simulation features)

### From source

```bash
git clone https://github.com/LiamCarPer/rust-security-toolkit.git
cd rust-security-toolkit
cargo build --release
```

The binary is `target/release/rts`.

### Dependencies

| Crate | Purpose |
|-------|---------|
| `solana-sdk` 4.x | Canonical transaction deserialization, PDA derivation |
| `solana-client` 4.x | RPC client for simulation and program verification |
| `clap` 4.x | CLI argument parsing with derive macros |
| `tokio` 1.x | Async runtime for RPC calls |
| `serde` / `serde_json` | JSON serialization and Anchor IDL parsing |
| `reqwest` | HTTP client for RPC and verified build registry |
| `sha2` | Anchor 8-byte discriminator computation |
| `bincode` | Solana wire-format deserialization |
| `colored` | ANSI terminal styling |

## Usage

### Basic decode

```bash
# From a hex-encoded transaction
rts 01000102c4f1e3a2b5d6c7e8090a1b2c3d4e5f60718293a4b5c6d7e8090a1b2c3d4e5f6...

# From a file
rts --file path/to/tx.hex

# From stdin (pipeline-friendly)
curl -s https://api.mainnet-beta.solana.com -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getTransaction",...}' | jq -r '.result.transaction[0]' | rts -
```

### With Anchor IDL validation

```bash
rts --idl path/to/program.json <tx_bytes>
```

When an IDL is provided, the decoder matches 8-byte discriminators to identify named instructions, decodes arguments by type, and cross-references account roles (signer, PDA seeds) against the IDL declarations.

### Output formats

```bash
# Default: ANSI terminal dashboard
rts <tx_bytes>

# Structured JSON
rts --json <tx_bytes>

# sat-compatible execution report
rts --output-tx-report report.json <tx_bytes>
```

### Network-dependent features

```bash
# Full analysis with RPC simulation and program verification
rts --rpc https://api.mainnet-beta.solana.com <tx_bytes>

# Offline mode (skips simulation, ownership checks, verified build registry)
rts --no-network <tx_bytes>

# Validate internal decoder against solana-sdk
rts --validate-decoding <tx_bytes>
```

### CLI reference

```
Usage: rts [OPTIONS] [TX_BYTES]

Arguments:
  [TX_BYTES]  Raw transaction bytes (Base58, Base64, Hex, or raw binary). Use '-' to read from stdin.

Options:
  -f, --file <PATH>               Read transaction bytes from a file
      --idl <PATH>                 Anchor IDL JSON for instruction decoding and validation
      --rpc <URL>                  RPC endpoint for simulation and on-chain verification
      --json                       Output structured JSON instead of the terminal dashboard
      --output-tx-report <PATH>    Export transaction execution report for sat integration
      --no-network                 Skip all RPC-dependent checks
      --validate-decoding          Run internal byte-level parser alongside solana-sdk
  -h, --help                       Print help
  -V, --version                    Print version
```

## Architecture

```
src/
├── main.rs         # CLI entry point, argument parsing, orchestration
├── decoder.rs      # Transaction deserialization, encoding detection,
│                   #   instruction parsing (System, Token, Token-2022,
│                   #   AToken, ComputeBudget), Anchor IDL discriminator
│                   #   matching, internal byte-level parser
├── validator.rs    # IDL-aligned structural risk checks (PDA seeds,
│                   #   signer roles, CU analysis, ALT integrity,
│                   #   writable account detection)
├── simulator.rs    # RPC wrappers: simulateTransaction, program
│                   #   ownership verification, verified build registry
├── ui.rs           # ANSI terminal dashboard, JSON export, sat
│                   #   integration format
└── types.rs        # Shared data models, Anchor IDL types, known
                    #   program/sysvar IDs
```

## Cross-tool integration with `sat`

The toolkit's primary downstream consumer is the **Solana Audit Toolkit (`sat`)**:

1. Capture or obtain a raw transaction
2. `rts --output-tx-report report.json <tx_bytes>` produces a structured report containing mapped account keys, parsed instruction names, decoded arguments, and PDA seed declarations
3. `sat analyze src --tx-report report.json` ingests the report and cross-references runtime account configuration against AST-parsed `#[derive(Accounts)]` structures

## Testing

```bash
# Run all tests (unit + integration + CLI end-to-end)
cargo test

# Generate fixture files from mainnet (requires RPC access)
cargo test fetch_mainnet_fixtures -- --ignored

# Generate synthetic test fixtures
cargo test generate_fixtures -- --ignored

# Run only CLI end-to-end tests
cargo test --test cli_e2e

# Run only program verification tests (mocked HTTP)
cargo test --test program_verification
```

Test coverage:
- **56 tests** (unit, integration, CLI e2e, mocked program verification)
- Encoding detection for all four formats (Base58, Base64, Hex, Raw)
- Transaction round-trip: legacy, v0, and compute budget fixtures
- Validator rule coverage: CU analysis, signer checks, writable entity detection, ALT integrity, PDA tier 1
- Program verification: upgradeable, frozen, unknown owner, RPC error handling
- CLI end-to-end: JSON output, stdin piping, `--output-tx-report`, `--validate-decoding`, `--no-network`

## Design principle

The Solana validator runtime is the ground truth for transaction deserialization. This tool does not attempt to second-guess the runtime at the byte level. The custom byte parser exists solely as a self-check (`--validate-decoding`) to surface internal tooling bugs — it is a correctness gate, not an attack-detection mechanism. All structural risk flags derive from IDL-aligned analysis and protocol-level invariants, never from parsing ambiguity.

## License

MIT
