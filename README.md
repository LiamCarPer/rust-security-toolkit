# Rust Security Toolkit

[![CI](https://github.com/LiamCarPer/rust-security-toolkit/actions/workflows/test.yml/badge.svg)](https://github.com/LiamCarPer/rust-security-toolkit/actions/workflows/test.yml)
[![Security Audit](https://github.com/LiamCarPer/rust-security-toolkit/actions/workflows/security-audit.yml/badge.svg)](https://github.com/LiamCarPer/rust-security-toolkit/actions/workflows/security-audit.yml)

**Solana transaction forensics and IDL-aligned validation CLI for auditors.**

`rts` decodes raw transaction bytes — from explorer exports, RPC responses, block scrapers, or hex dumps — into a human-readable forensics report, then cross-references the decoded instructions against an Anchor IDL to flag structural risks, misconfigurations, and potential attack vectors at the transaction layer.

## Features

- **Multi-encoding decode** — Auto-detects and decodes Base58, Base64, hexadecimal, and raw binary transaction encodings (raw binary works from `--file` and stdin). Supports legacy and v0 versioned transactions with Address Lookup Table (ALT) resolution — actual table pubkeys are fetched on-chain when `--rpc` is provided, with `<alt_index_N>` placeholders offline.
- **Named instruction decoding** — Parses System Program, SPL Token, Token-2022 (including transfer fee, confidential transfer, permanent delegate, and mint close authority extensions), Associated Token Program, and Compute Budget instructions. Matches Anchor IDL 8-byte discriminators for custom programs.
- **IDL-aligned structural validation** — PDA seed verification (tier 1 well-formedness + tier 2 runtime seed cross-reference), missing signer detection, insecure writable account flagging, compute unit analysis (missing limits, reordering, high-CU detection), and ALT integrity checks.
- **Native program expectations** - --expectations <PATH> accepts sat's native expectations export (the IDL analog for programs that ship none, e.g. Mango): 1-byte/8-byte discriminator matching, positional account roles, static PDA seeds, signer/writable/account-count checks, and tier-1/tier-2 PDA validation.
- **On-chain IDL auto-fetch** - `--idl-auto [PROGRAM_ID]` derives and fetches the Anchor IDL account straight from chain (legacy `anchor:idl` layout and the modern Program-Metadata-Program spec, zlib/gzip/base58/base64 handled), then validates the transaction against it - no IDL file hunting
- **Anchor event decoding** - `Program data:` CPI events are decoded against the IDL's event discriminators (explicit spec discriminators honored, computed `sha256("event:Name")[..8]` fallback) with program attribution from the invoke stack; events without IDL field definitions keep their raw payload hex
- **Multi-program IDL auto-fetch** - `--idl-auto` without a PROGRAM_ID fetches on-chain IDLs for every non-builtin program in the transaction (up to 8) and names each one's instructions, top-level and CPI
- **CPI call tree** - the dashboard nests inner instructions under their parent with per-instruction CU (top level), failure markers from simulation, and bundled well-known mint labels (USDC/wSOL/JitoSOL/...)
- **Transaction simulation** — Calls `simulateTransaction` via RPC to check if the transaction would execute at the current chain tip, reporting CU consumption, program error logs, and custom error codes.
- **Transaction-layer pattern detection** — Flags multi-instruction attack-shaped flows: approve-then-transfer (delegate drain), non-signing transfer authorities, fee-payer-as-recipient, repeated destinations, and mint-authority takeover paired with minting in one transaction.
- **Simulation↔decode cross-reference** — With `--rpc`, compares the simulation against the local decode: failing instruction index agreement, CU consumed vs declared limit, log-to-instruction invocation counts, and the *actual* (not worst-case) priority fee from `units_consumed`.
- **Dynamic program verification** — On-chain program ownership checks (BPFLoader, BPFLoaderUpgradeable) and Solana Verified Build Registry lookups to confirm deployed bytecode matches a public source repository. The registry URL is configurable via `--registry`.
- **Offline signature verification** - Cryptographically verifies each required signer's ed25519 signature against the serialized message; fee-payer failures are Critical, other signer failures Warning.
- **Fetch by signature** - `--signature <base58>` pulls the transaction from the RPC endpoint (`getTransaction`) and runs the full analysis pipeline.
- **Per-instruction compute units** - The simulation cross-reference parses `consumed N of M compute units` log lines into a per-instruction CU table and flags estimate-vs-actual deviations that suggest recalibration.
- **Real mainnet attack corpus** - committed mainnet transactions (close-account sweeps, Token-2022 transfers, reordered compute budget) plus SDK-built attack shapes (approve-drain, mint takeover) decoded end-to-end offline in tests/attack_corpus.rs
- **Actual high-CU flagging** - when simulation reports per-instruction compute units, the estimate-based high-CU warnings are superseded: refuted flags are removed and warnings are emitted from actual consumption
- **CPI-aware decoding** - `--signature` fetches getTransaction meta and decodes all inner instructions (with ALT-loaded account resolution, positional role names, and token amounts), rendered as an indented tree; the pattern engine analyzes the full flattened view with parent-aware flags
- **Balance-change analysis** - meta pre/postBalances and pre/postTokenBalances are rendered as per-account SOL and token deltas (sign-aware human amounts); the corpus refresh classifies on the CPI view and captures failed transactions
- **Stake/Vote decoding** - Stake, and Vote program instructions decoded with named fields and positional account roles
- **PDA arg-seed verification (tier 2)** - Anchor IDL `arg` seeds are resolved against decoded argument values (u8-u64/i64 LE, string UTF-8, bool, publicKey) and the derived PDA is compared against the transaction; unresolvable args skip silently
- **Batch mode** - `--batch <NDJSON>` decodes many transactions in one run (JSONL output with `--json`, per-tx exit-code summary otherwise)
- **Known-address registry** - `--known-addresses JSON` names well-known pubkeys across the dashboard
- **Blockhash freshness** - with `--rpc`, expired or near-expiry blockhashes raise BlockhashExpired flags
- **HTML report export** - `--output-html` writes a single self-contained styled HTML report
- **Severity-based exit codes** — The CLI exits `0` (clean), `1` (Info/Warning flags), or `2` (any Critical flag), so scripts and CI can gate on audit results.
- **Cross-tool integration** — Structured JSON export (`--output-tx-report`) consumable by the Solana Audit Toolkit (`sat`) for correlating runtime account configuration against static `#[derive(Accounts)]` analysis.
- **Internal correctness gate** — `--validate-decoding` runs a lightweight byte-level parser alongside `solana-sdk` and cross-checks every structural count (signatures, accounts, instructions, ALT lookups) against the SDK decode, surfacing internal tooling bugs as `TOOL_DECODE_MISMATCH` warnings.

## Installation

### Prerequisites

- Rust 1.89+ (edition 2024; the pinned solana dependency tree requires 1.89)
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

# Reuses the default verified build registry (https://verify.osec.io)
rts --rpc https://api.mainnet-beta.solana.com <tx_bytes>

# Custom verified build registry endpoint
rts --rpc https://api.mainnet-beta.solana.com --registry https://registry.example.com <tx_bytes>

# Offline mode (skips simulation, ownership checks, verified build registry)
rts --no-network <tx_bytes>

# Analyze a transaction by base58 signature (fetches via getTransaction)
rts --rpc https://api.mainnet-beta.solana.com --signature <base58_sig>

# Pattern detection with per-rule severity overrides (patterns.json)
# { "rules": { "approve_then_transfer": { "severity": "critical" }, "repeated_destination": { "enabled": false } } }
rts --patterns patterns.json <tx_bytes>

# Validate internal decoder against solana-sdk
rts --validate-decoding <tx_bytes>
```

Exit codes reflect audit results: `0` = no risk flags, `1` = Info/Warning flags
(or a fatal runtime error such as missing input), `2` = at least one Critical flag.

### CLI reference

```
Usage: rts [OPTIONS] [TX_BYTES]

Arguments:
  [TX_BYTES]  Raw transaction bytes (Base58, Base64, Hex, or raw binary). Use '-' to read from stdin.

Options:
  -f, --file <PATH>               Read transaction bytes from a file
      --idl <PATH>                 Anchor IDL JSON for instruction decoding and validation
      --expectations <PATH>        Native program expectations JSON (sat export); mutually exclusive with --idl
      --rpc <URL>                  RPC endpoint for simulation and on-chain verification
      --signature <BASE58>          Fetch and analyze a transaction by base58 signature (requires --rpc)
      --patterns <PATH>             Pattern detection config JSON (per-rule severity overrides)
      --registry <URL>             Verified build registry URL (default: https://verify.osec.io)
      --json                       Output structured JSON instead of the terminal dashboard
      --output-tx-report <PATH>    Export transaction execution report for sat integration
      --no-network                 Skip all RPC-dependent checks
      --validate-decoding          Run internal byte-level parser alongside solana-sdk
  -h, --help                       Print help
  -V, --version                    Print version
```

The process exit code is derived from the worst risk flag severity: `0` clean,
`1` Info/Warning, `2` Critical (fatal errors also exit `1`).

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
├── patterns.rs     # Transaction-layer pattern detection (approve-drain,
│                   #   authority takeover, repeated destinations)
├── sim_crossref.rs # Simulation ↔ decode cross-reference (error index,
│                   #   CU accounting, actual priority fee)
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

The report contract (`name` per instruction, `pda_info` per account with `bump`,
top-level `program_name`) is locked by the `test_tx_report_sat_contract` test
and verified end-to-end by the ignored `e2e_sat` test:

```bash
SAT_BIN=/path/to/sat cargo test --test e2e_sat -- --ignored
```

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

# Run only simulation tests (mocked HTTP)
cargo test --test simulation

# Run mainnet fixture round-trip tests (offline; skips if no fixtures committed)
cargo test --test mainnet_fixtures

# Run property tests (no-panic, differential gate, encoding round-trips)
cargo test --test properties

# Fuzz the decoder (requires nightly):

# Fuzz the pattern, cross-reference, expectations, and signature-verification
# surfaces (patterns.rs, sim_crossref.rs, expectations.rs, signature_verify.rs)
cargo +nightly fuzz run patterns
cargo +nightly fuzz run sim_crossref
cargo +nightly fuzz run expectations
cargo +nightly fuzz run signature_verify
cargo +nightly fuzz run decode
```

Test coverage:
- **93 tests** (unit, integration, CLI e2e, mocked program verification + simulation + ALT resolution, mainnet round-trip, property tests)
- Encoding detection for all four formats (Base58, Base64, Hex, Raw)
- Transaction round-trip: legacy, v0, and compute budget fixtures
- Mainnet round-trip: 30 committed mainnet transactions decoded across all four encodings with byte-identical reports
- Validator rule coverage: CU analysis, signer checks, writable entity detection, ALT integrity, PDA tier 1
- Program verification: upgradeable, frozen, unknown owner, RPC error handling
- Simulation: mocked RPC success, program error, CU exhaustion, and RPC error scenarios
- ALT resolution: mocked RPC success, not-found, error, and out-of-bounds scenarios
- Input handling: raw binary transactions via `--file` and stdin
- Property tests: no-panic over arbitrary bytes, differential decode gate and encoding round-trips over random valid transactions, IDL arg decoding
- Differential decoding gate: 150-account legacy, v0, and v0-with-ALT transactions parse with zero warnings
- CLI end-to-end: JSON output, stdin piping, `--output-tx-report`, `--validate-decoding`, `--no-network`

## Design principle

The Solana validator runtime is the ground truth for transaction deserialization. This tool does not attempt to second-guess the runtime at the byte level. The custom byte parser exists solely as a self-check (`--validate-decoding`) to surface internal tooling bugs — it is a correctness gate, not an attack-detection mechanism. All structural risk flags derive from IDL-aligned analysis and protocol-level invariants, never from parsing ambiguity.

## License

MIT