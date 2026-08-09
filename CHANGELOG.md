# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added
- **Per-instruction CU attribution**: the simulation cross-reference parses
  Program X consumed N of M compute units log lines into a per-instruction CU
  table (new SimulationResult.instruction_cu), shown on the dashboard; flags
  Info-level estimate-vs-actual deviations suggesting estimate_cu_cost
  recalibration
- **CU estimate audit** (src/decoder.rs): corrected System Transfer (1.5k to 1k),
  Allocate/Assign, System default, and Token Initialize* (15k to 5k) entries;
  estimate_cu_cost exposed pub(crate) for the cross-reference
- **Offline signature verification** (src/signature_verify.rs): per-signer
  ed25519 verification against the serialized message; fee-payer failures are
  Critical, other signer failures Warning (SignatureMismatch category)
- **Fetch by signature**: --signature BASE58 (requires --rpc) fetches the
  transaction via getTransaction and runs the full analysis pipeline
- **Pattern config**: --patterns PATH JSON enables per-rule severity overrides
- **Native program expectations** (--expectations): consumes sat native expectations
  documents as the IDL analog for IDL-less programs; 1-byte/8-byte discriminator
  matching (expectations_decoder), positional account roles, static PDA seeds,
  and native tier-1/tier-2 validator checks (missing signer, writable role,
  account count, PDA well-formedness and seed cross-reference)
- **Writable header fix**: readonly-signer messages now derive account writability
  exactly like the runtime is_writable_index (previously every readonly signer
  was mislabeled writable)
  and disabling for the five pattern rules; unknown keys/severities are hard errors
- **Transaction-layer pattern detection** (`src/patterns.rs`): approve-then-
  transfer delegate drain, non-signing token transfer authorities, fee payer
  as recipient, repeated destinations, and mint-authority takeover with
  same-transaction minting — flagged under a new `PatternDetection` category
- **Simulation ↔ decode cross-reference** (`src/sim_crossref.rs`): simulation
  error index vs decoded range, CU consumed vs declared limit, log
  invocation counts vs decoded instructions, and the actual (not worst-case)
  priority fee (`price × units_consumed / 1e6`, `ComputeBudgetInfo
  .priority_fee_actual`) shown on the dashboard when `--rpc` simulation runs
- **Severity-based exit codes**: `0` clean, `1` Info/Warning, `2` Critical —
  always-on, so scripts/CI can gate on audit results
- **Configurable verified build registry**: `--registry <URL>` flag replaces
  the hardcoded `https://verify.osec.io` default
- Known-program account roles: System, Token, Token-2022, and Associated Token
  instructions now carry static positional role names (from/to/source/mint/
  authority/...) on their mapped accounts
- Human-readable token amounts on Transfer/Approve/MintTo/Burn instructions:
  checked variants resolve offline from inline decimals; unchecked variants
  resolve mint decimals via cached RPC `getAccountInfo` when `--rpc` is given
- Worst-case priority fee reporting: total lamports/SOL from
  `SetComputeUnitPrice` x CU limit, shown on the terminal dashboard and in JSON

### Fixed
- Compute Budget discriminator mapping: `RequestHeapFrame` (1) was mislabeled
  as `SetComputeUnitLimit`, and the real `SetComputeUnitLimit` (2) was never
  parsed — explicit CU limits silently defaulted to 200k and raised a false
  "Missing Compute Budget" warning
- System instruction discriminators 7-11: `AuthorizeNonceAccount` was labeled
  "ResizeNonceAccount" and Allocate/AllocateWithSeed/AssignWithSeed/
  TransferWithSeed were shifted one off with wrong field offsets (now verified
  by round-trip tests against the real SDK serialization)
- `compute_budget_transfer.hex` fixture regenerated with the correct
  `SetComputeUnitLimit` tag
- `--output-tx-report` now emits the sat contract keys (`name` per instruction,
  `pda_info` per account with `bump`, top-level `program_name`) and populates
  IDL-declared account names, making the cross-tool correlation work
  (verified end-to-end against sat)

### Changed
- Security Audit CI gates on `cargo deny check` (cargo-geiger is informational,
  runs on nightly, and no longer blocks the pipeline)
- `cargo clippy --all-targets -- -D warnings` is clean including test targets

## [v0.1.0] - 2026-08-08

Initial release: Solana transaction forensics and IDL-aligned validation CLI for auditors.

### Added
- Multi-encoding decode (Base58, Base64, Hex, raw binary from `--file`/stdin) with
  ambiguity fallback between hex, base58, and padding-less base64
- Legacy and v0 versioned transaction support with on-chain Address Lookup Table
  resolution via `--rpc` (placeholders offline)
- Named instruction decoding: System, Token, Token-2022 (including transfer-fee,
  confidential-transfer, pointer, transfer-hook, and pausable extensions), AToken,
  Compute Budget, and Anchor IDL discriminators
- IDL-aligned structural validation: PDA seed tiers, missing signer detection,
  insecure writable entities, compute unit analysis, ALT integrity, and IDL account
  count consistency
- Transaction simulation with structured error codes (instruction index + code)
- Dynamic program verification: BPF loader ownership, verified build registry
  lookups, and upgrade authority reporting
- Differential decode gate (`--validate-decoding`) cross-checking the internal
  byte parser against `solana-sdk`
- `sat`-compatible transaction report export (`--output-tx-report`)
- Test suite: 92 tests including mocked-RPC simulation/verification/ALT suites,
  a 30-transaction mainnet fixture round-trip suite, and property tests
  (no-panic, differential gate, encoding round-trips) plus a libFuzzer target

### Fixed
- ComputeBudget reorder detection now applies the protocol prefix rule
- Token-2022 discriminator 31/35 mislabeling (CreateNativeMint vs
  InitializePermanentDelegate)
- Unbounded allocation in the Anchor argument decoder (malicious length
  prefixes) — found by the property test suite
- Compact-u16 (short_vec) and v0 message parsing in the internal decoder
- Dependency resolution: solana crates pinned to the agave 4.1.2 release train
  (wincode 0.5/0.6 incompatibility); `Cargo.lock` committed

### Security
- `cargo deny` license/advisory/bans policy (`deny.toml`)
- Property-based no-panic guarantees over arbitrary input bytes