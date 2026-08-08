# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Fixed
- `--output-tx-report` now emits the sat contract keys (`name` per instruction,
  `pda_info` per account with `bump`, top-level `program_name`) and populates
  IDL-declared account names, making the cross-tool correlation actually work
  (verified end-to-end against sat).

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
