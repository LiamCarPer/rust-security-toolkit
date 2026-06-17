# Product Requirements Document (PRD)
## Project Name: Rust Security Toolkit (`rust-security-toolkit`)
**Author:** Liam Carvajal
**Date:** June 20, 2026

---

## 1. Executive Summary & Objective

The **Rust Security Toolkit** is a transaction forensics and IDL-aligned validation CLI for Solana auditors. It decodes raw transaction bytes from any source (explorer exports, RPC responses, block scrapers, hex dumps) into a human-readable audit report, then validates the decoded instructions against an Anchor IDL to flag structural risks and misconfigurations.

**What it does:** Forensics on what a transaction *actually does* — decoding, simulation, account-role mapping, CU analysis, PDA verification, and structural risk flagging — and exports structured JSON that feeds into the Solana Audit Toolkit (`sat`) for cross-referencing against static code analysis.

**What it does not do:** Find novel zero-day vulnerabilities by byte-parsing the wire format. The Solana validator runtime is the ground truth for transaction deserialization. Disagreements between a custom parser and `solana-sdk` are the tool's own bugs, not attack vectors. The tool includes a lightweight internal decoder correctness check (`--validate-decoding`) as a quality-gate on its own output, not as a vulnerability discovery mechanism.

---

## 2. Key Features & Functional Requirements

### 2.1 CLI Interface (Clap + Tokio Async)
- **Input Sources:**
  - Raw transaction bytes via positional argument or `stdin` (pipeline-friendly: `curl <rpc> | rts decode -`).
  - `--file <path>`: Read transaction bytes from a file.
- **Context Inputs:**
  - `--idl <path>`: Anchor IDL JSON to enable named instruction decoding, PDA seed validation, and account-role mapping against expected program behavior.
  - `--rpc <url>`: Optional RPC endpoint for simulation and on-chain program verification.
- **Output Formats:**
  - Default: ANSI-styled terminal dashboard (human-readable forensics report).
  - `--json`: Structured JSON matching a stable audit schema.
  - `--output-tx-report <path>`: Streamlined JSON transaction execution report consumed by `sat analyze src --tx-report <json>` for cross-tool correlation.
- **Operational Flags:**
  - `--no-network`: Skip all RPC-dependent checks (simulation, owner lookups, verified build registry). Prints a banner listing omitted checks.
  - `--validate-decoding`: Run the internal byte-level parser alongside `solana-sdk` and flag any structural disagreement as a tool-internal correctness warning (not a security finding).

### 2.2 Transaction Decoder & Human-Readable Forensics

- **Encoding Auto-detection:** Base58 (explorer standard), Base64 (RPC JSON API), Hexadecimal, and raw binary.
- **Protocol Support:** Legacy transactions and v0 Versioned Transactions (with Address Lookup Table resolution).
- **Primary Decoding Path (`solana-sdk`):** Deserializes the transaction into `VersionedTransaction`, extracting the full account list, signatures, recent blockhash, compute budget instructions, and instruction boundaries. This is the canonical decode — it matches what the validator accepts.
- **Internal Correctness Check (`--validate-decoding`):** A lightweight byte-level parser that independently processes compact-u16 headers, signature counts, and instruction boundaries. Any disagreement with the `solana-sdk` path is reported as a `TOOL_DECODE_MISMATCH` warning — a signal that the tool's own parser logic needs fixing, surfaced transparently rather than silently producing bad output.
- **Core Instruction Decoding:**
  - **System Program:** Transfer, CreateAccount, Assign, Allocate, AssignWithSeed.
  - **Token Program** (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`): Transfer, MintTo, Burn, Approve, Revoke, CloseAccount.
  - **Token-2022 Program** (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`): All Token-equivalent operations plus extension-specific instructions (CreateMint with extensions, ConfidentialTransfer, UpdateTransferFee, etc.).
  - **Associated Token Program:** Create, CreateIdempotent, RecoverNested.
- **Anchor IDL Custom Instruction Decoding:** When an IDL is provided, computes 8-byte discriminators (`sha256("global:<instruction_name>")[0..8]`) and matches instruction data prefixes to identify named instructions, argument names, and types — replacing raw hex dumps with semantic labels.

### 2.3 Transaction Validation & Structural Risk Analysis

These checks operate on the decoded transaction **cross-referenced against an Anchor IDL** (when provided) or against Solana protocol invariants. They do not claim to find vulnerabilities in program source code — that is `sat`'s job. They flag misconfigurations, missing constraints, and structural risks visible at the transaction layer.

- **PDA Seed Validation (two-tier):**
  - **Tier 1 — IDL Well-Formedness (always available):** Validates that PDA accounts in the IDL declare well-formed `seeds` arrays with valid account index references and bump seeds.
  - **Tier 2 — Runtime Seed Verification (requires tx + IDL):** Computes `find_program_address(seeds, program_id)` for every declared PDA seed and cross-references the derived address against the actual account pubkey in the transaction. A mismatch indicates the PDA in the transaction was not derived from the seeds declared in the IDL — a potential account substitution.
- **Missing Signer Check:**
  - Cross-references instruction account roles against the IDL's expected signer configuration. Flags accounts that the IDL declares as requiring a signature but appear as non-signers in the transaction's message header.
- **Insecure Writable Accounts:**
  - Flags read-only entities (sysvar program IDs, known program addresses) that are marked as writable in the transaction account list — a common fee-locking or account-hijacking precondition.
- **Compute Unit (CU) Analysis:**
  - Parses `ComputeBudget` instructions (`RequestUnits`, `SetComputeUnitLimit`, `SetComputeUnitPrice`).
  - Flags transactions missing explicit CU limit constraints (defaulting to 200k per instruction — a spam-based DoS vector).
  - Highlights high-CU-depletion instruction sequences.
  - Flags `ComputeBudget` instructions reordered or injected mid-transaction (position other than index 0), which attackers use to manipulate priority fees or trigger frontrunning.
- **Address Lookup Table (ALT) Validation (v0 transactions):**
  - Verifies ALT entries are resolved and loaded correctly.
  - Flags empty lookup tables, mismatched address counts, and ALT accounts that may be closed between simulation and execution.
- **Dynamic Program Verification (online, optional):**
  - Checks on-chain program ownership (e.g., is the program owned by `BPFLoaderUpgradeab1e11111111111111111111111`?).
  - Cross-references against the Solana Verified Build Registry to confirm deployed bytecode matches a public source repository.
  - Avoids static program blacklists — all checks are dynamic and verifiable.
- **Transaction Simulation (online, requires `--rpc`):**
  - Calls `simulateTransaction` against the configured RPC endpoint.
  - Reports: execution success/failure, program error logs, insufficient funds, compute unit exhaustion, and any custom program error codes.
  - Provides an audit triage signal: if a transaction would fail at the current chain tip, investigating its exploit potential is deprioritized.

### 2.4 Cross-Tool Integration with `sat`

The toolkit's primary downstream consumer is the **Solana Audit Toolkit (`sat`)**. The bridge works as follows:

1. The user captures or obtains a raw transaction (explorer export, RPC response, archive replay).
2. `rts decode --json --output-tx-report report.json <tx_bytes>` produces a structured execution report containing:
   - Mapped account keys with roles (signer, writable, PDA-derived).
   - Parsed instruction names (from IDL discriminators) and decoded argument values.
   - PDA seeds as declared in the IDL vs as observed in the transaction.
3. `sat analyze src --tx-report report.json` ingests this report and cross-references the runtime account configuration against the AST-parsed `#[derive(Accounts)]` structures in the program's Rust source code — flagging cases where the code's declared constraints (signer, owner, seeds) diverge from what the transaction actually used.

---

## 3. UI/UX Design & Console Layout Mockup

```
╔════════════════════════════════════════════════════════════════════════════════╗
║              SOLANA TRANSACTION FORENSICS REPORT (v0)                          ║
╚════════════════════════════════════════════════════════════════════════════════╝
[+] Status: DECODED SUCCESSFULLY
[+] Simulation: WOULD SUCCEED (98,500 CU consumed / 150,000 limit)
[+] Fee Payer: 3u7Gg7L...nL79aX (Account #0)
[+] Compute Limit: 150,000 CU (Custom Limit Set)
[+] Priority Fee: 5,000 micro-lamports/CU

┌── Account Keys & Roles ────────────────────────────────────────────────────────┐
│ #0: 3u7Gg7L...nL79aX   [Signer + Writable]                                     │
│ #1: 7w3rT9q...9eKpLm   [Writable] (PDA: "vault" + user_pubkey)                 │
│ #2: TokenkegQfeZyiN...  [Read-only] (Token Program)                             │
└────────────────────────────────────────────────────────────────────────────────┘

┌── Address Lookup Table (ALT) Resolution ───────────────────────────────────────┐
│ Table: H649tS9...2kP (1 account resolved)                                      │
│   └── Mapped Account #3: 9xQkRx...y7h (Writable)                               │
└────────────────────────────────────────────────────────────────────────────────┘

┌── Instructions Breakdown ──────────────────────────────────────────────────────┐
│ [Instruction #0] Token Program: Transfer                                        │
│   ├── Program: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA                      │
│   ├── Mapped Accounts:                                                         │
│   │   ├── Source:      3u7Gg7L...nL79aX (Account #0)                           │
│   │   ├── Destination: 7w3rT9q...9eKpLm (Account #1)                           │
│   │   └── Authority:   7w3rT9q...9eKpLm (Account #1)  ← MISSING SIGNATURE      │
│   └── Mapped Data: { "amount": 50000000 }                                      │
└────────────────────────────────────────────────────────────────────────────────┘

┌── Structural Risk Flags ───────────────────────────────────────────────────────┐
│ 🔴 [CRITICAL] Instruction #0: Missing Signer                                   │
│    Account 'Authority' is declared as requiring a signature in the IDL,         │
│    but appears as a non-signer in the transaction message header.               │
│                                                                                │
│ 🔴 [CRITICAL] Instruction #0: PDA Seed Mismatch                                │
│    Account #1 expected PDA seeds ["vault", user_pubkey] per IDL.                │
│    Derived address does not match the account pubkey in the transaction.        │
│    Possible account substitution or seed manipulation.                          │
│                                                                                │
│ 🟡 [WARNING] Compute Budget: Reordering Detected                               │
│    ComputeBudget instruction at index #1 (expected at index #0).               │
│    Fee/limit manipulation may affect execution priority.                        │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Technical Architecture

### 4.1 Dependency Stack
- `solana-sdk = "1.18"` — Canonical transaction deserialization, ALT models, signature structures, `simulate_transaction`.
- `clap = { version = "4.4", features = ["derive", "env"] }`
- `tokio = { version = "1.35", features = ["full"] }`
- `serde = { version = "1.0", features = ["derive"] }`
- `serde_json = "1.0"`
- `bs58 = "0.5"`
- `base64 = "0.21"`
- `hex = "0.4"`
- `colored = "2.1"`
- `sha2 = "0.10"`

### 4.2 Modular Structure
```
src/
├── main.rs         # CLI entry point, argument parsing, orchestration
├── decoder.rs      # Transaction deserialization (solana-sdk primary path,
│                   #   light byte-level parser for --validate-decoding)
├── validator.rs    # IDL-aligned checks (PDA seeds, signer roles, CU, ALT,
│                   #   reordering, writable accounts, program ownership)
├── simulator.rs    # RPC transaction simulation wrapper
└── ui.rs           # ANSI terminal dashboard + JSON export formatter
```

### 4.3 Design Principle: The SDK Is Ground Truth

The Solana validator runtime determines whether a transaction is valid and how it executes. This tool does not attempt to second-guess the runtime at the byte level. The custom byte parser exists solely as a self-check (`--validate-decoding`) to surface internal tooling bugs — it is a correctness gate, not an attack-detection mechanism. All structural risk flags are derived from IDL-aligned analysis (does the tx match what the program said it expects?) and protocol-level invariants (CU limits, writable sysvars, ALT integrity) — not from parsing ambiguity.

---

## 5. Testing & CI/CD

### 5.1 Test Suite
- **Decoder Tests:** Transaction round-trip: decode 50+ mainnet and devnet transactions (legacy + v0) via `solana-sdk` and verify all fields are populated correctly.
- **Validator Unit Tests:** Each validation rule (PDA seed tiers, missing signer, writable sysvars, CU analysis, ALT checks, reordering) must have dedicated tests with both passing and failing fixture transactions.
- **Simulator Tests:** Mocked RPC responses for success, failure, CU exhaustion, and program error scenarios.
- **Regression Fixtures:** `tests/fixtures/` directory containing real transaction bytes in Base58, Base64, Hex, and raw binary — capturing edge cases discovered during development.

### 5.2 CI Pipeline
- `.github/workflows/test.yml`: `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` on every push and PR.
- `.github/workflows/security-audit.yml`: `cargo-audit` and `cargo-geiger` for supply chain security and `unsafe` block tracking.
