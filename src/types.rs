use serde::{Deserialize, Serialize};

pub const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const ASSOCIATED_TOKEN_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";
pub const ADDRESS_LOOKUP_TABLE_PROGRAM_ID: &str = "AddressLookupTab1e1111111111111111111111111";
pub const STAKE_PROGRAM_ID: &str = "Stake11111111111111111111111111111111111111";
pub const VOTE_PROGRAM_ID: &str = "Vote111111111111111111111111111111111111111";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReport {
    pub status: String,
    pub fee_payer: String,
    pub signatures: Vec<String>,
    pub recent_blockhash: String,
    pub message_version: Option<u8>,
    pub accounts: Vec<AccountInfo>,
    pub instructions: Vec<DecodedInstruction>,
    pub address_lookup_tables: Vec<AltResolution>,
    pub compute_budget: Option<ComputeBudgetInfo>,
    pub risk_flags: Vec<RiskFlag>,
    pub simulation: Option<SimulationResult>,
    pub warnings: Vec<String>,
    /// Per-signer offline cryptographic verification of the message
    /// signatures; populated whenever the transaction carries signatures.
    #[serde(default)]
    pub signature_verification: Vec<SignatureCheck>,
    /// Instructions invoked via CPI (`meta.innerInstructions`), present only
    /// when the transaction was fetched by signature with RPC meta. Account
    /// indices refer to the full message key list (static + ALT-loaded).
    #[serde(default)]
    pub inner_instructions: Vec<InnerInstruction>,
    /// SOL lamport deltas from meta pre/postBalances; only accounts whose
    /// balance changed are listed.
    #[serde(default)]
    pub balance_changes_sol: Vec<SolBalanceChange>,
    /// Token deltas from meta pre/postTokenBalances; only (account, mint)
    /// pairs whose balance changed are listed.
    #[serde(default)]
    pub token_balance_changes: Vec<TokenBalanceChange>,
    /// Decoded oracle price feeds referenced by the transaction, populated by
    /// the `--rpc` oracle pass. Offline runs leave this empty.
    #[serde(default)]
    pub oracle_feeds: Vec<OracleFeed>,
    /// Provenance of the IDL used for decoding: "file", "on-chain", or
    /// "bundled"; None when no schema was applied.
    #[serde(default)]
    pub idl_source: Option<String>,
    /// Runtime log lines from getTransaction meta and/or simulation.
    #[serde(default)]
    pub logs: Vec<String>,
    /// Decoded Anchor CPI events (`Program data:` lines matched against the
    /// IDL's event discriminators).
    #[serde(default)]
    pub events: Vec<EventRecord>,
    /// Bytecode analyses for IDL-less programs (sol-azy disassembly fallback).
    #[serde(default)]
    pub program_analyses: Vec<ProgramAnalysis>,
}

/// One decoded oracle price feed referenced by the transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OracleFeed {
    pub pubkey: String,
    pub program: String,
    pub price: i64,
    pub expo: i32,
    pub conf: u64,
    pub status: u32,
    /// Pyth v2 publish time; `None` for v1 feeds (no time field).
    pub publish_time: Option<i64>,
}

/// Remove duplicate risk flags in place, keyed by
/// `(category, instruction_index, message)`; first occurrence wins and the
/// original order is preserved.
pub fn dedup_risk_flags(flags: &mut Vec<RiskFlag>) {
    let mut i = 0;
    while i < flags.len() {
        let mut j = i + 1;
        while j < flags.len() {
            let same = flags[i].category == flags[j].category
                && flags[i].instruction_index == flags[j].instruction_index
                && flags[i].message == flags[j].message;
            if same {
                flags.remove(j);
            } else {
                j += 1;
            }
        }
        i += 1;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureCheck {
    pub index: u8,
    pub pubkey: String,
    pub verified: bool,
    pub note: String,
}

/// A CPI-invoked instruction decoded from `getTransaction` meta.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InnerInstruction {
    /// Position within the parent's inner instruction list.
    pub inner_index: u32,
    /// Index of the top-level instruction that invoked this CPI.
    pub parent_instruction_index: u8,
    pub program_id: String,
    pub program_name: String,
    pub instruction_name: Option<String>,
    pub accounts: Vec<MappedAccount>,
    pub data: serde_json::Value,
    pub raw_data_hex: String,
    #[serde(default)]
    pub token_amount: Option<TokenAmount>,
}

/// Raw `getTransaction` meta, parsed by the simulator and consumed by the
/// inner-instruction and balance annotators.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchedTxMeta {
    #[serde(default)]
    pub inner_instructions: Vec<TxMetaInnerInstructions>,
    #[serde(default)]
    pub loaded_addresses: Option<FetchedTxLoadedAddresses>,
    pub error: Option<serde_json::Value>,
    #[serde(default)]
    pub units_consumed: Option<u64>,
    #[serde(default)]
    pub logs: Vec<String>,
    #[serde(default)]
    pub pre_balances: Vec<u64>,
    #[serde(default)]
    pub post_balances: Vec<u64>,
    #[serde(default)]
    pub pre_token_balances: Vec<TokenBalanceDto>,
    #[serde(default)]
    pub post_token_balances: Vec<TokenBalanceDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenBalanceDto {
    pub account_index: u8,
    pub mint: String,
    pub ui_token_amount: UiTokenAmountDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiTokenAmountDto {
    /// Raw token units as a string (may exceed u64).
    pub amount: String,
    pub decimals: u8,
    pub ui_amount: Option<f64>,
    pub ui_amount_string: Option<String>,
}

/// SOL lamport balance change for one message account (meta pre/postBalances).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolBalanceChange {
    pub account_index: u8,
    pub pubkey: String,
    pub pre: u64,
    pub post: u64,
    pub delta: i64,
}

/// Token balance change for one (account, mint) pair (meta pre/postTokenBalances).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalanceChange {
    pub account_index: u8,
    pub pubkey: String,
    pub mint: String,
    pub pre: Option<TokenAmount>,
    pub post: Option<TokenAmount>,
    /// Signed raw-unit delta; token amounts may exceed u64 so this is i128.
    pub delta_raw: i128,
    /// Sign-aware human rendering of the delta (e.g. "-1.5").
    pub delta_human: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchedTxLoadedAddresses {
    pub writable: Vec<String>,
    pub readonly: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxMetaInnerInstructions {
    /// Index of the top-level instruction that invoked the CPIs.
    pub index: u8,
    #[serde(default)]
    pub instructions: Vec<TxMetaRawInnerInstruction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxMetaRawInnerInstruction {
    pub program_id_index: u8,
    #[serde(default)]
    pub accounts: Vec<u8>,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub index: u8,
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
    pub role: Option<String>,
    pub pda_info: Option<PdaInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdaInfo {
    pub seeds_declared: Vec<String>,
    pub bump: Option<u8>,
    pub expected_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedInstruction {
    pub index: u8,
    pub program_id: String,
    pub program_name: String,
    pub instruction_name: Option<String>,
    pub accounts: Vec<MappedAccount>,
    pub data: serde_json::Value,
    pub raw_data_hex: String,
    /// Human-readable token amount when resolvable (checked variants carry
    /// decimals inline; unchecked variants need an RPC mint/account lookup).
    #[serde(default)]
    pub token_amount: Option<TokenAmount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappedAccount {
    pub name: Option<String>,
    pub pubkey: String,
    pub account_index: u8,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AltResolution {
    pub table_address: String,
    pub resolved_accounts: Vec<ResolvedAccount>,
    /// Whether the table was fetched on-chain (requires --rpc). When false,
    /// `ResolvedAccount.pubkey` values are `<alt_index_N>` placeholders.
    #[serde(default)]
    pub resolved: bool,
}

/// A token amount annotated with its mint decimals and a precomputed
/// human-readable rendering (e.g. `"1.5"` for 1_500_000 raw with 6 decimals).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAmount {
    pub raw: u64,
    pub decimals: u8,
    pub human: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedAccount {
    pub index_in_tx: u8,
    pub pubkey: String,
    pub is_writable: bool,
    /// Index of this account within its address lookup table.
    #[serde(default)]
    pub table_index: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeBudgetInfo {
    pub compute_unit_limit: u32,
    pub compute_unit_price: u64,
    pub compute_unit_limit_set: bool,
    pub compute_budget_positions: Vec<usize>,
    pub is_reordered: bool,
    pub high_cu_instructions: Vec<u8>,
    /// Worst-case priority fee in lamports: price (micro-lamports/CU) ×
    /// limit (CU) / 1e6. The runtime charges price × consumed CU, so this is
    /// the maximum the fee payer commits to.
    #[serde(default)]
    pub priority_fee_lamports: u64,
    /// Actual priority fee in lamports (price × units consumed / 1e6) when a
    /// simulation result is available; None otherwise.
    #[serde(default)]
    pub priority_fee_actual: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub success: bool,
    pub error: Option<String>,
    pub logs: Vec<String>,
    pub units_consumed: u64,
    pub return_data: Option<String>,
    /// Structured error code, e.g. "Custom(42)" or "ProgramFailedToComplete".
    #[serde(default)]
    pub error_code: Option<String>,
    /// Index of the instruction that failed, when the error is an InstructionError.
    #[serde(default)]
    pub error_instruction_index: Option<u8>,
    /// Per-instruction compute unit attribution parsed from the simulation
    /// log stream; empty when logs did not carry consumption lines.
    #[serde(default)]
    pub instruction_cu: Vec<InstructionCu>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionCu {
    pub instruction_index: u8,
    pub program_id: String,
    pub units_consumed: u64,
    /// The compute unit limit in effect when the instruction completed.
    pub cu_limit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFlag {
    pub severity: RiskSeverity,
    pub category: RiskCategory,
    pub instruction_index: Option<u8>,
    pub message: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskSeverity {
    Critical,
    Warning,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RiskCategory {
    MissingSigner,
    PdaSeedMismatch,
    InsecureWritable,
    ComputeBudgetReordering,
    MissingComputeUnitLimit,
    HighComputeUnitUsage,
    AltIntegrity,
    ProgramOwnership,
    VerifiedBuild,
    InternalDecodeMismatch,
    PdaWellFormedness,
    IdlAccountMismatch,
    /// Transaction-layer pattern spanning multiple instructions/accounts
    /// (e.g. approve-then-transfer, mint authority takeover).
    PatternDetection,
    /// Disagreement between a simulation result and the local decode
    /// (error index, CU accounting, log-to-instruction correlation).
    SimulationMismatch,
    /// A message signature failed offline verification (tampered, missing,
    /// or mismatched signer); fee-payer failures are Critical.
    SignatureMismatch,
    /// A transaction account expected to be writable (per native program
    /// expectations) is not marked writable in the message header.
    WritableMismatch,
    /// A native instruction's compiled account list is longer than the
    /// expectations document declares; positional mapping may be misaligned.
    NativeAccountMismatch,
    /// A referenced oracle price feed has no verifiable freshness bound
    /// (Pyth v1, or a publish time outside the sanity window of the client
    /// clock). Transaction-layer configuration risk, not a vuln claim.
    StaleOraclePrice,
    /// A referenced oracle feed's confidence is more than 1% of its price.
    OracleConfidenceTooWide,
    /// One instruction references oracle feeds with different exponents —
    /// values at different decimal scales silently miscompare/miscombine.
    OracleDecimalsMismatch,
    /// The transaction's recent blockhash is expired or close to expiring
    /// relative to the RPC-reported block height.
    BlockhashExpired,
}

/// Per-rule pattern configuration. Severity strings are parsed by the
/// patterns module ("info" | "warning" | "critical"); unknown keys or
/// severities are hard errors.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatternConfig {
    #[serde(default)]
    pub rules: std::collections::BTreeMap<String, PatternRuleOverride>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatternRuleOverride {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Encoding {
    Base58,
    Base64,
    Hex,
    Raw,
}

// ── Anchor IDL types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlJson {
    pub version: String,
    pub name: String,
    #[serde(default)]
    pub instructions: Vec<IdlInstruction>,
    #[serde(default)]
    pub accounts: Vec<IdlAccountDef>,
    #[serde(default)]
    pub types: Vec<IdlTypeDef>,
    #[serde(default)]
    pub events: Vec<IdlEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlEvent {
    pub name: String,
    #[serde(default)]
    pub fields: Vec<IdlEventField>,
    #[serde(default)]
    pub discriminator: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlEventField {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: serde_json::Value,
    #[serde(default)]
    pub index: bool,
}

/// One decoded `Program data:` CPI event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub name: String,
    pub program_id: String,
    pub fields: serde_json::Value,
}

/// Bytecode-level analysis of one program (sol-azy disassembly fallback for
/// IDL-less / closed-source programs). Enrichment only — never risk flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramAnalysis {
    pub program_id: String,
    /// "upgradeable" | "deprecated" | "unknown"
    pub loader: String,
    pub elf_size: usize,
    pub elf_sha256: String,
    #[serde(default)]
    pub upgrade_authority: Option<String>,
    #[serde(default)]
    pub syscalls: Vec<String>,
    #[serde(default)]
    pub strings: Vec<String>,
    /// 8-byte `lddw` immediates that match an unknown instruction's data
    /// prefix, rendered as hex (candidate dispatch discriminators).
    #[serde(default)]
    pub dispatch_candidates: Vec<String>,
    /// Instruction indexes renamed via a candidate match.
    #[serde(default)]
    pub matched_instructions: Vec<u8>,
    /// Directory with the raw disassembly artifacts when persisted.
    #[serde(default)]
    pub artifact_dir: Option<String>,
}

impl IdlJson {
    pub fn find_instruction(&self, ix_name: &str) -> Option<&IdlInstruction> {
        self.instructions.iter().find(|ix| ix.name == ix_name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlInstruction {
    pub name: String,
    #[serde(default)]
    pub accounts: Vec<IdlAccountItem>,
    #[serde(default)]
    pub args: Vec<IdlArg>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlAccountItem {
    pub name: String,
    #[serde(rename = "isMut")]
    pub is_mut: bool,
    #[serde(rename = "isSigner")]
    pub is_signer: bool,
    #[serde(default)]
    pub pda: Option<IdlPda>,
    #[serde(default)]
    pub desc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlPda {
    #[serde(default)]
    pub seeds: Vec<IdlSeed>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlSeed {
    pub kind: String,
    #[serde(default)]
    pub value: Option<Vec<u8>>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub account: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlArg {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlAccountDef {
    pub name: String,
    #[serde(default)]
    #[serde(rename = "type")]
    pub ty: Option<IdlAccountType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlAccountType {
    pub kind: String,
    #[serde(default)]
    pub fields: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlTypeDef {
    pub name: String,
    #[serde(default)]
    pub ty: Option<IdlTypeKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlTypeKind {
    pub kind: String,
    #[serde(default)]
    pub variants: Vec<serde_json::Value>,
}

// ── Solana system sysvars (known read-only program addresses) ─────────────────

pub const KNOWN_SYSVAR_IDS: &[&str] = &[
    "SysvarRent111111111111111111111111111111111",
    "SysvarC1ock11111111111111111111111111111111",
    "SysvarEpochSchedu1e111111111111111111111111",
    "SysvarFees111111111111111111111111111111111",
    "SysvarRecentB1ockHashes11111111111111111111",
    "SysvarStakeHistory1111111111111111111111111",
    "SysvarInstruction1111111111111111111111111",
    "SysvarS1otHashes111111111111111111111111111",
    "SysvarS1otHistory11111111111111111111111111",
];

pub const KNOWN_PROGRAM_IDS: &[&str] = &[
    SYSTEM_PROGRAM_ID,
    TOKEN_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID,
    ASSOCIATED_TOKEN_PROGRAM_ID,
    COMPUTE_BUDGET_PROGRAM_ID,
    ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
];

#[allow(dead_code)]
pub fn is_sysvar_id(pubkey: &str) -> bool {
    KNOWN_SYSVAR_IDS.contains(&pubkey)
}

#[allow(dead_code)]
pub fn is_known_program_id(pubkey: &str) -> bool {
    KNOWN_PROGRAM_IDS.contains(&pubkey)
}

// ── Native program expectations (sat --expectations export) ───────────────────

/// Mirror of `sat`'s native expectations document (`ExpectationsDoc` in
/// solana-audit-toolkit/crates/sat/src/native/expectations.rs). This is the
/// native analog of an Anchor IDL: `rts` consumes it to run tier-1/tier-2
/// checks (signer presence, writable roles, PDA seed cross-reference)
/// against real transactions of programs that ship no IDL.
///
/// Contract notes (from sat's exporter):
/// - `source` is always `"native"`; `instructions[].accounts[]` maps 1:1 to
///   the instruction's account order (positional `AccountMeta` order).
/// - `pda.seeds` contains only seeds that are *statically* verifiable (string
///   or integer literals); `pda.dynamic_seed_count` counts seed expressions
///   that depend on runtime values and can only be verified on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectationsDoc {
    pub program_name: String,
    pub program_id: Option<String>,
    pub source: String,
    #[serde(default)]
    pub instructions: Vec<ExpectationInstruction>,
}

impl ExpectationsDoc {
    pub fn find_instruction(&self, ix_name: &str) -> Option<&ExpectationInstruction> {
        self.instructions.iter().find(|ix| ix.name == ix_name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectationInstruction {
    pub name: String,
    /// 8-byte hex for byte-match dispatch; 1-byte hex for u8-tag fallback
    /// (e.g. Mango's `MangoInstruction::unpack(data[0])`).
    pub discriminator_hex: Option<String>,
    pub handler: String,
    pub accounts: Vec<ExpectationAccount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectationAccount {
    pub name: String,
    /// 1:1 with the instruction's AccountMeta order.
    pub index: usize,
    pub is_signer_expected: bool,
    pub is_writable_expected: bool,
    pub pda: Option<ExpectationPda>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectationPda {
    /// Statically verifiable seeds (string/integer literals).
    pub seeds: Vec<String>,
    /// Seed expressions that depend on runtime values.
    #[serde(default)]
    pub dynamic_seed_count: usize,
}

/// A validated schema for a program's instruction set: either an Anchor IDL
/// or sat's native expectations export. Mutually exclusive in the CLI
/// (`--idl` vs `--expectations`); the decoder and validator branch on this.
#[derive(Debug, Clone)]
pub enum ProgramSchema {
    Idl(IdlJson),
    Native(ExpectationsDoc),
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANGO_STYLE_EXPECTATIONS: &str = r#"{
      "program_name": "program",
      "program_id": "AvtB6w9xboLwA145E221vhof5TddhqsChYcx7Fy3xVMH",
      "source": "native",
      "instructions": [
        {
          "name": "WithdrawMsrm",
          "discriminator_hex": "24",
          "handler": "withdraw_msrm",
          "accounts": [
            {"name": "owner_ai", "index": 2, "is_signer_expected": true, "is_writable_expected": false, "pda": null},
            {"name": "mango_account_ai", "index": 1, "is_signer_expected": false, "is_writable_expected": true, "pda": null}
          ]
        },
        {
          "name": "withdraw_escrow",
          "discriminator_hex": "25",
          "handler": "withdraw_escrow",
          "accounts": [
            {"name": "escrow", "index": 0, "is_signer_expected": false, "is_writable_expected": true,
             "pda": {"seeds": ["escrow"], "dynamic_seed_count": 1}}
          ]
        }
      ]
    }"#;

    #[test]
    fn parses_native_expectations_doc() {
        let doc: ExpectationsDoc = serde_json::from_str(MANGO_STYLE_EXPECTATIONS).expect("parse expectations");
        assert_eq!(doc.source, "native");
        assert_eq!(doc.program_id.as_deref(), Some("AvtB6w9xboLwA145E221vhof5TddhqsChYcx7Fy3xVMH"));
        assert_eq!(doc.instructions.len(), 2);

        let msrm = doc.find_instruction("WithdrawMsrm").expect("find WithdrawMsrm");
        assert_eq!(msrm.discriminator_hex.as_deref(), Some("24"));
        assert_eq!(msrm.handler, "withdraw_msrm");
        let owner = &msrm.accounts[0];
        assert_eq!(owner.name, "owner_ai");
        assert_eq!(owner.index, 2);
        assert!(owner.is_signer_expected);
        assert!(!owner.is_writable_expected);
        assert!(owner.pda.is_none());
        assert!(!msrm.accounts[1].is_signer_expected);
        assert!(msrm.accounts[1].is_writable_expected);

        let escrow = doc.find_instruction("withdraw_escrow").expect("find withdraw_escrow");
        let pda = escrow.accounts[0].pda.as_ref().expect("escrow pda");
        assert_eq!(pda.seeds, vec!["escrow".to_string()]);
        assert_eq!(pda.dynamic_seed_count, 1);
        assert!(doc.find_instruction("nope").is_none());
    }

    #[test]
    fn dedup_removes_duplicate_keyed_flags() {
        let mut flags =
            vec![flag(RiskCategory::MissingSigner, Some(0), "m"), flag(RiskCategory::MissingSigner, Some(0), "m")];
        dedup_risk_flags(&mut flags);
        assert_eq!(flags.len(), 1);
    }

    #[test]
    fn dedup_keeps_same_category_and_index_different_message() {
        let mut flags =
            vec![flag(RiskCategory::MissingSigner, Some(0), "a"), flag(RiskCategory::MissingSigner, Some(0), "b")];
        dedup_risk_flags(&mut flags);
        assert_eq!(flags.len(), 2);
    }

    #[test]
    fn dedup_keeps_different_category_same_message() {
        let mut flags =
            vec![flag(RiskCategory::MissingSigner, None, "m"), flag(RiskCategory::InsecureWritable, None, "m")];
        dedup_risk_flags(&mut flags);
        assert_eq!(flags.len(), 2);
    }

    #[test]
    fn dedup_preserves_first_occurrence_order() {
        let mut flags = vec![
            flag(RiskCategory::InsecureWritable, None, "first"),
            flag(RiskCategory::MissingSigner, None, "mid"),
            flag(RiskCategory::InsecureWritable, None, "first"),
        ];
        dedup_risk_flags(&mut flags);
        assert_eq!(flags.len(), 2);
        assert_eq!(flags[0].message, "first");
        assert_eq!(flags[1].message, "mid");
    }

    #[test]
    fn dedup_empty_vec_unchanged() {
        let mut flags: Vec<RiskFlag> = Vec::new();
        dedup_risk_flags(&mut flags);
        assert!(flags.is_empty());
    }

    fn flag(category: RiskCategory, index: Option<u8>, message: &str) -> RiskFlag {
        RiskFlag {
            severity: RiskSeverity::Warning,
            category,
            instruction_index: index,
            message: message.to_string(),
            details: String::new(),
        }
    }
}
