use serde::{Deserialize, Serialize};

pub const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const ASSOCIATED_TOKEN_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";
pub const ADDRESS_LOOKUP_TABLE_PROGRAM_ID: &str = "AddressLookupTab1e1111111111111111111111111";

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedAccount {
    pub index_in_tx: u8,
    pub pubkey: String,
    pub is_writable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeBudgetInfo {
    pub compute_unit_limit: u32,
    pub compute_unit_price: u64,
    pub compute_unit_limit_set: bool,
    pub compute_budget_positions: Vec<usize>,
    pub is_reordered: bool,
    pub high_cu_instructions: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub success: bool,
    pub error: Option<String>,
    pub logs: Vec<String>,
    pub units_consumed: u64,
    pub return_data: Option<String>,
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
