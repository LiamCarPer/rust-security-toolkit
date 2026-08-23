//! Oracle price-feed decoding and validation.
//!
//! Decodes Pyth price-account layouts (v1 and v2) from on-chain account data
//! fetched over the optional `--rpc` path, then emits transaction-layer risk
//! flags: stale prices (unbounded age), wide confidence, and cross-feed
//! exponent (decimals) mismatches inside a single instruction.
//!
//! Honest scope (PRD-aligned): these are *transaction-layer configuration
//! risks*, not vulnerability claims — "this tx referenced a feed that is X
//! seconds old with Y-wide confidence" is verifiable fact; whether the program
//! depends on that price is program knowledge this tool does not model.
//!
//! Layout notes:
//! - Pyth v2 price account: magic `0xa1b2c3d4` @0, version u32 @4, type u32
//!   @8, size u32 @12, price_type u32 @16, expo i32 @20,
//!   num_component_prices u32 @24, padding @28..60, price i64 @60, conf u64
//!   @68, status u32 @76, corporate_action u32 @80, publish_slot u64 @84,
//!   publish_time i64 @92.
//! - Pyth v1 price account: magic/version/type/size @0..16, decimals u32 @16,
//!   price i64 @20, conf u64 @28, status u32 @36, corporate_action u32 @40,
//!   publish_slot u64 @44.
//! - Switchboard v2 `AggregatorAccountData` is a documented follow-up: its
//!   nested `latest_confirmed_round` offsets could not be verified in this
//!   round, so it is NOT decoded rather than decoded at guessed offsets.

use std::collections::HashMap;

use crate::simulator;
use crate::types::{RiskCategory, RiskFlag, RiskSeverity, TransactionReport};

/// Pyth price-account magic.
const PYTH_MAGIC: u32 = 0xa1b2_c3d4;

/// Pyth program owners (price accounts are program-owned).
const PYTH_PROGRAM_IDS: &[&str] = &[
    "FsJ3A3u2uj5F1XkmMZ5pW8rcKjmr2M9nZ3cXaFvTvM4A",
    "pythWSnswVUd12oZpeFP8e9CVaEqJgTgSjRTOqmjBu",
];

/// Staleness window: a publish time farther than this from the client clock
/// (either direction) is definitely unusable. Finer bounds need block time,
/// which this round does not fetch.
const STALE_SKEW_SECS: i64 = 2 * 3600;

/// Confidence-to-price ratio above this (1%) is flagged.
const MAX_CONF_RATIO: u64 = 100;

/// A decoded Pyth price.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PythPrice {
    pub price: i64,
    pub expo: i32,
    pub conf: u64,
    pub status: u32,
    pub publish_time: i64,
}

/// Whether the bytes look like a Pyth price account (magic match).
pub fn is_pyth_price_data(data: &[u8]) -> bool {
    data.len() >= 100 && u32::from_le_bytes(data[0..4].try_into().unwrap()) == PYTH_MAGIC
}

/// Decode a Pyth v2 price account.
pub fn decode_pyth_v2(data: &[u8]) -> Option<PythPrice> {
    if data.len() < 100 || u32::from_le_bytes(data[0..4].try_into().unwrap()) != PYTH_MAGIC {
        return None;
    }
    Some(PythPrice {
        price: i64::from_le_bytes(data[60..68].try_into().ok()?),
        conf: u64::from_le_bytes(data[68..76].try_into().ok()?),
        status: u32::from_le_bytes(data[76..80].try_into().ok()?),
        publish_time: i64::from_le_bytes(data[92..100].try_into().ok()?),
        expo: i32::from_le_bytes(data[20..24].try_into().ok()?),
    })
}

/// Decode a Pyth v1 price account (decimals @16, price @20, conf @28,
/// status @36, corporate_action @40, publish_slot @44 — no publish_time).
pub fn decode_pyth_v1(data: &[u8]) -> Option<PythPrice> {
    if data.len() < 52 || u32::from_le_bytes(data[0..4].try_into().unwrap()) != PYTH_MAGIC {
        return None;
    }
    Some(PythPrice {
        price: i64::from_le_bytes(data[20..28].try_into().ok()?),
        conf: u64::from_le_bytes(data[28..36].try_into().ok()?),
        status: u32::from_le_bytes(data[36..40].try_into().ok()?),
        publish_time: 0, // v1 carries no publish time; staleness is unbounded
        expo: i32::from_le_bytes(data[16..20].try_into().ok()?),
    })
}

/// One decoded feed referenced by the transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFeed {
    pub pubkey: String,
    /// Pyth v2 vs v1 (affects whether a publish time exists).
    pub v2: bool,
    pub price: PythPrice,
}

/// Whether the account is likely a Pyth price account by owner.
pub fn is_pyth_owner(owner: &str) -> bool {
    PYTH_PROGRAM_IDS.iter().any(|id| id.eq_ignore_ascii_case(owner))
}

/// Fetches and decodes every Pyth price account referenced by the report.
/// Silent on fetch failures (house style — the account just stays undecoded).
pub async fn fetch_pyth_feeds(rpc_url: &str, report: &TransactionReport) -> Vec<DecodedFeed> {
    let client = reqwest::Client::new();
    let mut out = Vec::new();
    let mut data_cache: HashMap<String, Option<Vec<u8>>> = HashMap::new();
    let mut owner_cache: HashMap<String, Option<String>> = HashMap::new();

    for account in &report.accounts {
        if account.pubkey.contains('<') {
            continue; // ALT placeholder, not yet resolved
        }
        let owner = match owner_cache.get(&account.pubkey) {
            Some(o) => o.clone(),
            None => {
                let fetched = simulator::fetch_account_owner(&client, rpc_url, &account.pubkey).await.unwrap_or(None);
                owner_cache.insert(account.pubkey.clone(), fetched.clone());
                fetched
            }
        };
        if owner.as_deref().is_some_and(is_pyth_owner) || owner.is_none() {
            // Fetch the payload either way: magic-match is the authoritative
            // structural signal; owner matching just narrows the set.
            let data = match data_cache.get(&account.pubkey) {
                Some(d) => d.clone(),
                None => {
                    let fetched = simulator::fetch_account_data(&client, rpc_url, &account.pubkey).await.unwrap_or(None);
                    data_cache.insert(account.pubkey.clone(), fetched.clone());
                    fetched
                }
            };
            if let Some(data) = data {
                if let Some(price) = decode_pyth_v2(&data) {
                    out.push(DecodedFeed { pubkey: account.pubkey.clone(), v2: true, price });
                } else if let Some(price) = decode_pyth_v1(&data) {
                    out.push(DecodedFeed { pubkey: account.pubkey.clone(), v2: false, price });
                }
            }
        }
    }
    out
}

/// Flags for the decoded feeds:
/// - `StaleOraclePrice` (Warning): a v2 feed's publish time is outside the
///   sanity window of the client clock, or a v1 feed (no time field at all).
/// - `OracleConfidenceTooWide` (Warning): conf/|price| above 1%.
/// - `OracleDecimalsMismatch` (Critical): the same instruction references
///   two feeds with different exponents — the classic decimals-mismatch
///   shape (values compared/combined at different scales).
pub fn check_feeds(report: &TransactionReport, feeds: &[DecodedFeed]) -> Vec<RiskFlag> {
    let mut flags = Vec::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    for feed in feeds {
        if feed.price.conf > 0
            && feed.price.price != 0
            && feed.price.conf > feed.price.price.unsigned_abs() / MAX_CONF_RATIO
        {
            flags.push(RiskFlag {
                severity: RiskSeverity::Warning,
                category: RiskCategory::OracleConfidenceTooWide,
                instruction_index: instruction_of_pubkey(report, &feed.pubkey),
                message: format!("Oracle feed {} has very wide confidence", feed.pubkey),
                details: format!(
                    "confidence {} vs |price| {} (ratio > 1%)",
                    feed.price.conf,
                    feed.price.price.unsigned_abs()
                ),
            });
        }

        if !feed.v2 {
            flags.push(RiskFlag {
                severity: RiskSeverity::Warning,
                category: RiskCategory::StaleOraclePrice,
                instruction_index: instruction_of_pubkey(report, &feed.pubkey),
                message: format!("Oracle feed {} is a Pyth v1 price (no publish time)", feed.pubkey),
                details: "v1 feeds carry no publish_time; the transaction cannot bound the price's age".to_string(),
            });
        } else if feed.price.publish_time > 0 && (now - feed.price.publish_time).abs() > STALE_SKEW_SECS {
            flags.push(RiskFlag {
                severity: RiskSeverity::Warning,
                category: RiskCategory::StaleOraclePrice,
                instruction_index: instruction_of_pubkey(report, &feed.pubkey),
                message: format!("Oracle feed {} may be stale", feed.pubkey),
                details: format!(
                    "publish_time {} vs client clock {} (skew window {}s)",
                    feed.price.publish_time, now, STALE_SKEW_SECS
                ),
            });
        }
    }

    // Cross-feed exponent mismatch within one instruction.
    let mut by_instruction: HashMap<Option<u8>, Vec<&DecodedFeed>> = HashMap::new();
    for feed in feeds {
        let idx = instruction_of_pubkey(report, &feed.pubkey);
        by_instruction.entry(idx).or_default().push(feed);
    }
    for (instruction_index, grouped) in by_instruction {
        let mut exponents = std::collections::BTreeSet::new();
        for feed in &grouped {
            exponents.insert(feed.price.expo);
        }
        if exponents.len() >= 2 {
            let expo_list: Vec<String> = grouped.iter().map(|f| format!("{}:{}", f.pubkey, f.price.expo)).collect();
            flags.push(RiskFlag {
                severity: RiskSeverity::Critical,
                category: RiskCategory::OracleDecimalsMismatch,
                instruction_index,
                message: "Instruction combines oracle feeds with different exponents".to_string(),
                details: format!(
                    "{} — prices are at different decimal scales and would silently miscompare/miscombine",
                    expo_list.join(", ")
                ),
            });
        }
    }

    flags
}

/// The instruction index that references a pubkey (first match).
fn instruction_of_pubkey(report: &TransactionReport, pubkey: &str) -> Option<u8> {
    report
        .instructions
        .iter()
        .enumerate()
        .find(|(_, ix)| ix.accounts.iter().any(|a| a.pubkey == pubkey))
        .map(|(i, _)| i as u8)
}

/// Full oracle pass: fetch + decode + flag. Returns risk flags; failures are
/// silent (a feed we cannot fetch simply produces no flags). Decoded feeds
/// are stored on the report for downstream consumers (`--output-tx-report`,
/// the sat bridge).
pub async fn check_report(rpc_url: &str, report: &mut TransactionReport) -> Vec<RiskFlag> {
    let feeds = fetch_pyth_feeds(rpc_url, report).await;
    let flags = check_feeds(report, &feeds);
    report.oracle_feeds = feeds
        .into_iter()
        .map(|f| crate::types::OracleFeed {
            pubkey: f.pubkey,
            program: "pyth".to_string(),
            price: f.price.price,
            expo: f.price.expo,
            conf: f.price.conf,
            status: f.price.status,
            publish_time: (f.v2).then_some(f.price.publish_time),
        })
        .collect();
    flags
}

/// Synthetic buffers for tests (public so the integration test crate can
/// build fixtures without duplicating layout constants).
pub fn test_pyth_v2_buffer(price: i64, expo: i32, conf: u64, status: u32, publish_time: i64) -> Vec<u8> {
    let mut data = vec![0u8; 100];
    data[0..4].copy_from_slice(&PYTH_MAGIC.to_le_bytes());
    data[4..8].copy_from_slice(&2u32.to_le_bytes());
    data[20..24].copy_from_slice(&expo.to_le_bytes());
    data[60..68].copy_from_slice(&price.to_le_bytes());
    data[68..76].copy_from_slice(&conf.to_le_bytes());
    data[76..80].copy_from_slice(&status.to_le_bytes());
    data[92..100].copy_from_slice(&publish_time.to_le_bytes());
    data
}

/// Test-only: decode a synthetic Pyth v1 buffer.
pub fn test_pyth_v1_buffer(price: i64, decimals: i32, conf: u64, status: u32) -> Vec<u8> {
    let mut data = vec![0u8; 52];
    data[0..4].copy_from_slice(&PYTH_MAGIC.to_le_bytes());
    data[4..8].copy_from_slice(&1u32.to_le_bytes());
    data[16..20].copy_from_slice(&decimals.to_le_bytes());
    data[20..28].copy_from_slice(&price.to_le_bytes());
    data[28..36].copy_from_slice(&conf.to_le_bytes());
    data[36..40].copy_from_slice(&status.to_le_bytes());
    data
}

/// The `--rpc` oracle pass entry point (kept Result-shaped for the caller).
pub async fn run(rpc_url: &str, report: &mut TransactionReport) -> anyhow::Result<Vec<RiskFlag>> {
    Ok(check_report(rpc_url, report).await)
}
