//! Oracle price-feed tests: layout decoding (Pyth v1/v2), risk-flag logic,
//! and the mocked-RPC fetch path.

use rust_security_toolkit::oracle;
use rust_security_toolkit::oracle::{
    check_feeds, decode_pyth_v1, decode_pyth_v2, test_pyth_v1_buffer, test_pyth_v2_buffer,
};
use rust_security_toolkit::types::{
    AccountInfo, DecodedInstruction, MappedAccount, RiskCategory, RiskSeverity, TransactionReport,
};

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

// ── Parser units ─────────────────────────────────────────────────────────────

#[test]
fn pyth_v2_buffer_decodes_all_fields() {
    let data = test_pyth_v2_buffer(123_450_000, -6, 250, 1, 1_700_000_000);
    let price = decode_pyth_v2(&data).expect("v2 buffer must decode");
    assert_eq!(price.price, 123_450_000);
    assert_eq!(price.expo, -6);
    assert_eq!(price.conf, 250);
    assert_eq!(price.status, 1);
    assert_eq!(price.publish_time, 1_700_000_000);
}

#[test]
fn pyth_v1_buffer_decodes_fields() {
    let data = test_pyth_v1_buffer(99, 6, 1, 1);
    let price = decode_pyth_v1(&data).expect("v1 buffer must decode");
    assert_eq!(price.price, 99);
    assert_eq!(price.expo, 6);
    assert_eq!(price.conf, 1);
    assert_eq!(price.status, 1);
    // v1 has no publish time — staleness is unbounded.
    assert_eq!(price.publish_time, 0);
}

#[test]
fn truncated_and_foreign_buffers_do_not_decode() {
    let data = test_pyth_v2_buffer(1, -6, 1, 1, 1);
    assert!(decode_pyth_v2(&data[..60]).is_none(), "truncated v2 must not decode");
    let mut foreign = test_pyth_v2_buffer(1, -6, 1, 1, 1);
    foreign[0] = 0xAA;
    assert!(decode_pyth_v2(&foreign).is_none(), "wrong magic must not decode");
    assert!(decode_pyth_v1(&foreign).is_none());
    assert!(!oracle::is_pyth_price_data(&foreign));
}

// ── Flag logic ───────────────────────────────────────────────────────────────

fn report_with_feeds(instructions: Vec<DecodedInstruction>) -> TransactionReport {
    let mut accounts = Vec::new();
    for ix in &instructions {
        for a in &ix.accounts {
            accounts.push(AccountInfo {
                index: a.account_index,
                pubkey: a.pubkey.clone(),
                is_signer: false,
                is_writable: false,
                role: None,
                pda_info: None,
            });
        }
    }
    TransactionReport {
        status: "ok".to_string(),
        fee_payer: String::new(),
        signatures: vec![],
        recent_blockhash: String::new(),
        message_version: None,
        accounts,
        instructions,
        address_lookup_tables: vec![],
        compute_budget: None,
        risk_flags: vec![],
        simulation: None,
        warnings: vec![],
        signature_verification: vec![],
        inner_instructions: vec![],
        balance_changes_sol: vec![],
        token_balance_changes: vec![],
        oracle_feeds: vec![],
        idl_source: None,
        logs: vec![],
        events: vec![],
    }
}

fn feed(pubkey: &str, v2: bool, price: i64, expo: i32, conf: u64, publish_time: i64) -> oracle::DecodedFeed {
    oracle::DecodedFeed {
        pubkey: pubkey.to_string(),
        v2,
        price: oracle::PythPrice { price, expo, conf, status: 1, publish_time },
    }
}

#[test]
fn wide_confidence_is_flagged() {
    let ix = DecodedInstruction {
        index: 0,
        program_id: "FsJ3A3u2uj5F1XkmMZ5pW8rcKjmr2M9nZ3cXaFvTvM4A".to_string(),
        program_name: "oracle".to_string(),
        instruction_name: Some("read".to_string()),
        data: serde_json::json!({}),
        raw_data_hex: String::new(),
        accounts: vec![MappedAccount {
            name: Some("price_feed".into()),
            pubkey: "AAA".into(),
            account_index: 0,
            is_signer: false,
            is_writable: false,
        }],
        token_amount: None,
    };
    let report = report_with_feeds(vec![ix]);
    let feeds = vec![feed("AAA", true, 1_000_000, -6, 25_000, 0)]; // conf 2.5%
    let flags = check_feeds(&report, &feeds);
    assert!(
        flags
            .iter()
            .any(|f| f.category == RiskCategory::OracleConfidenceTooWide && f.severity == RiskSeverity::Warning),
        "{flags:#?}"
    );
    assert!(!flags.iter().any(|f| f.category == RiskCategory::OracleDecimalsMismatch), "{flags:#?}");
}

#[test]
fn cross_feed_exponent_mismatch_is_critical() {
    let ix = DecodedInstruction {
        index: 0,
        program_id: "FsJ3A3u2uj5F1XkmMZ5pW8rcKjmr2M9nZ3cXaFvTvM4A".to_string(),
        program_name: "oracle".to_string(),
        instruction_name: Some("read_two".to_string()),
        data: serde_json::json!({}),
        raw_data_hex: String::new(),
        accounts: vec![
            MappedAccount {
                name: Some("price_a".into()),
                pubkey: "AAA".into(),
                account_index: 0,
                is_signer: false,
                is_writable: false,
            },
            MappedAccount {
                name: Some("price_b".into()),
                pubkey: "BBB".into(),
                account_index: 1,
                is_signer: false,
                is_writable: false,
            },
        ],
        token_amount: None,
    };
    let report = report_with_feeds(vec![ix]);
    let feeds = vec![feed("AAA", true, 100, -6, 1, 0), feed("BBB", true, 90, -9, 1, 0)];
    let flags = check_feeds(&report, &feeds);
    assert!(
        flags.iter().any(|f| {
            f.category == RiskCategory::OracleDecimalsMismatch
                && f.severity == RiskSeverity::Critical
                && f.instruction_index == Some(0)
        }),
        "{flags:#?}"
    );
}

#[test]
fn stale_and_v1_feeds_are_flagged() {
    let report = report_with_feeds(vec![]);
    let now = now();
    let feeds = vec![
        feed("AAA", true, 100, -6, 1, now - 3 * 3600), // 3h old
        feed("BBB", false, 100, -6, 1, 0),             // v1: no time field
    ];
    let flags = check_feeds(&report, &feeds);
    let stale: Vec<_> = flags.iter().filter(|f| f.category == RiskCategory::StaleOraclePrice).collect();
    assert_eq!(stale.len(), 2, "{flags:#?}");
    assert!(stale.iter().all(|f| f.severity == RiskSeverity::Warning));
}

#[test]
fn healthy_feeds_produce_no_flags() {
    let report = report_with_feeds(vec![]);
    let feeds = vec![feed("AAA", true, 1_000_000, -6, 100, now())];
    let flags = check_feeds(&report, &feeds);
    assert!(flags.is_empty(), "{flags:#?}");
}

// ── Mocked RPC fetch path ────────────────────────────────────────────────────

#[tokio::test]
async fn fetch_pyth_feeds_decodes_via_mocked_rpc() {
    use httpmock::Method::POST;
    use httpmock::prelude::*;

    let server = MockServer::start();
    let feed_data = test_pyth_v2_buffer(
        42_000_000,
        -6,
        1_000_000, // ≈2.4% of price — wide confidence, should flag
        1,
        now(),
    );
    let feed_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&feed_data)
    };

    // getAccountInfo returns base64 data + the Pyth owner; both the owner and
    // the data fetch hit the same mock.
    server.mock(|when, then| {
        when.method(POST).path("/");
        then.status(200).json_body(serde_json::json!({
            "jsonrpc": "2.0",
            "result": { "context": { "slot": 1 }, "value": {
                "owner": "FsJ3A3u2uj5F1XkmMZ5pW8rcKjmr2M9nZ3cXaFvTvM4A",
                "executable": false,
                "lamports": 1,
                "rentEpoch": 0,
                "data": [feed_b64, "base64"]
            } },
            "id": 1
        }));
    });

    let mut report = report_with_feeds(vec![]);
    report.accounts.push(AccountInfo {
        index: 0,
        pubkey: "FEED1111111111111111111111111111111111111111".to_string(),
        is_signer: false,
        is_writable: false,
        role: Some("price_feed".to_string()),
        pda_info: None,
    });

    let flags = oracle::check_report(&server.url(""), &mut report).await;
    // The decoded feed is the functional proof both RPC calls succeeded.
    assert_eq!(report.oracle_feeds.len(), 1, "feed must be decoded into the report");
    assert_eq!(report.oracle_feeds[0].price, 42_000_000);
    assert_eq!(report.oracle_feeds[0].expo, -6);
    assert!(flags.iter().any(|f| f.category == RiskCategory::OracleConfidenceTooWide), "{flags:#?}");
}
