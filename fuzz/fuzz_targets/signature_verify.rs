#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_security_toolkit::signature_verify::{verify_report, verify_transaction};
use rust_security_toolkit::types::TransactionReport;
use solana_sdk::transaction::VersionedTransaction;

fuzz_target!(|data: &[u8]| {
    let Ok(tx) = bincode::deserialize::<VersionedTransaction>(data) else {
        return;
    };
    let checks = verify_transaction(&tx);
    let mut report = TransactionReport {
        status: String::new(),
        fee_payer: String::new(),
        signatures: Vec::new(),
        recent_blockhash: String::new(),
        message_version: None,
        accounts: Vec::new(),
        instructions: Vec::new(),
        address_lookup_tables: Vec::new(),
        compute_budget: None,
        risk_flags: Vec::new(),
        simulation: None,
        warnings: Vec::new(),
        signature_verification: checks,
        inner_instructions: Vec::new(),
        balance_changes_sol: Vec::new(),
        token_balance_changes: Vec::new(),
        oracle_feeds: Vec::new(),
        idl_source: None,
        logs: Vec::new(),
        events: Vec::new(),
    };
    let _ = verify_report(&mut report);
});
