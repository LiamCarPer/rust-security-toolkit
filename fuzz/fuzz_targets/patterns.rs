#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_security_toolkit::patterns::detect_patterns_with_config;
use rust_security_toolkit::types::{PatternConfig, TransactionReport};

fuzz_target!(|data: &[u8]| {
    let Ok(report) = serde_json::from_slice::<TransactionReport>(data) else {
        return;
    };
    let config = serde_json::from_slice::<PatternConfig>(data).unwrap_or_default();
    let _ = detect_patterns_with_config(&report, &config);
});
