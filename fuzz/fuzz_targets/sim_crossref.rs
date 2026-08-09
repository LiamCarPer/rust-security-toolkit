#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_security_toolkit::sim_crossref::cross_reference;
use rust_security_toolkit::types::TransactionReport;

fuzz_target!(|data: &[u8]| {
    let Ok(mut report) = serde_json::from_slice::<TransactionReport>(data) else {
        return;
    };
    let _ = cross_reference(&mut report);
});
