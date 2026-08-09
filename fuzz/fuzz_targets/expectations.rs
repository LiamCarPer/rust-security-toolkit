#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_security_toolkit::expectations_decoder::{decode_instruction, match_expectation};
use rust_security_toolkit::types::ExpectationsDoc;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let Some(doc) = input.get("doc").and_then(|d| serde_json::from_value::<ExpectationsDoc>(d.clone()).ok()) else {
        return;
    };
    let program_id = input.get("program_id").and_then(serde_json::Value::as_str).unwrap_or_default();
    let data: Vec<u8> = input
        .get("data")
        .and_then(serde_json::Value::as_array)
        .map(|arr| arr.iter().filter_map(serde_json::Value::as_u64).map(|b| b as u8).collect())
        .unwrap_or_default();
    let _ = match_expectation(program_id, &data, &doc);
    let _ = decode_instruction(program_id, &data, &doc);
    let _ = doc.find_instruction(program_id);
});
