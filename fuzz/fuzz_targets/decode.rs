#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_security_toolkit::anchor_decoder::decode_anchor_args;
use rust_security_toolkit::decoder::decode_raw_bytes;
use rust_security_toolkit::types::IdlArg;

/// Fuzz the canonical decode path and the Anchor argument decoder.
//
// Run with:
//   cargo +nightly fuzz run decode
fuzz_target!(|data: &[u8]| {
    let _ = decode_raw_bytes(data, None);

    let args = vec![
        IdlArg { name: "a".into(), ty: serde_json::json!("u64") },
        IdlArg { name: "b".into(), ty: serde_json::json!("string") },
        IdlArg { name: "c".into(), ty: serde_json::json!({"vec": "u8"}) },
        IdlArg { name: "d".into(), ty: serde_json::json!({"option": "publicKey"}) },
        IdlArg { name: "e".into(), ty: serde_json::json!({"array": ["u8", 8]}) },
    ];
    let _ = decode_anchor_args(data, &args);
});
