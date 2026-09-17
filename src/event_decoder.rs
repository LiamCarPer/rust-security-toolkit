use base64::Engine;
use sha2::{Digest, Sha256};

use crate::anchor_decoder::decode_anchor_type;
use crate::types::{EventRecord, IdlEvent, IdlJson, TransactionReport};

pub fn decode_events(report: &mut TransactionReport, idl: &IdlJson) {
    if idl.events.is_empty() || report.logs.is_empty() {
        return;
    }

    let mut program_stack: Vec<String> = Vec::new();

    for line in &report.logs {
        let line = line.trim();

        if let Some(encoded) = line.strip_prefix("Program data: ") {
            if let Some(record) = decode_data(encoded.trim(), idl, &program_stack) {
                report.events.push(record);
            }
            continue;
        }

        let Some(rest) = line.strip_prefix("Program ") else {
            continue;
        };
        let Some((program_id, tail)) = rest.split_once(' ') else {
            continue;
        };

        if tail.starts_with("invoke") {
            program_stack.push(program_id.to_string());
        } else if tail == "success" || tail.starts_with("failed:") {
            match program_stack.iter().rposition(|p| p.as_str() == program_id) {
                Some(pos) => program_stack.truncate(pos),
                None => {
                    program_stack.pop();
                }
            }
        }
    }
}

fn decode_data(encoded: &str, idl: &IdlJson, program_stack: &[String]) -> Option<EventRecord> {
    let data = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
    if data.len() < 8 {
        return None;
    }
    let discriminator: [u8; 8] = data[..8].try_into().ok()?;

    for event in &idl.events {
        let matched = match event.discriminator.as_deref() {
            Some(explicit) if !explicit.is_empty() => data.starts_with(explicit),
            _ => data.len() >= 8 && event_discriminator(&event.name) == discriminator,
        };
        if !matched {
            continue;
        }
        let offset = event.discriminator.as_ref().map(|d| d.len()).filter(|l| *l > 0).unwrap_or(8);
        let payload = data.get(offset..).unwrap_or_default();
        let fields = if event.fields.is_empty() {
            serde_json::json!({ "raw": hex::encode(payload) })
        } else {
            decode_fields(payload, event)
        };
        let program_id = program_stack.last().cloned().unwrap_or_else(|| "unknown".to_string());
        return Some(EventRecord { name: event.name.clone(), program_id, fields });
    }

    None
}

fn decode_fields(data: &[u8], event: &IdlEvent) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    let mut offset = 0usize;

    for field in &event.fields {
        if offset >= data.len() {
            break;
        }
        let (value, consumed) = decode_anchor_type(data, offset, &field.ty);
        map.insert(field.name.clone(), value);
        if consumed == 0 {
            break;
        }
        offset += consumed;
    }

    serde_json::Value::Object(map)
}

fn event_discriminator(name: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(b"event:");
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
    let mut discriminator = [0u8; 8];
    discriminator.copy_from_slice(&digest[..8]);
    discriminator
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;

    use super::*;
    use crate::types::IdlEventField;

    fn idl_with_events(events: Vec<IdlEvent>) -> IdlJson {
        IdlJson {
            version: "0.1.0".to_string(),
            name: "test_program".to_string(),
            instructions: Vec::new(),
            accounts: Vec::new(),
            types: Vec::new(),
            events,
        }
    }

    fn report_with_logs(logs: Vec<String>) -> TransactionReport {
        TransactionReport {
            status: "SUCCESS".to_string(),
            fee_payer: "FeePayer111111111111111111111111111111111".to_string(),
            signatures: Vec::new(),
            recent_blockhash: "Blockhash111111111111111111111111111111".to_string(),
            message_version: None,
            accounts: Vec::new(),
            instructions: Vec::new(),
            address_lookup_tables: Vec::new(),
            compute_budget: None,
            risk_flags: Vec::new(),
            simulation: None,
            warnings: Vec::new(),
            signature_verification: Vec::new(),
            inner_instructions: Vec::new(),
            balance_changes_sol: Vec::new(),
            token_balance_changes: Vec::new(),
            oracle_feeds: Vec::new(),
            idl_source: None,
            logs,
            events: Vec::new(),
            program_analyses: Vec::new(),
        }
    }

    fn encode_event(name: &str, payload: &[u8]) -> String {
        let mut data = event_discriminator(name).to_vec();
        data.extend_from_slice(payload);
        STANDARD.encode(data)
    }

    fn u64_event(name: &str, field: &str) -> IdlEvent {
        IdlEvent {
            name: name.to_string(),
            fields: vec![IdlEventField { name: field.to_string(), ty: serde_json::json!("u64"), index: false }],
            discriminator: None,
        }
    }

    #[test]
    fn decodes_u64_event_with_program_attribution() {
        let idl = idl_with_events(vec![u64_event("Transfer", "amount")]);
        let mut report = report_with_logs(vec![
            "Program Prog111111111111111111111111111111111111 invoke [1]".to_string(),
            format!("Program data: {}", encode_event("Transfer", &42u64.to_le_bytes())),
            "Program Prog111111111111111111111111111111111111 success".to_string(),
        ]);

        decode_events(&mut report, &idl);

        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].name, "Transfer");
        assert_eq!(report.events[0].program_id, "Prog111111111111111111111111111111111111");
        assert_eq!(report.events[0].fields["amount"], serde_json::json!("42"));
    }

    #[test]
    fn decodes_string_and_public_key_fields() {
        let idl = idl_with_events(vec![IdlEvent {
            name: "Announce".to_string(),
            fields: vec![
                IdlEventField { name: "label".to_string(), ty: serde_json::json!("string"), index: false },
                IdlEventField { name: "owner".to_string(), ty: serde_json::json!("publicKey"), index: false },
            ],
            discriminator: None,
        }]);

        let label = b"hello";
        let mut payload = Vec::new();
        payload.extend_from_slice(&(label.len() as u32).to_le_bytes());
        payload.extend_from_slice(label);
        payload.extend_from_slice(&[7u8; 32]);

        let mut report = report_with_logs(vec![
            "Program Prog222222222222222222222222222222222222 invoke [1]".to_string(),
            format!("Program data: {}", encode_event("Announce", &payload)),
            "Program Prog222222222222222222222222222222222222 success".to_string(),
        ]);

        decode_events(&mut report, &idl);

        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].fields["label"], serde_json::json!("hello"));
        assert_eq!(report.events[0].fields["owner"], serde_json::json!(bs58::encode([7u8; 32]).into_string()));
    }

    #[test]
    fn wrong_discriminator_ignored() {
        let idl = idl_with_events(vec![u64_event("Transfer", "amount")]);
        let mut data = vec![0u8; 8];
        data.extend_from_slice(&7u64.to_le_bytes());
        let mut report = report_with_logs(vec![
            "Program Prog111111111111111111111111111111111111 invoke [1]".to_string(),
            format!("Program data: {}", STANDARD.encode(data)),
            "Program Prog111111111111111111111111111111111111 success".to_string(),
        ]);

        decode_events(&mut report, &idl);

        assert!(report.events.is_empty());
    }

    #[test]
    fn malformed_base64_ignored() {
        let idl = idl_with_events(vec![u64_event("Transfer", "amount")]);
        let mut report = report_with_logs(vec![
            "Program Prog111111111111111111111111111111111111 invoke [1]".to_string(),
            "Program data: !!!".to_string(),
            "Program Prog111111111111111111111111111111111111 success".to_string(),
        ]);

        decode_events(&mut report, &idl);

        assert!(report.events.is_empty());
    }

    #[test]
    fn nested_cpi_event_attributed_to_inner_program() {
        let idl = idl_with_events(vec![u64_event("Transfer", "amount")]);
        let mut report = report_with_logs(vec![
            "Program Outer111111111111111111111111111111111111 invoke [1]".to_string(),
            "Program Inner111111111111111111111111111111111111 invoke [2]".to_string(),
            format!("Program data: {}", encode_event("Transfer", &9u64.to_le_bytes())),
            "Program Inner111111111111111111111111111111111111 success".to_string(),
            "Program Outer111111111111111111111111111111111111 success".to_string(),
        ]);

        decode_events(&mut report, &idl);

        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].program_id, "Inner111111111111111111111111111111111111");
    }

    #[test]
    fn no_events_idl_noop() {
        let idl = idl_with_events(Vec::new());
        let mut report = report_with_logs(vec![
            "Program Prog111111111111111111111111111111111111 invoke [1]".to_string(),
            format!("Program data: {}", encode_event("Transfer", &42u64.to_le_bytes())),
            "Program Prog111111111111111111111111111111111111 success".to_string(),
        ]);

        decode_events(&mut report, &idl);

        assert!(report.events.is_empty());
    }

    #[test]
    fn empty_logs_noop() {
        let idl = idl_with_events(vec![u64_event("Transfer", "amount")]);
        let mut report = report_with_logs(Vec::new());

        decode_events(&mut report, &idl);

        assert!(report.events.is_empty());
    }

    #[test]
    fn truncated_payload_no_panic() {
        let idl = idl_with_events(vec![u64_event("Transfer", "amount")]);
        let mut report = report_with_logs(vec![
            "Program Prog111111111111111111111111111111111111 invoke [1]".to_string(),
            format!("Program data: {}", encode_event("Transfer", &[1u8, 2, 3, 4])),
            "Program Prog111111111111111111111111111111111111 success".to_string(),
        ]);

        decode_events(&mut report, &idl);

        assert_eq!(report.events.len(), 1);
        assert!(report.events[0].fields["amount"].is_null());
    }
    #[test]
    fn explicit_discriminator_and_raw_payload() {
        let disc = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let idl = idl_with_events(vec![IdlEvent {
            name: "Thing".to_string(),
            fields: Vec::new(),
            discriminator: Some(disc.clone()),
        }]);
        let mut payload = disc.clone();
        payload.extend_from_slice(&[1, 2, 3, 4]);
        let logs = vec![
            "Program Prog111111111111111111111111111111111111 invoke [1]".to_string(),
            format!("Program data: {}", STANDARD.encode(&payload)),
            "Program Prog111111111111111111111111111111111111 success".to_string(),
        ];
        let mut report = report_with_logs(logs);
        decode_events(&mut report, &idl);
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].name, "Thing");
        assert_eq!(report.events[0].fields["raw"], "01020304");
    }
}
