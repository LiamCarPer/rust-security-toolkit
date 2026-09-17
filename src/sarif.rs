//! SARIF 2.1.0 export for GitHub code scanning / CI gating.

use crate::types::{RiskSeverity, TransactionReport};

fn level(severity: &RiskSeverity) -> &'static str {
    match severity {
        RiskSeverity::Critical => "error",
        RiskSeverity::Warning => "warning",
        RiskSeverity::Info => "note",
    }
}

pub fn render_sarif(report: &TransactionReport) -> String {
    let signature = report.signatures.first().cloned().unwrap_or_else(|| report.fee_payer.clone());
    let results: Vec<serde_json::Value> = report
        .risk_flags
        .iter()
        .map(|flag| {
            let location = match flag.instruction_index {
                Some(index) => serde_json::json!({
                    "logicalLocations": [{
                        "fullyQualifiedName": format!("instruction#{index}"),
                        "kind": "instruction"
                    }]
                }),
                None => serde_json::json!({
                    "logicalLocations": [{
                        "fullyQualifiedName": "transaction",
                        "kind": "transaction"
                    }]
                }),
            };
            serde_json::json!({
                "ruleId": format!("{:?}", flag.category),
                "level": level(&flag.severity),
                "message": { "text": flag.message },
                "properties": { "details": flag.details },
                "locations": [ location ],
            })
        })
        .collect();

    let sarif = serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "rts",
                    "informationUri": "https://github.com/LiamCarPer/rust-security-toolkit",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            },
            "invocations": [{
                "executionSuccessful": true,
                "properties": {
                    "transaction": signature,
                    "feePayer": report.fee_payer,
                    "idlSource": report.idl_source,
                }
            }],
            "results": results,
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{RiskCategory, RiskFlag};

    fn report_with(flags: Vec<RiskFlag>) -> TransactionReport {
        TransactionReport {
            status: "DECODED SUCCESSFULLY".to_string(),
            fee_payer: "FeePayer111111111111111111111111111111111".to_string(),
            signatures: vec!["Sig111111111111111111111111111111111111111111111111111111111111111".to_string()],
            recent_blockhash: String::new(),
            message_version: None,
            accounts: Vec::new(),
            instructions: Vec::new(),
            address_lookup_tables: Vec::new(),
            compute_budget: None,
            risk_flags: flags,
            simulation: None,
            warnings: Vec::new(),
            signature_verification: Vec::new(),
            inner_instructions: Vec::new(),
            balance_changes_sol: Vec::new(),
            token_balance_changes: Vec::new(),
            oracle_feeds: Vec::new(),
            idl_source: None,
            logs: Vec::new(),
            events: Vec::new(),
            program_analyses: Vec::new(),
        }
    }

    fn flag(severity: RiskSeverity, index: Option<u8>) -> RiskFlag {
        RiskFlag {
            severity,
            category: RiskCategory::PatternDetection,
            instruction_index: index,
            message: "test finding".to_string(),
            details: "details".to_string(),
        }
    }

    #[test]
    fn valid_sarif_with_results() {
        let report = report_with(vec![flag(RiskSeverity::Critical, Some(3))]);
        let out = render_sarif(&report);
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid json");
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["results"][0]["level"], "error");
        assert_eq!(v["runs"][0]["results"][0]["ruleId"], "PatternDetection");
        assert_eq!(
            v["runs"][0]["results"][0]["locations"][0]["logicalLocations"][0]["fullyQualifiedName"],
            "instruction#3"
        );
    }

    #[test]
    fn empty_report_has_no_results() {
        let report = report_with(Vec::new());
        let v: serde_json::Value = serde_json::from_str(&render_sarif(&report)).expect("valid json");
        assert!(v["runs"][0]["results"].as_array().unwrap().is_empty());
    }

    #[test]
    fn severity_level_mapping() {
        let report = report_with(vec![flag(RiskSeverity::Warning, None), flag(RiskSeverity::Info, None)]);
        let v: serde_json::Value = serde_json::from_str(&render_sarif(&report)).expect("valid json");
        assert_eq!(v["runs"][0]["results"][0]["level"], "warning");
        assert_eq!(v["runs"][0]["results"][1]["level"], "note");
    }
}
