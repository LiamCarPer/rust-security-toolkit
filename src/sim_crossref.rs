use crate::types::{RiskCategory, RiskFlag, RiskSeverity};

pub fn cross_reference(report: &mut crate::types::TransactionReport) -> Vec<crate::types::RiskFlag> {
    let mut flags = Vec::new();

    let Some(sim) = report.simulation.as_ref() else { return flags };
    let success = sim.success;
    let error_instruction_index = sim.error_instruction_index;
    let units_consumed = sim.units_consumed;
    let invocation_count = sim.logs.iter().filter(|l| l.starts_with("Program ") && l.contains("invoke [")).count();

    if let Some(i) = error_instruction_index {
        let decoded = report.instructions.len();
        if i as usize >= decoded {
            flags.push(RiskFlag {
                severity: RiskSeverity::Warning,
                category: RiskCategory::SimulationMismatch,
                instruction_index: Some(i),
                message: format!(
                    "Simulation failed at instruction #{i} which is outside the instruction indexes our decoder saw ({decoded} instructions)"
                ),
                details: "The simulation failed at an instruction index the decoder did not decode; \
                          the simulation and the local decode disagree about the transaction layout."
                    .to_string(),
            });
        }
    }

    if let Some(cb) = report.compute_budget.as_ref()
        && units_consumed > cb.compute_unit_limit as u64
    {
        let index = cb.compute_budget_positions.first().map(|&p| p.min(255) as u8);
        let prefix = index.map(|i| format!("Instruction #{i}: ")).unwrap_or_default();
        flags.push(RiskFlag {
            severity: RiskSeverity::Warning,
            category: RiskCategory::SimulationMismatch,
            instruction_index: index,
            message: format!(
                "{prefix}simulation consumed {units_consumed} CU, declared limit {} CU",
                cb.compute_unit_limit
            ),
            details: "The simulation consumed more compute units than the transaction's declared \
                      compute unit limit permits; the transaction is likely to fail once submitted."
                .to_string(),
        });
    }

    if let Some(cb) = report.compute_budget.as_mut()
        && cb.compute_unit_price > 0
        && units_consumed > 0
    {
        cb.priority_fee_actual = Some((cb.compute_unit_price as u128 * units_consumed as u128 / 1_000_000) as u64);
    }

    let decoded = report.instructions.len();
    if invocation_count != decoded {
        flags.push(RiskFlag {
            severity: RiskSeverity::Warning,
            category: RiskCategory::SimulationMismatch,
            instruction_index: None,
            message: format!(
                "Simulation logged {invocation_count} program invocations but we decoded {decoded} instructions"
            ),
            details: "The simulation log and the local decode disagree on how many instructions executed.".to_string(),
        });
    }

    if !success
        && let Some(i) = error_instruction_index
        && let Some(ix) = report.instructions.iter().find(|d| d.index == i)
    {
        let name = ix.instruction_name.as_deref().unwrap_or(ix.program_name.as_str());
        flags.push(RiskFlag {
            severity: RiskSeverity::Info,
            category: RiskCategory::SimulationMismatch,
            instruction_index: Some(i),
            message: format!("Instruction #{i} (decoded as '{name}') was the first to fail during simulation"),
            details: "The simulation error points at a locally decoded instruction; recorded for context, \
                      not a mismatch."
                .to_string(),
        });
    }

    flags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn base_report(
        instructions: usize,
        budget: Option<ComputeBudgetInfo>,
        simulation: Option<SimulationResult>,
    ) -> TransactionReport {
        TransactionReport {
            status: "OK".into(),
            fee_payer: SYSTEM_PROGRAM_ID.into(),
            signatures: vec![],
            recent_blockhash: "11111111111111111111111111111111".into(),
            message_version: None,
            accounts: vec![],
            instructions: (0..instructions as u8)
                .map(|i| DecodedInstruction {
                    index: i,
                    program_id: SYSTEM_PROGRAM_ID.into(),
                    program_name: "System Program".into(),
                    instruction_name: Some("transfer".into()),
                    accounts: vec![],
                    data: serde_json::Value::Null,
                    raw_data_hex: String::new(),
                    token_amount: None,
                })
                .collect(),
            address_lookup_tables: vec![],
            compute_budget: budget,
            risk_flags: vec![],
            simulation,
            warnings: vec![],
        }
    }

    fn simulation(
        success: bool,
        logs: Vec<String>,
        units_consumed: u64,
        error_instruction_index: Option<u8>,
    ) -> SimulationResult {
        SimulationResult {
            success,
            error: None,
            logs,
            units_consumed,
            return_data: None,
            error_code: None,
            error_instruction_index,
        }
    }

    fn invoke_logs(n: usize) -> Vec<String> {
        (1..=n).map(|i| format!("Program 11111111111111111111111111111111 invoke [{i}]")).collect()
    }

    fn budget(limit: u32, price: u64, positions: Vec<usize>) -> ComputeBudgetInfo {
        ComputeBudgetInfo {
            compute_unit_limit: limit,
            compute_unit_price: price,
            compute_unit_limit_set: true,
            compute_budget_positions: positions,
            is_reordered: false,
            high_cu_instructions: vec![],
            priority_fee_lamports: 0,
            priority_fee_actual: None,
        }
    }

    #[test]
    fn no_simulation_returns_empty() {
        let mut report = base_report(2, None, None);
        let flags = cross_reference(&mut report);
        assert!(flags.is_empty());
    }

    #[test]
    fn error_index_out_of_bounds_warns() {
        let mut report = base_report(3, None, Some(simulation(false, invoke_logs(1), 0, Some(5))));
        let flags = cross_reference(&mut report);
        let oob =
            flags.iter().find(|f| f.message.contains("outside the instruction indexes")).expect("out-of-bounds flag");
        assert_eq!(oob.severity, RiskSeverity::Warning);
        assert_eq!(oob.category, RiskCategory::SimulationMismatch);
        assert_eq!(oob.instruction_index, Some(5));
        assert!(oob.message.contains("5") && oob.message.contains("3 instructions"));
        assert!(flags.iter().any(|f| f.message.contains("program invocations")));
    }

    #[test]
    fn cu_over_limit_warns() {
        let mut report =
            base_report(2, Some(budget(150_000, 0, vec![0])), Some(simulation(true, invoke_logs(2), 175_000, None)));
        let flags = cross_reference(&mut report);
        let cu = flags.iter().find(|f| f.message.contains("declared limit")).expect("cu flag");
        assert_eq!(cu.severity, RiskSeverity::Warning);
        assert_eq!(cu.instruction_index, Some(0));
        assert!(cu.message.contains("Instruction #0"));
        assert!(cu.message.contains("175000 CU"));
    }

    #[test]
    fn price_and_units_set_priority_fee_actual() {
        let mut report = base_report(
            2,
            Some(budget(200_000, 1_000, vec![0])),
            Some(simulation(true, invoke_logs(2), 175_000, None)),
        );
        let flags = cross_reference(&mut report);
        assert!(flags.is_empty());
        assert_eq!(report.compute_budget.as_ref().map(|c| c.priority_fee_actual), Some(Some(175)));
    }

    #[test]
    fn log_invocation_mismatch_warns() {
        let mut report = base_report(3, None, Some(simulation(true, invoke_logs(1), 0, None)));
        let flags = cross_reference(&mut report);
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].severity, RiskSeverity::Warning);
        assert!(flags[0].message.contains("1 program invocations"));
        assert!(flags[0].message.contains("3 instructions"));
    }

    #[test]
    fn failed_simulation_documents_failing_instruction() {
        let mut report = base_report(2, None, Some(simulation(false, invoke_logs(2), 0, Some(1))));
        let flags = cross_reference(&mut report);
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].severity, RiskSeverity::Info);
        assert_eq!(flags[0].instruction_index, Some(1));
        assert!(flags[0].message.contains("was the first to fail"));
        assert!(flags[0].message.contains("transfer"));
    }

    #[test]
    fn empty_logs_flag_against_decoded_instructions() {
        let mut report = base_report(2, None, Some(simulation(true, vec![], 0, None)));
        let flags = cross_reference(&mut report);
        assert_eq!(flags.len(), 1);
        assert!(flags[0].message.contains("0 program invocations but we decoded 2 instructions"));
    }
}
