use crate::types::{InstructionCu, RiskCategory, RiskFlag, RiskSeverity};

fn program_id_ok(id: &str) -> bool {
    !id.is_empty()
        && !id.contains(' ')
        && !id.starts_with("log:")
        && !id.starts_with("data:")
        && !id.starts_with("return:")
        && !id.starts_with("failed")
}

fn parse_invoke(line: &str) -> Option<(String, u64)> {
    let rest = line.strip_prefix("Program ")?;
    let pos = rest.find(" invoke [")?;
    let id = &rest[..pos];
    if !program_id_ok(id) {
        return None;
    }
    let depth = rest[pos + " invoke [".len()..].strip_suffix(']')?.parse::<u64>().ok()?;
    Some((id.to_string(), depth))
}

fn is_success(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("Program ") else { return false };
    let Some(id) = rest.strip_suffix(" success") else { return false };
    program_id_ok(id)
}

fn is_failed(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("Program ") else { return false };
    let Some(pos) = rest.find(" failed: ") else { return false };
    program_id_ok(&rest[..pos])
}

fn parse_consumed(line: &str) -> Option<(String, u64, u64)> {
    let rest = line.strip_prefix("Program ")?;
    let pos = rest.find(" consumed ")?;
    let id = &rest[..pos];
    if !program_id_ok(id) {
        return None;
    }
    let tail = &rest[pos + " consumed ".len()..];
    let (units_str, limit_part) = tail.split_once(" of ")?;
    let limit_str = limit_part.strip_suffix(" compute units")?;
    let units_consumed = units_str.parse::<u64>().ok()?;
    let cu_limit = limit_str.parse::<u64>().ok()?;
    Some((id.to_string(), units_consumed, cu_limit))
}

pub fn parse_instruction_cu(logs: &[String]) -> Vec<InstructionCu> {
    let mut stack: Vec<u64> = Vec::new();
    let mut completed_top_levels: u32 = 0;
    let mut current_top_level: u32 = 0;
    let mut has_top_level = false;
    let mut out = Vec::new();

    for line in logs {
        if let Some((_, depth)) = parse_invoke(line) {
            if depth == 0 {
                continue;
            }
            if depth == 1 {
                current_top_level = completed_top_levels;
                has_top_level = true;
            }
            stack.push(depth);
            continue;
        }
        if is_success(line) || is_failed(line) {
            if let Some(depth) = stack.pop()
                && depth == 1
            {
                completed_top_levels += 1;
            }
            continue;
        }
        if let Some((id, units_consumed, cu_limit)) = parse_consumed(line) {
            if !has_top_level {
                continue;
            }
            out.push(InstructionCu {
                instruction_index: current_top_level.min(255) as u8,
                program_id: id,
                units_consumed,
                cu_limit,
            });
        }
    }

    out
}

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

    if let Some(sim) = report.simulation.as_mut() {
        sim.instruction_cu = parse_instruction_cu(&sim.logs);
    }

    if let Some(sim) = report.simulation.as_ref()
        && !sim.instruction_cu.is_empty()
    {
        let actuals: std::collections::HashMap<u8, &InstructionCu> =
            sim.instruction_cu.iter().map(|cu| (cu.instruction_index, cu)).collect();
        let threshold = report
            .compute_budget
            .as_ref()
            .map(|cb| crate::decoder::high_cu_threshold(cb.compute_unit_limit))
            .unwrap_or(10_000);

        report.risk_flags.retain(|f| {
            if f.category == RiskCategory::HighComputeUnitUsage
                && let Some(idx) = f.instruction_index
                && let Some(actual) = actuals.get(&idx)
                && actual.units_consumed < threshold as u64
            {
                return false;
            }
            true
        });

        let covered: std::collections::HashSet<u8> = report
            .risk_flags
            .iter()
            .filter(|f| f.category == RiskCategory::HighComputeUnitUsage)
            .filter_map(|f| f.instruction_index)
            .collect();
        let mut emitted: std::collections::HashSet<u8> = std::collections::HashSet::new();
        for cu in &sim.instruction_cu {
            if cu.program_id == crate::types::COMPUTE_BUDGET_PROGRAM_ID
                || cu.units_consumed < threshold as u64
                || cu.instruction_index as usize >= report.instructions.len()
                || covered.contains(&cu.instruction_index)
                || !emitted.insert(cu.instruction_index)
            {
                continue;
            }
            flags.push(RiskFlag {
                severity: RiskSeverity::Warning,
                category: RiskCategory::HighComputeUnitUsage,
                instruction_index: Some(cu.instruction_index),
                message: format!(
                    "High Compute Unit Usage: Instruction #{} consumed {} CU (simulated), above the {} CU threshold",
                    cu.instruction_index, cu.units_consumed, threshold
                ),
                details: "Simulated compute unit consumption exceeds the high-CU threshold; \
                          may indicate a spam/DoS-shaped instruction or an unusually heavy operation."
                    .to_string(),
            });
        }
    }

    if let Some(sim) = report.simulation.as_ref() {
        for cu in &sim.instruction_cu {
            let Some(ix) = report.instructions.iter().find(|d| d.index == cu.instruction_index) else { continue };
            let estimate = crate::decoder::estimate_cu_cost(ix);
            if estimate == 0 {
                continue;
            }
            let actual = cu.units_consumed;
            let estimate_exceeds = (estimate as f64) > actual as f64 * 1.5;
            let actual_exceeds = actual > estimate as u64 * 3;
            if estimate_exceeds || actual_exceeds {
                let name = ix.instruction_name.as_deref().unwrap_or(ix.program_name.as_str());
                flags.push(RiskFlag {
                    severity: RiskSeverity::Info,
                    category: RiskCategory::SimulationMismatch,
                    instruction_index: Some(cu.instruction_index),
                    message: format!(
                        "Instruction #{} ({name}): simulated {actual} CU vs estimated {estimate} CU — estimate table may need recalibration",
                        cu.instruction_index
                    ),
                    details: "The simulated compute unit consumption deviates from the static estimate by \
                              more than 50% in one direction or more than 3x in the other; the estimate \
                              table may need recalibration."
                        .to_string(),
                });
            }
        }
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
            signature_verification: vec![],
            inner_instructions: vec![],
            balance_changes_sol: vec![],
            token_balance_changes: vec![],
            oracle_feeds: Vec::new(),
            idl_source: None,
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
            instruction_cu: Vec::new(),
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

    #[test]
    fn flat_instructions_attributed_with_indexes() {
        let logs = vec![
            "Program 11111111111111111111111111111111 invoke [1]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            "Program 11111111111111111111111111111111 consumed 150 of 200000 compute units".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 1234 of 200000 compute units".to_string(),
            "Program JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4 invoke [1]".to_string(),
            "Program JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4 success".to_string(),
            "Program JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4 consumed 370267 of 1400000 compute units".to_string(),
        ];
        let cu = parse_instruction_cu(&logs);
        assert_eq!(cu.len(), 3);
        assert_eq!(cu[0].instruction_index, 0);
        assert_eq!(cu[0].program_id, SYSTEM_PROGRAM_ID);
        assert_eq!(cu[0].units_consumed, 150);
        assert_eq!(cu[0].cu_limit, 200_000);
        assert_eq!(cu[1].instruction_index, 1);
        assert_eq!(cu[1].program_id, TOKEN_PROGRAM_ID);
        assert_eq!(cu[1].units_consumed, 1234);
        assert_eq!(cu[1].cu_limit, 200_000);
        assert_eq!(cu[2].instruction_index, 2);
        assert_eq!(cu[2].program_id, "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
        assert_eq!(cu[2].units_consumed, 370_267);
        assert_eq!(cu[2].cu_limit, 1_400_000);
    }

    #[test]
    fn nested_cpi_single_entry_for_outer_instruction() {
        let logs = vec![
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]".to_string(),
            "Program 11111111111111111111111111111111 invoke [2]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 7138 of 200000 compute units".to_string(),
        ];
        let cu = parse_instruction_cu(&logs);
        assert_eq!(cu.len(), 1);
        assert_eq!(cu[0].instruction_index, 0);
        assert_eq!(cu[0].program_id, TOKEN_PROGRAM_ID);
        assert_eq!(cu[0].units_consumed, 7138);
        assert_eq!(cu[0].cu_limit, 200_000);
    }

    #[test]
    fn failed_instruction_has_no_entry() {
        let logs = vec![
            "Program 11111111111111111111111111111111 invoke [1]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            "Program 11111111111111111111111111111111 consumed 100 of 200000 compute units".to_string(),
            "Program JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4 invoke [1]".to_string(),
            "Program JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4 failed: custom program error: 0x1".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 200 of 200000 compute units".to_string(),
        ];
        let cu = parse_instruction_cu(&logs);
        assert_eq!(cu.len(), 2);
        assert_eq!(cu[0].instruction_index, 0);
        assert_eq!(cu[0].units_consumed, 100);
        assert_eq!(cu[1].instruction_index, 2);
        assert_eq!(cu[1].program_id, TOKEN_PROGRAM_ID);
        assert_eq!(cu[1].units_consumed, 200);
        assert!(cu.iter().all(|e| e.instruction_index != 1));
    }

    #[test]
    fn custom_program_log_with_consumed_ignored() {
        let logs = vec![
            "Program 11111111111111111111111111111111 invoke [1]".to_string(),
            "Program log: consumed 500 of 1000 compute units".to_string(),
            "Program log: we consumed 1000 compute units".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            "Program 11111111111111111111111111111111 consumed 150 of 200000 compute units".to_string(),
        ];
        let cu = parse_instruction_cu(&logs);
        assert_eq!(cu.len(), 1);
        assert_eq!(cu[0].program_id, SYSTEM_PROGRAM_ID);
        assert_eq!(cu[0].units_consumed, 150);
    }

    #[test]
    fn malformed_consumed_numbers_skipped() {
        let logs = vec![
            "Program 11111111111111111111111111111111 invoke [1]".to_string(),
            "Program 11111111111111111111111111111111 consumed abc of 5 compute units".to_string(),
            "Program 11111111111111111111111111111111 consumed 5 of abc compute units".to_string(),
            "Program 11111111111111111111111111111111 consumed 5 of 100".to_string(),
            "Program 11111111111111111111111111111111 consumed 5 100 compute units".to_string(),
        ];
        let cu = parse_instruction_cu(&logs);
        assert!(cu.is_empty());
    }

    #[test]
    fn empty_logs_yield_empty() {
        let cu = parse_instruction_cu(&[]);
        assert!(cu.is_empty());
    }

    #[test]
    fn consumed_before_any_invoke_skipped() {
        let logs = vec!["Program 11111111111111111111111111111111 consumed 100 of 200000 compute units".to_string()];
        let cu = parse_instruction_cu(&logs);
        assert!(cu.is_empty());
    }

    #[test]
    fn depth_zero_and_garbled_lines_ignored() {
        let logs = vec![
            "Program 11111111111111111111111111111111 invoke [0]".to_string(),
            "Program 11111111111111111111111111111111 invoke [x]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            "Program 11111111111111111111111111111111 consumed 5 of 6 compute units".to_string(),
            "Program 11111111111111111111111111111111 invoke [1]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            "Program 11111111111111111111111111111111 consumed 7 of 8 compute units".to_string(),
        ];
        let cu = parse_instruction_cu(&logs);
        assert_eq!(cu.len(), 1);
        assert_eq!(cu[0].instruction_index, 0);
        assert_eq!(cu[0].units_consumed, 7);
        assert_eq!(cu[0].cu_limit, 8);
    }

    #[test]
    fn cross_reference_populates_instruction_cu() {
        let logs = vec![
            "Program 11111111111111111111111111111111 invoke [1]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            "Program 11111111111111111111111111111111 consumed 100 of 200000 compute units".to_string(),
            "Program 11111111111111111111111111111111 invoke [1]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            "Program 11111111111111111111111111111111 consumed 200 of 200000 compute units".to_string(),
        ];
        let mut report = base_report(2, None, Some(simulation(true, logs, 300, None)));
        let flags = cross_reference(&mut report);
        assert!(
            flags.iter().all(|f| f.severity == RiskSeverity::Info && f.message.contains("recalibration")),
            "unexpected flags: {:?}",
            flags
        );
        let cu = report.simulation.as_ref().expect("simulation present").instruction_cu.clone();
        assert_eq!(cu.len(), 2);
        assert_eq!(cu[0].instruction_index, 0);
        assert_eq!(cu[0].units_consumed, 100);
        assert_eq!(cu[1].instruction_index, 1);
        assert_eq!(cu[1].units_consumed, 200);
    }

    fn instruction(program_name: &str, name: &str, index: u8) -> DecodedInstruction {
        DecodedInstruction {
            index,
            program_id: String::new(),
            program_name: program_name.to_string(),
            instruction_name: Some(name.to_string()),
            accounts: vec![],
            data: serde_json::Value::Null,
            raw_data_hex: String::new(),
            token_amount: None,
        }
    }

    fn consumed_logs(consumed: u64) -> Vec<String> {
        vec![
            "Program 11111111111111111111111111111111 invoke [1]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            format!("Program 11111111111111111111111111111111 consumed {consumed} of 200000 compute units"),
        ]
    }

    fn consumed_logs_at_index(index: usize, consumed: u64) -> Vec<String> {
        let mut logs = Vec::new();
        for _ in 0..index {
            logs.push(format!("Program {SYSTEM_PROGRAM_ID} invoke [1]"));
            logs.push(format!("Program {SYSTEM_PROGRAM_ID} success"));
        }
        logs.push(format!("Program {SYSTEM_PROGRAM_ID} invoke [1]"));
        logs.push(format!("Program {SYSTEM_PROGRAM_ID} success"));
        logs.push(format!("Program {SYSTEM_PROGRAM_ID} consumed {consumed} of 200000 compute units"));
        logs
    }

    fn estimate_high_cu_flag(index: u8) -> RiskFlag {
        RiskFlag {
            severity: RiskSeverity::Warning,
            category: RiskCategory::HighComputeUnitUsage,
            instruction_index: Some(index),
            message: format!("High Compute Unit Usage: Instruction #{index} estimated CU cost exceeds threshold."),
            details: String::new(),
        }
    }

    #[test]
    fn estimate_vs_actual_within_bounds_no_flag() {
        let mut report = base_report(1, None, Some(simulation(true, consumed_logs(8_000), 8_000, None)));
        report.instructions = vec![instruction("Token Program", "Transfer", 0)];
        let flags = cross_reference(&mut report);
        assert!(flags.is_empty(), "unexpected flags: {:?}", flags);
    }

    #[test]
    fn estimate_underestimates_actual_flags_info() {
        let mut report = base_report(1, None, Some(simulation(true, consumed_logs(15_000), 15_000, None)));
        report.instructions = vec![instruction("Token Program", "Transfer", 0)];
        let flags = cross_reference(&mut report);
        let cal = flags.iter().find(|f| f.message.contains("recalibration")).expect("calibration flag");
        assert_eq!(cal.severity, RiskSeverity::Info);
        assert_eq!(cal.category, RiskCategory::SimulationMismatch);
        assert_eq!(cal.instruction_index, Some(0));
        assert!(cal.message.contains("Instruction #0 (Transfer): simulated 15000 CU vs estimated 3000 CU"));
    }

    #[test]
    fn estimate_overestimates_actual_flags_info() {
        let mut report = base_report(1, None, Some(simulation(true, consumed_logs(2_000), 2_000, None)));
        report.instructions = vec![instruction("System Program", "CreateAccount", 0)];
        let flags = cross_reference(&mut report);
        let cal = flags.iter().find(|f| f.message.contains("recalibration")).expect("calibration flag");
        assert_eq!(cal.severity, RiskSeverity::Info);
        assert_eq!(cal.instruction_index, Some(0));
        assert!(cal.message.contains("simulated 2000 CU vs estimated 15000 CU"));
    }

    #[test]
    fn compute_budget_instructions_never_flag() {
        let mut report = base_report(1, None, Some(simulation(true, consumed_logs(1_000), 1_000, None)));
        report.instructions = vec![instruction("Compute Budget", "SetComputeUnitLimit", 0)];
        let flags = cross_reference(&mut report);
        assert!(flags.is_empty(), "unexpected flags: {:?}", flags);
    }

    #[test]
    fn calibration_flags_append_after_existing() {
        let mut report = base_report(
            1,
            Some(budget(150_000, 0, vec![0])),
            Some(simulation(true, consumed_logs(170_000), 175_000, None)),
        );
        report.instructions = vec![instruction("System Program", "Transfer", 0)];
        let flags = cross_reference(&mut report);
        let cu = flags.iter().find(|f| f.message.contains("declared limit")).expect("cu-limit flag");
        assert_eq!(cu.severity, RiskSeverity::Warning);
        let cal = flags.iter().find(|f| f.message.contains("recalibration")).expect("calibration flag");
        assert_eq!(cal.severity, RiskSeverity::Info);
        assert_eq!(flags.last().map(|f| f.message.contains("recalibration")), Some(true));
    }

    #[test]
    fn estimate_high_flag_refuted_by_actuals_is_removed() {
        let mut report = base_report(1, None, Some(simulation(true, consumed_logs(2_000), 2_000, None)));
        report.risk_flags.push(estimate_high_cu_flag(0));
        let flags = cross_reference(&mut report);
        assert!(
            report.risk_flags.iter().all(|f| f.category != RiskCategory::HighComputeUnitUsage),
            "refuted estimate flag must be removed: {:?}",
            report.risk_flags
        );
        assert!(
            flags.iter().all(|f| f.category != RiskCategory::HighComputeUnitUsage),
            "no actual-based flag expected: {:?}",
            flags
        );
    }

    #[test]
    fn actual_high_usage_emits_warning_without_estimate_flag() {
        let mut report = base_report(2, None, Some(simulation(true, consumed_logs_at_index(1, 40_000), 40_000, None)));
        let flags = cross_reference(&mut report);
        let high = flags.iter().find(|f| f.category == RiskCategory::HighComputeUnitUsage).expect("high-cu flag");
        assert_eq!(high.severity, RiskSeverity::Warning);
        assert_eq!(high.instruction_index, Some(1));
        assert!(
            high.message.contains("Instruction #1 consumed 40000 CU (simulated), above the 10000 CU threshold"),
            "unexpected message: {}",
            high.message
        );
    }

    #[test]
    fn actual_high_usage_keeps_existing_estimate_flag_single() {
        let mut report = base_report(1, None, Some(simulation(true, consumed_logs(40_000), 40_000, None)));
        report.risk_flags.push(estimate_high_cu_flag(0));
        let flags = cross_reference(&mut report);
        let count = report
            .risk_flags
            .iter()
            .chain(flags.iter())
            .filter(|f| f.category == RiskCategory::HighComputeUnitUsage)
            .count();
        assert_eq!(count, 1, "exactly one high-CU flag must remain for index 0");
        assert_eq!(report.risk_flags[0].instruction_index, Some(0));
        assert!(report.risk_flags[0].message.contains("estimated CU cost exceeds threshold"));
    }

    #[test]
    fn actuals_below_threshold_no_flags() {
        let mut report = base_report(1, None, Some(simulation(true, consumed_logs(1_000), 1_000, None)));
        let flags = cross_reference(&mut report);
        assert!(
            flags.iter().all(|f| f.category != RiskCategory::HighComputeUnitUsage),
            "unexpected flags: {:?}",
            flags
        );
        assert!(report.risk_flags.iter().all(|f| f.category != RiskCategory::HighComputeUnitUsage));
    }

    #[test]
    fn high_cu_logic_skips_without_simulation() {
        let mut report = base_report(1, None, None);
        report.risk_flags.push(estimate_high_cu_flag(0));
        let flags = cross_reference(&mut report);
        assert!(flags.is_empty(), "unexpected flags: {:?}", flags);
        assert_eq!(report.risk_flags.len(), 1);
        assert!(report.risk_flags.iter().any(|f| f.category == RiskCategory::HighComputeUnitUsage));
    }

    #[test]
    fn out_of_range_instruction_index_skipped() {
        let mut report =
            base_report(2, None, Some(simulation(true, consumed_logs_at_index(99, 1_000_000), 1_000_000, None)));
        let flags = cross_reference(&mut report);
        assert!(
            flags.iter().all(|f| f.category != RiskCategory::HighComputeUnitUsage),
            "out-of-range index must not be flagged: {:?}",
            flags
        );
    }

    #[test]
    fn compute_budget_instruction_not_flagged() {
        let logs = vec![
            format!("Program {COMPUTE_BUDGET_PROGRAM_ID} invoke [1]"),
            format!("Program {COMPUTE_BUDGET_PROGRAM_ID} success"),
            format!("Program {COMPUTE_BUDGET_PROGRAM_ID} consumed 50000 of 200000 compute units"),
        ];
        let mut report = base_report(1, None, Some(simulation(true, logs, 50_000, None)));
        let flags = cross_reference(&mut report);
        assert!(
            flags.iter().all(|f| f.category != RiskCategory::HighComputeUnitUsage),
            "compute budget program must not be flagged: {:?}",
            flags
        );
    }
}
