#[cfg(test)]
mod cli_e2e_tests {
    use std::io::Write;
    use std::process::Command;
    use std::process::Stdio;

    fn rts_binary() -> Command {
        let path =
            std::env::var("CARGO_BIN_EXE_rts").expect("CARGO_BIN_EXE_rts not set; binary must be compiled first");
        Command::new(path)
    }

    fn read_fixture_hex(name: &str) -> String {
        let path = format!("tests/fixtures/{}", name);
        std::fs::read_to_string(&path).expect(&format!("Fixture not found: {}", path))
    }

    /// Decode a legacy transfer fixture via the CLI with --json output.
    #[test]
    fn test_cli_decode_legacy_json() {
        let hex = read_fixture_hex("system_transfer.hex");

        let output = rts_binary().arg("--json").arg(&hex).output().expect("Failed to execute rts binary");

        assert!(output.status.success(), "rts exited with: {:?}", output.status);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let report: serde_json::Value = serde_json::from_str(&stdout).expect("rts --json output is not valid JSON");
        assert_eq!(report["status"], "DECODED SUCCESSFULLY");
        assert!(report["instructions"].as_array().unwrap().len() >= 1);
        assert_eq!(report["instructions"][0]["program_name"], "System Program");
    }

    /// Decode a v0 transaction via the CLI.
    #[test]
    fn test_cli_decode_v0_json() {
        let hex = read_fixture_hex("v0_transfer.hex");

        let output = rts_binary().arg("--json").arg(&hex).output().expect("Failed to execute rts binary");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(report["message_version"], serde_json::Value::Number(0.into()));
    }

    /// Decode a compute budget transaction via the CLI.
    #[test]
    fn test_cli_decode_cu_json() {
        let hex = read_fixture_hex("compute_budget_transfer.hex");

        let output = rts_binary().arg("--json").arg(&hex).output().expect("Failed to execute rts binary");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert!(report["compute_budget"]["compute_unit_limit_set"].as_bool().unwrap());
        assert_eq!(report["compute_budget"]["compute_unit_limit"], serde_json::Value::Number(150000.into()));
        assert_eq!(report["compute_budget"]["compute_unit_price"], serde_json::Value::Number(5000.into()));
    }

    /// Pipe transaction bytes via stdin.
    #[test]
    fn test_cli_decode_stdin() {
        let hex = read_fixture_hex("system_transfer.hex");

        let mut child = rts_binary()
            .arg("--json")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to spawn rts binary");

        {
            let stdin = child.stdin.as_mut().expect("Failed to open stdin");
            stdin.write_all(hex.as_bytes()).expect("Failed to write to stdin");
        }

        let output = child.wait_with_output().expect("Failed to wait on rts");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(report["status"], "DECODED SUCCESSFULLY");
    }

    /// Verify --output-tx-report writes a file consumable by sat.
    #[test]
    fn test_cli_output_tx_report() {
        let hex = read_fixture_hex("system_transfer.hex");
        let report_path = "tests/fixtures/_e2e_tx_report.json";

        let output = rts_binary()
            .arg("--json")
            .arg("--output-tx-report")
            .arg(report_path)
            .arg(&hex)
            .output()
            .expect("Failed to execute rts binary");

        assert!(output.status.success());

        let report_json = std::fs::read_to_string(report_path).expect("Tx report file not written");
        let report: serde_json::Value = serde_json::from_str(&report_json).unwrap();
        assert_eq!(report["schema_version"], "1.0");
        assert!(report["transaction"]["signatures"].as_array().unwrap().len() >= 1);
        assert!(report["accounts"].as_array().unwrap().len() >= 2);

        // Cleanup
        let _ = std::fs::remove_file(report_path);
    }

    /// Verify the terminal dashboard exits successfully (non-JSON mode).
    #[test]
    fn test_cli_terminal_output() {
        let hex = read_fixture_hex("system_transfer.hex");

        let output = rts_binary().arg(&hex).output().expect("Failed to execute rts binary");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("SOLANA TRANSACTION FORENSICS REPORT"));
        assert!(stdout.contains("System Program"));
        assert!(stdout.contains("DECODED SUCCESSFULLY"));
    }

    /// Verify --validate-decoding flag does not crash.
    #[test]
    fn test_cli_validate_decoding() {
        let hex = read_fixture_hex("system_transfer.hex");

        let output = rts_binary()
            .arg("--json")
            .arg("--validate-decoding")
            .arg(&hex)
            .output()
            .expect("Failed to execute rts binary");

        assert!(output.status.success());
    }

    /// Verify --no-network flag.
    #[test]
    fn test_cli_no_network() {
        let hex = read_fixture_hex("system_transfer.hex");

        let output = rts_binary().arg("--no-network").arg(&hex).output().expect("Failed to execute rts binary");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("--no-network"));
    }

    /// Verify error handling on invalid input.
    #[test]
    fn test_cli_invalid_input_handling() {
        let output = rts_binary().arg("not-a-valid-transaction").output().expect("Failed to execute rts binary");

        assert!(!output.status.success());
    }
}
