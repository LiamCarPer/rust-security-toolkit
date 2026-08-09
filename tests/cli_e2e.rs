#[cfg(test)]
mod cli_e2e_tests {
    use solana_sdk::{
        hash::Hash,
        instruction::{AccountMeta, Instruction},
        message::{VersionedMessage, legacy},
        pubkey::Pubkey,
        signature::Keypair,
        signer::Signer,
        transaction::VersionedTransaction,
    };
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
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("Fixture not found: {}", path))
    }

    /// Decode a legacy transfer fixture via the CLI with --json output.
    #[test]
    fn test_cli_decode_legacy_json() {
        let hex = read_fixture_hex("system_transfer.hex");

        let output = rts_binary().arg("--json").arg(&hex).output().expect("Failed to execute rts binary");

        assert_eq!(
            output.status.code(),
            Some(2),
            "fixture carries a Critical Insecure Writable flag; severity exit code must be 2"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);

        let report: serde_json::Value = serde_json::from_str(&stdout).expect("rts --json output is not valid JSON");
        assert_eq!(report["status"], "DECODED SUCCESSFULLY");
        assert!(!report["instructions"].as_array().unwrap().is_empty());
        assert_eq!(report["instructions"][0]["program_name"], "System Program");
    }

    /// Decode a v0 transaction via the CLI.
    #[test]
    fn test_cli_decode_v0_json() {
        let hex = read_fixture_hex("v0_transfer.hex");

        let output = rts_binary().arg("--json").arg(&hex).output().expect("Failed to execute rts binary");

        assert_eq!(output.status.code(), Some(2), "v0 fixture also carries the Critical Insecure Writable flag");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(report["message_version"], serde_json::Value::Number(0.into()));
    }

    /// Decode a compute budget transaction via the CLI.
    #[test]
    fn test_cli_decode_cu_json() {
        let hex = read_fixture_hex("compute_budget_transfer.hex");

        let output = rts_binary().arg("--json").arg(&hex).output().expect("Failed to execute rts binary");

        assert_eq!(
            output.status.code(),
            Some(2),
            "fixture carries a Critical Insecure Writable flag; severity exit code must be 2"
        );
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
        assert_eq!(
            output.status.code(),
            Some(2),
            "fixture carries a Critical Insecure Writable flag; severity exit code must be 2"
        );
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

        assert_eq!(
            output.status.code(),
            Some(2),
            "fixture carries a Critical Insecure Writable flag; severity exit code must be 2"
        );

        let report_json = std::fs::read_to_string(report_path).expect("Tx report file not written");
        let report: serde_json::Value = serde_json::from_str(&report_json).unwrap();
        assert_eq!(report["schema_version"], "1.0");
        assert!(!report["transaction"]["signatures"].as_array().unwrap().is_empty());
        assert!(report["accounts"].as_array().unwrap().len() >= 2);

        // Cleanup
        let _ = std::fs::remove_file(report_path);
    }

    /// Verify the terminal dashboard exits successfully (non-JSON mode).
    #[test]
    fn test_cli_terminal_output() {
        let hex = read_fixture_hex("system_transfer.hex");

        let output = rts_binary().arg(&hex).output().expect("Failed to execute rts binary");

        assert_eq!(
            output.status.code(),
            Some(2),
            "fixture carries a Critical Insecure Writable flag; severity exit code must be 2"
        );
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

        assert_eq!(
            output.status.code(),
            Some(2),
            "fixture carries a Critical Insecure Writable flag; severity exit code must be 2"
        );
    }

    /// Verify --no-network flag.
    #[test]
    fn test_cli_no_network() {
        let hex = read_fixture_hex("system_transfer.hex");

        let output = rts_binary().arg("--no-network").arg(&hex).output().expect("Failed to execute rts binary");

        assert_eq!(
            output.status.code(),
            Some(2),
            "fixture carries a Critical Insecure Writable flag; severity exit code must be 2"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("--no-network"));
    }

    /// Verify error handling on invalid input.
    #[test]
    fn test_cli_invalid_input_handling() {
        let output = rts_binary().arg("not-a-valid-transaction").output().expect("Failed to execute rts binary");

        assert!(!output.status.success());
    }

    /// Decode raw binary transaction bytes via --file.
    #[test]
    fn test_cli_raw_binary_file() {
        let output = rts_binary()
            .arg("--json")
            .arg("--file")
            .arg("tests/fixtures/system_transfer.bin")
            .output()
            .expect("Failed to execute rts binary");

        assert_eq!(
            output.status.code(),
            Some(2),
            "fixture carries a Critical Insecure Writable flag; severity exit code must be 2"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: serde_json::Value = serde_json::from_str(&stdout).expect("rts --json output is not valid JSON");
        assert_eq!(report["status"], "DECODED SUCCESSFULLY");
        assert_eq!(report["instructions"][0]["program_name"], "System Program");
    }

    /// Pipe raw binary transaction bytes via stdin.
    #[test]
    fn test_cli_raw_binary_stdin() {
        let bytes = std::fs::read("tests/fixtures/system_transfer.bin").expect("read bin fixture");

        let mut child = rts_binary()
            .arg("--json")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to spawn rts binary");

        {
            let stdin = child.stdin.as_mut().expect("Failed to open stdin");
            stdin.write_all(&bytes).expect("Failed to write to stdin");
        }

        let output = child.wait_with_output().expect("Failed to wait on rts");
        assert_eq!(
            output.status.code(),
            Some(2),
            "fixture carries a Critical Insecure Writable flag; severity exit code must be 2"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: serde_json::Value = serde_json::from_str(&stdout).expect("rts --json output is not valid JSON");
        assert_eq!(report["status"], "DECODED SUCCESSFULLY");
    }

    // ── Native expectations CLI tests ────────────────────────────────────────

    /// Deterministic program id matching `tests/fixtures/native_expectations.json`.
    fn expectations_program_id() -> Pubkey {
        Pubkey::new_from_array([1u8; 32])
    }

    /// Serialize a single-instruction legacy transaction as hex.
    fn build_tx_hex(program_id: Pubkey, metas: Vec<AccountMeta>, data: Vec<u8>) -> String {
        let payer = Keypair::new();
        let recent_blockhash = Hash::new_from_array([7u8; 32]);
        let ix = Instruction { program_id, accounts: metas, data };
        let message = VersionedMessage::Legacy(legacy::Message::new_with_blockhash(
            &[ix],
            Some(&payer.pubkey()),
            &recent_blockhash,
        ));
        let tx = VersionedTransaction { signatures: vec![payer.sign_message(&message.serialize())], message };
        hex::encode(bincode::serialize(&tx).unwrap())
    }

    /// WithdrawMsrm metas: mango_group readonly, owner (signer per
    /// `owner_is_signer`, readonly like the real Mango shape), vault writable.
    fn msrm_metas(owner_is_signer: bool) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(Pubkey::new_unique(), owner_is_signer),
            AccountMeta::new(Pubkey::new_unique(), false),
        ]
    }

    fn risk_categories(json: &serde_json::Value) -> Vec<String> {
        json["risk_flags"]
            .as_array()
            .map(|flags| {
                flags.iter().filter_map(|f| f["category"].as_str().map(str::to_string)).collect::<Vec<String>>()
            })
            .unwrap_or_default()
    }

    /// Missing signer (owner not a signer) is a Critical flag: exit code 2 and
    /// the JSON report carries the MissingSigner entry.
    #[test]
    fn test_cli_expectations_flags_missing_signer() {
        let tx_hex = build_tx_hex(expectations_program_id(), msrm_metas(false), vec![0x24]);

        let output = rts_binary()
            .arg("--expectations")
            .arg("tests/fixtures/native_expectations.json")
            .arg("--json")
            .arg(&tx_hex)
            .output()
            .expect("Failed to execute rts binary");

        assert_eq!(output.status.code(), Some(2), "Critical MissingSigner must exit 2");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: serde_json::Value = serde_json::from_str(&stdout).expect("rts --json output is not valid JSON");
        let categories = risk_categories(&report);
        assert!(
            categories.iter().any(|c| c == "missing_signer"),
            "risk_flags must contain missing_signer, got: {:?}",
            categories
        );
    }

    /// A correct-signer WithdrawMsrm tx has no Critical flags; the missing
    /// compute budget warning (MissingComputeUnitLimit) drives the exit code
    /// to 1, and no MissingSigner/InsecureWritable flags are emitted.
    #[test]
    fn test_cli_expectations_clean_tx_exit_one() {
        let tx_hex = build_tx_hex(expectations_program_id(), msrm_metas(true), vec![0x24]);

        let output = rts_binary()
            .arg("--expectations")
            .arg("tests/fixtures/native_expectations.json")
            .arg("--json")
            .arg(&tx_hex)
            .output()
            .expect("Failed to execute rts binary");

        // No Critical flags, but the missing compute budget is a Warning:
        // severity exit code is 1 (not 0).
        assert_eq!(output.status.code(), Some(1), "clean tx must exit 1 (MissingComputeUnitLimit warning)");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: serde_json::Value = serde_json::from_str(&stdout).expect("rts --json output is not valid JSON");
        let categories = risk_categories(&report);
        assert!(
            !categories.iter().any(|c| c == "missing_signer"),
            "no MissingSigner on a correct-signer tx, got: {:?}",
            categories
        );
        assert!(
            !categories.iter().any(|c| c == "insecure_writable"),
            "no InsecureWritable on a clean tx, got: {:?}",
            categories
        );
    }

    /// `--idl` and `--expectations` conflict at clap parse time: non-zero exit
    /// and the clap-4 conflict wording on stderr.
    #[test]
    fn test_cli_idl_expectations_conflict() {
        let tx_hex = build_tx_hex(expectations_program_id(), msrm_metas(true), vec![0x24]);

        let output = rts_binary()
            .arg("--idl")
            .arg("tests/fixtures/system_transfer.hex")
            .arg("--expectations")
            .arg("tests/fixtures/native_expectations.json")
            .arg(&tx_hex)
            .output()
            .expect("Failed to execute rts binary");

        assert!(!output.status.success(), "clap must reject --idl + --expectations together");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("cannot be used with"), "clap conflict wording missing, stderr: {}", stderr);
    }

    /// A non-"native" source under --expectations bails with a clear error
    /// before any decoding happens.
    #[test]
    fn test_cli_expectations_rejects_non_native_source() {
        use std::io::Write;
        let path = std::env::temp_dir().join(format!("rts_non_native_{}.json", std::process::id()));
        let mut f = std::fs::File::create(&path).expect("create temp file");
        f.write_all(b"{\"program_name\":\"p\",\"program_id\":null,\"source\":\"anchor\",\"instructions\":[]}")
            .expect("write temp file");
        let tx_hex = build_tx_hex(expectations_program_id(), msrm_metas(true), vec![0x24]);

        let output = rts_binary().arg("--expectations").arg(&path).arg(&tx_hex).output().expect("run rts");
        let _ = std::fs::remove_file(&path);

        assert_eq!(output.status.code(), Some(1), "non-native source must exit 1");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("requires a native expectations document"), "clear error expected, stderr: {}", stderr);
    }
}
