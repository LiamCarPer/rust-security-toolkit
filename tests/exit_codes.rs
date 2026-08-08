#[cfg(test)]
mod exit_code_tests {
    use solana_sdk::hash::Hash;
    use solana_sdk::instruction::{AccountMeta, Instruction};
    use solana_sdk::message::{VersionedMessage, legacy};
    use solana_sdk::pubkey::Pubkey;
    use solana_sdk::signature::Keypair;
    use solana_sdk::signer::Signer;
    use solana_sdk::transaction::VersionedTransaction;
    use solana_system_interface::instruction::SystemInstruction;
    use std::process::Command;
    use std::str::FromStr;

    const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";
    const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

    fn rts_binary() -> Command {
        let path =
            std::env::var("CARGO_BIN_EXE_rts").expect("CARGO_BIN_EXE_rts not set; binary must be compiled first");
        Command::new(path)
    }

    fn build_clean_transaction_hex() -> String {
        let payer = Keypair::new();
        let recipient = Pubkey::new_unique();
        let recent_blockhash = Hash::new_from_array([7u8; 32]);

        let mut cu_limit_data = vec![2u8];
        cu_limit_data.extend_from_slice(&300_000u32.to_le_bytes());

        let instructions = vec![
            Instruction {
                program_id: Pubkey::from_str(COMPUTE_BUDGET_PROGRAM_ID).unwrap(),
                accounts: vec![],
                data: cu_limit_data,
            },
            Instruction {
                program_id: Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap(),
                accounts: vec![AccountMeta::new(payer.pubkey(), true), AccountMeta::new_readonly(recipient, false)],
                data: bincode::serialize(&SystemInstruction::Transfer { lamports: 1_000_000 }).unwrap(),
            },
        ];

        let message = VersionedMessage::Legacy(legacy::Message::new_with_blockhash(
            &instructions,
            Some(&payer.pubkey()),
            &recent_blockhash,
        ));
        let tx = VersionedTransaction { signatures: vec![payer.sign_message(&message.serialize())], message };
        hex::encode(bincode::serialize(&tx).unwrap())
    }

    #[test]
    fn test_clean_transaction_exits_zero() {
        let tx_hex = build_clean_transaction_hex();
        let tx_path = std::env::temp_dir().join(format!("rts_exit_codes_clean_{}.hex", std::process::id()));
        std::fs::write(&tx_path, &tx_hex).expect("Failed to write temp transaction fixture");

        let output = rts_binary()
            .arg("--file")
            .arg(&tx_path)
            .arg("--no-network")
            .output()
            .expect("Failed to execute rts binary");

        let _ = std::fs::remove_file(&tx_path);
        assert_eq!(output.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    }

    #[test]
    fn test_missing_input_exits_one() {
        let output = rts_binary().output().expect("Failed to execute rts binary");

        assert_eq!(output.status.code(), Some(1));
    }
}
