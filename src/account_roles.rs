//! Static positional account-role annotation for well-known Solana programs.

use crate::types::{
    ASSOCIATED_TOKEN_PROGRAM_ID, DecodedInstruction, InnerInstruction, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID,
    TOKEN_PROGRAM_ID,
};

/// Fill `MappedAccount.name` for instructions from well-known programs using a
/// static positional role table. Only sets names that are still `None`.
pub fn annotate_known_program_roles(instructions: &mut [DecodedInstruction]) {
    for ix in instructions {
        let Some(instruction_name) = ix.instruction_name.as_deref() else {
            continue;
        };
        for (position, mapped) in ix.accounts.iter_mut().enumerate() {
            if mapped.name.is_none()
                && let Some(role) = known_program_role(&ix.program_id, instruction_name, position)
            {
                mapped.name = Some(role.to_string());
            }
        }
    }
}

pub fn annotate_inner_instruction_roles(instructions: &mut [InnerInstruction]) {
    for ix in instructions {
        let Some(instruction_name) = ix.instruction_name.as_deref() else {
            continue;
        };
        for (position, mapped) in ix.accounts.iter_mut().enumerate() {
            if mapped.name.is_none()
                && let Some(role) = known_program_role(&ix.program_id, instruction_name, position)
            {
                mapped.name = Some(role.to_string());
            }
        }
    }
}

/// Resolve the positional role for `(program_id, instruction_name, position)`.
/// Returns `None` for anything outside the static table.
fn known_program_role(program_id: &str, instruction_name: &str, position: usize) -> Option<&'static str> {
    match program_id {
        SYSTEM_PROGRAM_ID => system_program_role(instruction_name, position),
        TOKEN_PROGRAM_ID | TOKEN_2022_PROGRAM_ID => token_program_role(instruction_name, position),
        ASSOCIATED_TOKEN_PROGRAM_ID => associated_token_role(instruction_name, position),
        _ => None,
    }
}

/// System Program role table.
fn system_program_role(instruction_name: &str, position: usize) -> Option<&'static str> {
    match instruction_name {
        "CreateAccount" | "CreateAccountAllowPrefund" => match position {
            0 => Some("funding"),
            1 => Some("new_account"),
            _ => None,
        },
        "Assign" | "Allocate" => match position {
            0 => Some("account"),
            _ => None,
        },
        "Transfer" => match position {
            0 => Some("from"),
            1 => Some("to"),
            _ => None,
        },
        "CreateAccountWithSeed" => match position {
            0 => Some("funding"),
            1 => Some("created"),
            2 => Some("base"),
            _ => None,
        },
        "AdvanceNonceAccount" | "AuthorizeNonceAccount" | "UpgradeNonceAccount" => match position {
            0 => Some("nonce_account"),
            1 => Some("authorized"),
            _ => None,
        },
        "WithdrawNonceAccount" => match position {
            0 => Some("nonce_account"),
            1 => Some("authorized"),
            2 => Some("to"),
            _ => None,
        },
        "InitializeNonceAccount" => match position {
            0 => Some("nonce_account"),
            1 => Some("authorized"),
            2 => Some("rent_sysvar"),
            _ => None,
        },
        "AllocateWithSeed" | "AssignWithSeed" => match position {
            0 => Some("account"),
            1 => Some("base"),
            _ => None,
        },
        "TransferWithSeed" => match position {
            0 => Some("from"),
            1 => Some("from_base"),
            2 => Some("to"),
            _ => None,
        },
        _ => None,
    }
}

/// Token Program / Token-2022 shared role table.
fn token_program_role(instruction_name: &str, position: usize) -> Option<&'static str> {
    match instruction_name {
        // InitializeMint2 (Token-2022) omits the rent sysvar; mapping it anyway is harmless.
        "InitializeMint" | "InitializeMint2" => match position {
            0 => Some("mint"),
            1 => Some("rent"),
            _ => None,
        },
        // InitializeAccount2/3 (Token-2022) omit the rent sysvar; harmless if absent.
        "InitializeAccount" | "InitializeAccount2" | "InitializeAccount3" => match position {
            0 => Some("account"),
            1 => Some("mint"),
            2 => Some("owner"),
            3 => Some("rent"),
            _ => None,
        },
        "InitializeMultisig" | "InitializeMultisig2" => match position {
            0 => Some("multisig"),
            1 => Some("rent"),
            _ => Some("signer"),
        },
        "Transfer" => match position {
            0 => Some("source"),
            1 => Some("destination"),
            2 => Some("authority"),
            _ => None,
        },
        "Approve" => match position {
            0 => Some("source"),
            1 => Some("delegate"),
            2 => Some("owner"),
            _ => None,
        },
        "Revoke" => match position {
            0 => Some("source"),
            1 => Some("owner"),
            _ => None,
        },
        "SetAuthority" => match position {
            0 => Some("account"),
            1 => Some("current_authority"),
            _ => None,
        },
        "MintTo" | "MintToChecked" => match position {
            0 => Some("mint"),
            1 => Some("to"),
            2 => Some("authority"),
            _ => None,
        },
        "Burn" | "BurnChecked" => match position {
            0 => Some("source"),
            1 => Some("mint"),
            2 => Some("authority"),
            _ => None,
        },
        "CloseAccount" => match position {
            0 => Some("account"),
            1 => Some("destination"),
            2 => Some("owner"),
            _ => None,
        },
        "FreezeAccount" | "ThawAccount" => match position {
            0 => Some("account"),
            1 => Some("mint"),
            2 => Some("authority"),
            _ => None,
        },
        "TransferChecked" => match position {
            0 => Some("source"),
            1 => Some("mint"),
            2 => Some("destination"),
            3 => Some("authority"),
            _ => None,
        },
        "ApproveChecked" => match position {
            0 => Some("source"),
            1 => Some("mint"),
            2 => Some("delegate"),
            3 => Some("owner"),
            _ => None,
        },
        "SyncNative" | "InitializeImmutableOwner" => match position {
            0 => Some("account"),
            _ => None,
        },
        "AmountToUiAmount" | "UiAmountToAmount" | "GetAccountDataSize" => match position {
            0 => Some("mint"),
            _ => None,
        },
        "InitializePermanentDelegate" => match position {
            0 => Some("mint"),
            _ => None,
        },
        _ => None,
    }
}

/// Associated Token Program role table.
fn associated_token_role(instruction_name: &str, position: usize) -> Option<&'static str> {
    match instruction_name {
        "Create" => match position {
            0 => Some("payer"),
            1 => Some("associated_token_account"),
            2 => Some("wallet"),
            3 => Some("mint"),
            4 => Some("system_program"),
            5 => Some("token_program"),
            6 => Some("rent"),
            _ => None,
        },
        "CreateIdempotent" => match position {
            0 => Some("payer"),
            1 => Some("associated_token_account"),
            2 => Some("wallet"),
            3 => Some("mint"),
            4 => Some("system_program"),
            5 => Some("token_program"),
            _ => None,
        },
        "RecoverNested" => match position {
            0 => Some("nested_associated_token"),
            1 => Some("wallet"),
            2 => Some("mint"),
            3 => Some("nested_mint"),
            4 => Some("destination_associated_token"),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::MappedAccount;

    fn mapped(pubkey: &str) -> MappedAccount {
        MappedAccount { name: None, pubkey: pubkey.to_string(), account_index: 0, is_signer: false, is_writable: false }
    }

    fn named(pubkey: &str, name: &str) -> MappedAccount {
        MappedAccount { name: Some(name.to_string()), ..mapped(pubkey) }
    }

    fn instruction(program_id: &str, name: &str, accounts: Vec<MappedAccount>) -> DecodedInstruction {
        DecodedInstruction {
            index: 0,
            program_id: program_id.to_string(),
            program_name: String::new(),
            instruction_name: Some(name.to_string()),
            accounts,
            data: serde_json::Value::Null,
            raw_data_hex: String::new(),
            token_amount: None,
        }
    }

    #[test]
    fn system_transfer_gets_from_and_to() {
        let mut ix = instruction(SYSTEM_PROGRAM_ID, "Transfer", vec![mapped("alice"), mapped("bob")]);
        annotate_known_program_roles(std::slice::from_mut(&mut ix));
        assert_eq!(ix.accounts[0].name.as_deref(), Some("from"));
        assert_eq!(ix.accounts[1].name.as_deref(), Some("to"));
    }

    #[test]
    fn token_transfer_checked_gets_four_roles() {
        let mut ix = instruction(
            TOKEN_PROGRAM_ID,
            "TransferChecked",
            vec![mapped("source"), mapped("mint"), mapped("dest"), mapped("auth")],
        );
        annotate_known_program_roles(std::slice::from_mut(&mut ix));
        let names: Vec<_> = ix.accounts.iter().map(|a| a.name.as_deref()).collect();
        assert_eq!(names, [Some("source"), Some("mint"), Some("destination"), Some("authority")]);
    }

    #[test]
    fn unknown_program_or_instruction_leaves_names_none() {
        let mut unknown_program =
            instruction("UnknownProg111111111111111111111111111111", "Transfer", vec![mapped("a"), mapped("b")]);
        let mut unknown_instruction = instruction(SYSTEM_PROGRAM_ID, "NoSuchInstruction", vec![mapped("a")]);
        annotate_known_program_roles(std::slice::from_mut(&mut unknown_program));
        annotate_known_program_roles(std::slice::from_mut(&mut unknown_instruction));
        assert!(unknown_program.accounts.iter().all(|a| a.name.is_none()));
        assert!(unknown_instruction.accounts.iter().all(|a| a.name.is_none()));
    }

    #[test]
    fn existing_names_are_not_overwritten() {
        let mut ix = instruction(SYSTEM_PROGRAM_ID, "Transfer", vec![named("alice", "custom"), mapped("bob")]);
        annotate_known_program_roles(std::slice::from_mut(&mut ix));
        assert_eq!(ix.accounts[0].name.as_deref(), Some("custom"));
        assert_eq!(ix.accounts[1].name.as_deref(), Some("to"));
    }

    #[test]
    fn associated_token_create_position_zero_is_payer() {
        let mut ix = instruction(
            ASSOCIATED_TOKEN_PROGRAM_ID,
            "Create",
            vec![mapped("payer"), mapped("ata"), mapped("wallet"), mapped("mint")],
        );
        annotate_known_program_roles(std::slice::from_mut(&mut ix));
        assert_eq!(ix.accounts[0].name.as_deref(), Some("payer"));
        assert_eq!(ix.accounts[1].name.as_deref(), Some("associated_token_account"));
        assert_eq!(ix.accounts[2].name.as_deref(), Some("wallet"));
        assert_eq!(ix.accounts[3].name.as_deref(), Some("mint"));
    }
}
