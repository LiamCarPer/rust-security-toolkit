use std::collections::HashMap;

use litesvm::LiteSVM;
use rts_replay::{diff_outcomes, execute};
use solana_address::Address;
use solana_hash::Hash;
use solana_keypair::Keypair;
use solana_message::{VersionedMessage, legacy};
use solana_signature::Signature;
use solana_signer::Signer;
use solana_system_interface::instruction::transfer;
use solana_transaction::versioned::VersionedTransaction;

fn build_transfer(
    payer: &Keypair,
    to: &Address,
    lamports: u64,
    blockhash: Hash,
    fake_signature: bool,
) -> VersionedTransaction {
    let from = Address::from(payer.pubkey());
    let instruction = transfer(&from, to, lamports);
    let message = VersionedMessage::Legacy(legacy::Message::new_with_blockhash(
        &[instruction],
        Some(&from),
        &blockhash,
    ));
    let signature =
        if fake_signature { Signature::default() } else { payer.sign_message(&message.serialize()) };
    VersionedTransaction { signatures: vec![signature], message }
}

fn svm_with_payer(payer: &Keypair) -> LiteSVM {
    let mut svm = LiteSVM::new().with_sigverify(false);
    svm.airdrop(&Address::from(payer.pubkey()), 10_000_000_000).expect("airdrop");
    svm
}

fn pre_state(payer: &Address, to: &Address) -> (HashMap<Address, u64>, HashMap<Address, Vec<u8>>) {
    let mut lamports = HashMap::new();
    lamports.insert(*payer, 10_000_000_000);
    lamports.insert(*to, 1_000_000);
    let mut data = HashMap::new();
    data.insert(*payer, Vec::new());
    data.insert(*to, Vec::new());
    (lamports, data)
}

#[test]
fn signed_transfer_executes_offline() {
    let payer = Keypair::new();
    let recipient = Address::new_unique();
    let mut svm = svm_with_payer(&payer);
    svm.airdrop(&recipient, 1_000_000).expect("fund recipient");
    let tx = build_transfer(&payer, &recipient, 1_000_000, svm.latest_blockhash(), false);
    let (lamports, data) = pre_state(&Address::from(payer.pubkey()), &recipient);

    let outcome = execute(&svm, &tx, &lamports, &data);
    assert!(outcome.success, "error: {:?} logs: {:?}", outcome.error, outcome.logs);
    let recipient_delta = outcome.sol_deltas.iter().find(|d| d.pubkey == recipient.to_string()).expect("recipient delta");
    assert_eq!(recipient_delta.delta, 1_000_000);
}

#[test]
fn sigverify_off_allows_unknown_signers() {
    let payer = Keypair::new();
    let recipient = Address::new_unique();
    let mut svm = svm_with_payer(&payer);
    svm.airdrop(&recipient, 1_000_000).expect("fund recipient");
    let tx = build_transfer(&payer, &recipient, 500_000, svm.latest_blockhash(), true);
    let (lamports, data) = pre_state(&Address::from(payer.pubkey()), &recipient);

    let outcome = execute(&svm, &tx, &lamports, &data);
    assert!(
        outcome.success,
        "replay with a default signature must still execute when sigverify is off; error: {:?}",
        outcome.error
    );
}

#[test]
fn mutation_changes_effects() {
    let payer = Keypair::new();
    let recipient = Address::new_unique();
    let mut svm = svm_with_payer(&payer);
    svm.airdrop(&recipient, 1_000_000).expect("fund recipient");
    let (lamports, data) = pre_state(&Address::from(payer.pubkey()), &recipient);

    let blockhash = svm.latest_blockhash();
    let original = execute(&svm, &build_transfer(&payer, &recipient, 1_000_000, blockhash, false), &lamports, &data);
    let mutated = execute(&svm, &build_transfer(&payer, &recipient, 2_000_000, blockhash, false), &lamports, &data);
    let delta = diff_outcomes(&original, &mutated);
    assert!(!delta.is_empty(), "amount mutation should change SOL deltas");
    assert!(delta.iter().any(|d| d.contains("SOL delta")), "deltas: {:?}", delta);
}

#[test]
fn undecodable_tx_bytes_are_rejected() {
    let svm = LiteSVM::new();
    let bytes = b"\x00\x01\x02";
    let tx_hex = hex::encode(bytes);
    assert!(bincode::deserialize::<VersionedTransaction>(&hex::decode(&tx_hex).unwrap()).is_err());
    let _ = svm;
}
