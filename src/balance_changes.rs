use std::collections::HashMap;

use crate::inner_instructions::full_key_list;
use crate::simulator::format_ui_amount;
use crate::types::{
    FetchedTxMeta, SolBalanceChange, TokenAmount, TokenBalanceChange, TokenBalanceDto, TransactionReport,
};

pub fn annotate_report(report: &mut TransactionReport, meta: FetchedTxMeta) -> Vec<String> {
    let mut warnings = Vec::new();
    annotate_sol_balances(report, &meta, &mut warnings);
    annotate_token_balances(report, &meta, &mut warnings);
    warnings
}

fn annotate_sol_balances(report: &mut TransactionReport, meta: &FetchedTxMeta, warnings: &mut Vec<String>) {
    if meta.pre_balances.is_empty() && meta.post_balances.is_empty() {
        return;
    }
    if meta.pre_balances.len() != meta.post_balances.len() {
        warnings.push(format!(
            "pre/post balance length mismatch ({} vs {})",
            meta.pre_balances.len(),
            meta.post_balances.len()
        ));
        return;
    }
    let keys = full_key_list(report, meta);
    for (index, (&pre, &post)) in meta.pre_balances.iter().zip(meta.post_balances.iter()).enumerate() {
        if pre == post {
            continue;
        }
        let pubkey = resolve_pubkey(&keys, index, warnings);
        report.balance_changes_sol.push(SolBalanceChange {
            account_index: index as u8,
            pubkey,
            pre,
            post,
            delta: post as i64 - pre as i64,
        });
    }
}

fn annotate_token_balances(report: &mut TransactionReport, meta: &FetchedTxMeta, warnings: &mut Vec<String>) {
    if meta.pre_token_balances.is_empty() && meta.post_token_balances.is_empty() {
        return;
    }
    let pre_map = token_map(&meta.pre_token_balances);
    let post_map = token_map(&meta.post_token_balances);
    let mut keys: Vec<(u8, String)> = pre_map.keys().chain(post_map.keys()).cloned().collect();
    keys.sort();
    keys.dedup();
    let full_keys = full_key_list(report, meta);
    for (account_index, mint) in keys {
        let pre_entry = pre_map.get(&(account_index, mint.clone()));
        let post_entry = post_map.get(&(account_index, mint.clone()));
        let Some(pre_raw) = parse_entry_amount(pre_entry, warnings) else {
            continue;
        };
        let Some(post_raw) = parse_entry_amount(post_entry, warnings) else {
            continue;
        };
        let decimals =
            pre_entry.map(|(_, decimals)| *decimals).or_else(|| post_entry.map(|(_, decimals)| *decimals)).unwrap_or(0);
        let delta_raw = (post_raw as i128).wrapping_sub(pre_raw as i128);
        if delta_raw == 0 {
            continue;
        }
        let pubkey = resolve_pubkey(&full_keys, account_index as usize, warnings);
        report.token_balance_changes.push(TokenBalanceChange {
            account_index,
            pubkey,
            mint,
            pre: to_token_amount(pre_raw, decimals),
            post: to_token_amount(post_raw, decimals),
            delta_raw,
            delta_human: format_delta_human(delta_raw, decimals),
        });
    }
}

fn token_map(balances: &[TokenBalanceDto]) -> HashMap<(u8, String), (String, u8)> {
    let mut map = HashMap::new();
    for balance in balances {
        map.insert(
            (balance.account_index, balance.mint.clone()),
            (balance.ui_token_amount.amount.clone(), balance.ui_token_amount.decimals),
        );
    }
    map
}

fn parse_entry_amount(entry: Option<&(String, u8)>, warnings: &mut Vec<String>) -> Option<u128> {
    let amount = entry.map(|(amount, _)| amount.as_str()).unwrap_or("");
    match parse_amount(amount) {
        Some(raw) => Some(raw),
        None => {
            warnings.push("non-numeric token balance amount".to_string());
            None
        }
    }
}

fn parse_amount(amount: &str) -> Option<u128> {
    if amount.is_empty() { Some(0) } else { amount.parse::<u128>().ok() }
}

fn to_token_amount(raw: u128, decimals: u8) -> Option<TokenAmount> {
    u64::try_from(raw).ok().map(|raw| TokenAmount { raw, decimals, human: format_ui_amount(raw, decimals) })
}

fn format_delta_human(delta: i128, decimals: u8) -> String {
    let sign = if delta < 0 { "-" } else { "" };
    let magnitude = delta.unsigned_abs();
    let digits = match u64::try_from(magnitude) {
        Ok(mag) => format_ui_amount(mag, decimals),
        Err(_) => magnitude.to_string(),
    };
    format!("{sign}{digits}")
}

fn resolve_pubkey(keys: &[String], index: usize, warnings: &mut Vec<String>) -> String {
    match keys.get(index) {
        Some(pubkey) => pubkey.clone(),
        None => {
            warnings.push(format!("balance change for account #{index} is outside the message key list"));
            "unknown".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AccountInfo, FetchedTxLoadedAddresses, UiTokenAmountDto};

    fn account(index: u8, pubkey: &str) -> AccountInfo {
        AccountInfo {
            index,
            pubkey: pubkey.to_string(),
            is_signer: false,
            is_writable: false,
            role: None,
            pda_info: None,
        }
    }

    fn report_with_accounts(accounts: Vec<AccountInfo>) -> TransactionReport {
        TransactionReport {
            status: "ok".to_string(),
            fee_payer: "fee_payer".to_string(),
            signatures: Vec::new(),
            recent_blockhash: String::new(),
            message_version: None,
            accounts,
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
        }
    }

    fn token_balance(account_index: u8, mint: &str, amount: &str, decimals: u8) -> TokenBalanceDto {
        TokenBalanceDto {
            account_index,
            mint: mint.to_string(),
            ui_token_amount: UiTokenAmountDto {
                amount: amount.to_string(),
                decimals,
                ui_amount: None,
                ui_amount_string: None,
            },
        }
    }

    fn meta_with_balances(
        pre: Vec<u64>,
        post: Vec<u64>,
        pre_token: Vec<TokenBalanceDto>,
        post_token: Vec<TokenBalanceDto>,
    ) -> FetchedTxMeta {
        FetchedTxMeta {
            inner_instructions: Vec::new(),
            loaded_addresses: None,
            error: None,
            units_consumed: None,
            pre_balances: pre,
            post_balances: post,
            pre_token_balances: pre_token,
            post_token_balances: post_token,
        }
    }

    #[test]
    fn sol_deltas_recorded_for_changed_accounts() {
        let mut report = report_with_accounts(vec![account(0, "a"), account(1, "b"), account(2, "c")]);
        let meta = meta_with_balances(vec![1000, 500, 0], vec![990, 600, 0], Vec::new(), Vec::new());

        let warnings = annotate_report(&mut report, meta);
        assert!(warnings.is_empty());
        assert_eq!(report.balance_changes_sol.len(), 2);
        assert_eq!(report.balance_changes_sol[0].account_index, 0);
        assert_eq!(report.balance_changes_sol[0].pubkey, "a");
        assert_eq!(report.balance_changes_sol[0].pre, 1000);
        assert_eq!(report.balance_changes_sol[0].post, 990);
        assert_eq!(report.balance_changes_sol[0].delta, -10);
        assert_eq!(report.balance_changes_sol[1].account_index, 1);
        assert_eq!(report.balance_changes_sol[1].pubkey, "b");
        assert_eq!(report.balance_changes_sol[1].pre, 500);
        assert_eq!(report.balance_changes_sol[1].post, 600);
        assert_eq!(report.balance_changes_sol[1].delta, 100);
        assert!(!report.balance_changes_sol.iter().any(|c| c.account_index == 2));
    }

    #[test]
    fn sol_mismatched_lengths_warn() {
        let mut report = report_with_accounts(vec![account(0, "a"), account(1, "b")]);
        let meta = meta_with_balances(vec![1, 2], vec![1, 2, 3], Vec::new(), Vec::new());

        let warnings = annotate_report(&mut report, meta);
        assert!(warnings.iter().any(|w| w.contains("length")));
        assert!(report.balance_changes_sol.is_empty());
    }

    #[test]
    fn token_deltas_merged_by_account_and_mint() {
        let mut report = report_with_accounts(vec![account(0, "a"), account(1, "b"), account(2, "c")]);
        let meta = meta_with_balances(
            Vec::new(),
            Vec::new(),
            vec![token_balance(2, "mintA", "1500000", 6)],
            vec![token_balance(2, "mintA", "1000000", 6)],
        );

        let warnings = annotate_report(&mut report, meta);
        assert!(warnings.is_empty());
        assert_eq!(report.token_balance_changes.len(), 1);
        let change = &report.token_balance_changes[0];
        assert_eq!(change.account_index, 2);
        assert_eq!(change.pubkey, "c");
        assert_eq!(change.mint, "mintA");
        assert_eq!(change.delta_raw, -500_000);
        assert_eq!(change.delta_human, "-0.5");
        let pre = change.pre.as_ref().expect("pre amount");
        assert_eq!(pre.raw, 1_500_000);
        assert_eq!(pre.decimals, 6);
        assert_eq!(pre.human, "1.5");
        let post = change.post.as_ref().expect("post amount");
        assert_eq!(post.raw, 1_000_000);
        assert_eq!(post.decimals, 6);
        assert_eq!(post.human, "1");
    }

    #[test]
    fn token_zero_delta_skipped() {
        let mut report = report_with_accounts(vec![account(0, "a")]);
        let meta = meta_with_balances(
            Vec::new(),
            Vec::new(),
            vec![token_balance(0, "mintA", "500", 2)],
            vec![token_balance(0, "mintA", "500", 2)],
        );

        let warnings = annotate_report(&mut report, meta);
        assert!(warnings.is_empty());
        assert!(report.token_balance_changes.is_empty());
    }

    #[test]
    fn token_non_numeric_amount_warned() {
        let mut report = report_with_accounts(vec![account(0, "a")]);
        let meta = meta_with_balances(
            Vec::new(),
            Vec::new(),
            vec![token_balance(0, "mintA", "abc", 2)],
            vec![token_balance(0, "mintA", "10", 2)],
        );

        let warnings = annotate_report(&mut report, meta);
        assert!(warnings.iter().any(|w| w.contains("non-numeric")));
        assert!(report.token_balance_changes.is_empty());
    }

    #[test]
    fn token_delta_exceeding_u64_keeps_raw() {
        let mut report = report_with_accounts(vec![account(0, "a")]);
        let meta = meta_with_balances(
            Vec::new(),
            Vec::new(),
            vec![token_balance(0, "mintA", "340282366920938463463374607431768211455", 6)],
            vec![token_balance(0, "mintA", "18446744073709551616", 6)],
        );

        let warnings = annotate_report(&mut report, meta);
        assert!(warnings.is_empty());
        assert_eq!(report.token_balance_changes.len(), 1);
        let change = &report.token_balance_changes[0];
        assert!(change.pre.is_none());
        assert!(change.post.is_none());
        assert_eq!(change.delta_raw, 18_446_744_073_709_551_617);
        assert_eq!(change.delta_human, "18446744073709551617");
    }

    #[test]
    fn out_of_range_account_index_warned() {
        let mut report = report_with_accounts(vec![account(0, "a")]);
        let meta = meta_with_balances(
            Vec::new(),
            Vec::new(),
            vec![token_balance(99, "mintA", "100", 0)],
            vec![token_balance(99, "mintA", "0", 0)],
        );

        let warnings = annotate_report(&mut report, meta);
        assert!(warnings.iter().any(|w| w.contains("outside the message key list")));
        assert_eq!(report.token_balance_changes.len(), 1);
        assert_eq!(report.token_balance_changes[0].pubkey, "unknown");
        assert_eq!(report.token_balance_changes[0].account_index, 99);
    }

    #[test]
    fn empty_meta_no_warnings() {
        let mut report = report_with_accounts(Vec::new());
        let meta = meta_with_balances(Vec::new(), Vec::new(), Vec::new(), Vec::new());

        let warnings = annotate_report(&mut report, meta);
        assert!(warnings.is_empty());
        assert!(report.balance_changes_sol.is_empty());
        assert!(report.token_balance_changes.is_empty());
    }

    #[test]
    fn loaded_address_resolution() {
        let mut report = report_with_accounts(Vec::new());
        let mut meta = meta_with_balances(
            Vec::new(),
            Vec::new(),
            vec![token_balance(0, "mintA", "5", 0)],
            vec![token_balance(0, "mintA", "0", 0)],
        );
        meta.loaded_addresses =
            Some(FetchedTxLoadedAddresses { writable: vec!["loaded_writable_key".to_string()], readonly: Vec::new() });

        let warnings = annotate_report(&mut report, meta);
        assert!(warnings.is_empty());
        assert_eq!(report.token_balance_changes.len(), 1);
        assert_eq!(report.token_balance_changes[0].pubkey, "loaded_writable_key");
    }
}
