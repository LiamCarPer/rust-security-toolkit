//! Bundled well-known mainnet address labels (mints and headline accounts).
//! User-supplied `--known-addresses` entries take precedence over these.

pub fn label(pubkey: &str) -> Option<&'static str> {
    match pubkey {
        "So11111111111111111111111111111111111111112" => Some("wSOL"),
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" => Some("USDC"),
        "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB" => Some("USDT"),
        "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So" => Some("mSOL"),
        "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn" => Some("JitoSOL"),
        "bSo13r4TkiE4KumL71LsHTPpL2euBYLFx6h9HP3piy1" => Some("bSOL"),
        "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263" => Some("BONK"),
        "EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm" => Some("WIF"),
        "HZ1JovNiVvGrGNiiYvEozEVgZ58xaU3RKwX8eACQBCt3" => Some("PYTH"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_mints_are_labelled() {
        assert_eq!(label("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"), Some("USDC"));
        assert_eq!(label("So11111111111111111111111111111111111111112"), Some("wSOL"));
        assert_eq!(label("HZ1JovNiVvGrGNiiYvEozEVgZ58xaU3RKwX8eACQBCt3"), Some("PYTH"));
    }

    #[test]
    fn unknown_address_has_no_label() {
        assert_eq!(label("11111111111111111111111111111111"), None);
        assert_eq!(label("not-a-pubkey"), None);
    }
}
