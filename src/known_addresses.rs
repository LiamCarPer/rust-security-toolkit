use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct KnownAddresses {
    map: BTreeMap<String, String>,
}

pub fn parse(json: &str) -> Result<KnownAddresses, String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("malformed known-addresses JSON: {}", e))?;
    let obj = value.as_object().ok_or("known-addresses JSON must be an object")?;
    let known_map = obj.get("known").ok_or("missing 'known' key")?;
    let known = known_map.as_object().ok_or("'known' must be an object")?;
    let mut map = BTreeMap::new();
    for (key, _value) in obj {
        if key != "known" {
            return Err(format!("unknown known-addresses key '{}'", key));
        }
    }
    for (pubkey, name) in known {
        let decoded =
            bs58::decode(pubkey).into_vec().map_err(|e| format!("invalid base58 pubkey '{}': {}", pubkey, e))?;
        if decoded.len() != 32 {
            return Err(format!("pubkey '{}' must decode to 32 bytes (got {})", pubkey, decoded.len()));
        }
        let name = name.as_str().ok_or(format!("name for '{}' must be a string", pubkey))?;
        if name.is_empty() {
            return Err(format!("name for '{}' must not be empty", pubkey));
        }
        map.insert(pubkey.clone(), name.to_string());
    }
    Ok(KnownAddresses { map })
}

impl KnownAddresses {
    pub fn name(&self, pubkey: &str) -> Option<&str> {
        self.map.get(pubkey).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_known_addresses() {
        let key = bs58::encode([7u8; 32]).into_string();
        let json = format!(r#"{{"known": {{"{}": "USDC Mint"}}}}"#, key);
        let parsed = parse(&json).expect("valid json parses");
        assert_eq!(parsed.name(&key), Some("USDC Mint"));
    }

    #[test]
    fn empty_known_is_ok() {
        let parsed = parse(r#"{"known": {}}"#).expect("empty known parses");
        assert!(parsed.name("anything").is_none());
    }

    #[test]
    fn rejects_invalid_base58_key() {
        assert!(parse(r#"{"known": {"!!!": "x"}}"#).is_err());
    }

    #[test]
    fn rejects_short_and_long_keys() {
        let short = bs58::encode([1u8; 16]).into_string();
        assert!(parse(&format!(r#"{{"known": {{"{}": "x"}}}}"#, short)).is_err());
        let long = bs58::encode([1u8; 40]).into_string();
        assert!(parse(&format!(r#"{{"known": {{"{}": "x"}}}}"#, long)).is_err());
    }

    #[test]
    fn rejects_empty_value() {
        let key = bs58::encode([3u8; 32]).into_string();
        assert!(parse(&format!(r#"{{"known": {{"{}": ""}}}}"#, key)).is_err());
    }

    #[test]
    fn rejects_non_string_value() {
        let key = bs58::encode([3u8; 32]).into_string();
        assert!(parse(&format!(r#"{{"known": {{"{}": 5}}}}"#, key)).is_err());
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        assert!(parse(r#"{"mints": {}}"#).is_err());
    }

    #[test]
    fn rejects_missing_known_key() {
        assert!(parse("{}").is_err());
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(parse("not json").is_err());
    }
}
