/// Offline cryptographic signature verification (Tier B+).
///
/// Verifies each required signer's ed25519 signature against the serialized
/// message. Stub to be implemented.
pub fn verify_report(_report: &mut crate::types::TransactionReport) -> Vec<crate::types::RiskFlag> {
    Vec::new()
}
