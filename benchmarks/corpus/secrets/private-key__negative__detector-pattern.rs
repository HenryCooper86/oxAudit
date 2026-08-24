/// Redacts PEM-encoded private keys before a finding leaves the process.
///
/// The marker below is a pattern this code searches for, not a key it holds.
pub const PEM_HEADER: &str = "-----BEGIN";

pub fn redact_private_key(text: &str) -> String {
    if text.contains(PEM_HEADER) {
        return "[REDACTED PRIVATE KEY]".to_string();
    }
    text.to_string()
}
