//! valutx-secret-broker
//!
//! Brokered secret management and redaction.
//! Ensures raw credentials never enter model prompts, traces, or logs.

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Handle pointing to a vaulted secret by reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    /// Opaque identifier.
    pub id: String,
    /// Redacted placeholder token.
    pub placeholder: String,
}

/// Redacts sensitive patterns and secret tokens from strings.
pub fn redact_text(input: &str, secrets: &[&str]) -> String {
    let mut result = input.to_string();
    for secret in secrets {
        if !secret.is_empty() {
            result = result.replace(secret, "[REDACTED_SECRET]");
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redaction() {
        let text = "connecting with token=super_secret_12345 to host";
        let cleaned = redact_text(text, &["super_secret_12345"]);
        assert_eq!(cleaned, "connecting with token=[REDACTED_SECRET] to host");
    }
}
