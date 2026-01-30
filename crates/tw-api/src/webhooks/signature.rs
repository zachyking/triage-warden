//! Webhook signature validation.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Validates an HMAC-SHA256 signature.
///
/// Supports signatures in formats:
/// - Raw hex: `abc123...`
/// - Prefixed: `sha256=abc123...`
pub fn validate_signature(body: &[u8], signature: &str, secret: &str) -> bool {
    // Strip prefix if present
    let sig_hex = signature
        .strip_prefix("sha256=")
        .or_else(|| signature.strip_prefix("SHA256="))
        .unwrap_or(signature);

    // Decode hex signature
    let expected = match hex::decode(sig_hex) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    // Compute HMAC
    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };

    mac.update(body);

    // Constant-time comparison
    mac.verify_slice(&expected).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_signature() {
        let body = b"test payload";
        let secret = "webhook-secret";

        // Compute expected signature
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        let result = mac.finalize();
        let signature = hex::encode(result.into_bytes());

        assert!(validate_signature(body, &signature, secret));
        assert!(validate_signature(
            body,
            &format!("sha256={}", signature),
            secret
        ));
        assert!(validate_signature(
            body,
            &format!("SHA256={}", signature),
            secret
        ));

        // Invalid signature
        assert!(!validate_signature(body, "invalid", secret));
        assert!(!validate_signature(body, &signature, "wrong-secret"));
    }
}
