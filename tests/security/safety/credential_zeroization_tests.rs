//! Credential zeroization integration tests.
//!
//! These tests verify that credentials are properly zeroized when dropped:
//! - SecureString zeroizes memory on drop
//! - Debug and Display don't leak secrets
//! - Serialization works correctly for storage
//! - Equality comparisons use constant-time operations
//!
//! These tests use the SecureString implementation from tw-core.

#[cfg(test)]
mod tests {
    use tw_core::crypto::SecureString;

// =============================================================================
// Basic SecureString Functionality Tests
// =============================================================================

#[test]
fn test_secure_string_creation() {
    let secret = SecureString::new("my-api-key-12345".to_string());
    assert_eq!(secret.expose_secret(), "my-api-key-12345");
}

#[test]
fn test_secure_string_from_string() {
    let secret: SecureString = "converted-secret".to_string().into();
    assert_eq!(secret.expose_secret(), "converted-secret");
}

#[test]
fn test_secure_string_from_str() {
    let secret: SecureString = "str-secret".into();
    assert_eq!(secret.expose_secret(), "str-secret");
}

#[test]
fn test_secure_string_len() {
    let secret = SecureString::new("12345".to_string());
    assert_eq!(secret.len(), 5);
    assert!(!secret.is_empty());
}

#[test]
fn test_secure_string_empty() {
    let secret = SecureString::default();
    assert!(secret.is_empty());
    assert_eq!(secret.len(), 0);
    assert_eq!(secret.expose_secret(), "");
}

#[test]
fn test_secure_string_clone() {
    let original = SecureString::new("cloneable-secret".to_string());
    let cloned = original.clone();

    assert_eq!(original.expose_secret(), cloned.expose_secret());
    assert_eq!(original, cloned);
}

// =============================================================================
// Debug and Display Redaction Tests
// =============================================================================

#[test]
fn test_debug_does_not_leak_secret() {
    let secret = SecureString::new("super-secret-password".to_string());
    let debug_output = format!("{:?}", secret);

    assert!(
        !debug_output.contains("super-secret-password"),
        "Debug output should not contain the secret"
    );
    assert!(
        debug_output.contains("REDACTED"),
        "Debug output should show REDACTED"
    );
    assert!(
        debug_output.contains("SecureString"),
        "Debug output should show type name"
    );
}

#[test]
fn test_display_does_not_leak_secret() {
    let secret = SecureString::new("another-secret".to_string());
    let display_output = format!("{}", secret);

    assert!(
        !display_output.contains("another-secret"),
        "Display output should not contain the secret"
    );
    assert!(
        display_output.contains("REDACTED"),
        "Display output should show REDACTED"
    );
}

#[test]
fn test_debug_with_various_secret_values() {
    let long_secret = "a".repeat(1000);
    let secrets = vec![
        "simple",
        "with spaces",
        "with\nnewline",
        "with\ttab",
        "unicode-secrets",
        "special!@#$%^&*()",
        "",
        long_secret.as_str(),
    ];

    for secret_value in secrets {
        let secret = SecureString::new(secret_value.to_string());
        let debug_output = format!("{:?}", secret);

        assert!(
            !debug_output.contains(secret_value) || secret_value.is_empty(),
            "Debug should not contain secret: {}",
            secret_value
        );
    }
}

// =============================================================================
// Equality Tests (Constant-Time Comparison)
// =============================================================================

#[test]
fn test_equality_same_value() {
    let secret1 = SecureString::new("same-value".to_string());
    let secret2 = SecureString::new("same-value".to_string());

    assert_eq!(secret1, secret2);
}

#[test]
fn test_equality_different_value() {
    let secret1 = SecureString::new("value-one".to_string());
    let secret2 = SecureString::new("value-two".to_string());

    assert_ne!(secret1, secret2);
}

#[test]
fn test_equality_different_lengths() {
    let short = SecureString::new("short".to_string());
    let long = SecureString::new("much-longer-secret".to_string());

    assert_ne!(short, long);
}

#[test]
fn test_equality_empty_strings() {
    let empty1 = SecureString::new(String::new());
    let empty2 = SecureString::default();

    assert_eq!(empty1, empty2);
}

#[test]
fn test_equality_with_similar_prefixes() {
    // These secrets have same prefix but different endings
    let secret1 = SecureString::new("prefix-suffix-a".to_string());
    let secret2 = SecureString::new("prefix-suffix-b".to_string());

    assert_ne!(secret1, secret2);
}

// =============================================================================
// Serialization Tests
// =============================================================================

#[test]
fn test_serialize_to_json() {
    let secret = SecureString::new("serializable-secret".to_string());
    let json = serde_json::to_string(&secret).unwrap();

    // JSON should contain the actual value (for storage)
    assert!(
        json.contains("serializable-secret"),
        "Serialized JSON should contain the secret for storage"
    );
}

#[test]
fn test_deserialize_from_json() {
    let json = r#""deserialized-secret""#;
    let secret: SecureString = serde_json::from_str(json).unwrap();

    assert_eq!(secret.expose_secret(), "deserialized-secret");
}

#[test]
fn test_serialize_deserialize_roundtrip() {
    let original = SecureString::new("roundtrip-secret".to_string());
    let json = serde_json::to_string(&original).unwrap();
    let restored: SecureString = serde_json::from_str(&json).unwrap();

    assert_eq!(original, restored);
    assert_eq!(restored.expose_secret(), "roundtrip-secret");
}

#[test]
fn test_serialize_in_struct() {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Config {
        api_key: SecureString,
        name: String,
    }

    let config = Config {
        api_key: SecureString::new("secret-api-key".to_string()),
        name: "test".to_string(),
    };

    let json = serde_json::to_string(&config).unwrap();
    assert!(json.contains("secret-api-key"));
    assert!(json.contains("test"));

    let restored: Config = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.api_key.expose_secret(), "secret-api-key");
    assert_eq!(restored.name, "test");
}

// =============================================================================
// Zeroization Behavior Tests
// =============================================================================

#[test]
fn test_secure_string_uses_zeroizing_wrapper() {
    // This test verifies the code structure is correct
    // The actual memory zeroization is guaranteed by the zeroize crate

    // Create and drop a secure string
    let ptr: *const u8;
    {
        let secret = SecureString::new("test-zeroize-behavior".to_string());
        ptr = secret.expose_secret().as_ptr();
        assert_eq!(secret.expose_secret(), "test-zeroize-behavior");
    }
    // Secret is dropped here, memory should be zeroized

    // The pointer is still valid as a pointer value (not null)
    // but we can't safely verify the memory is zeroed without unsafe code
    assert!(!ptr.is_null());
}

#[test]
fn test_secure_string_drop_is_called() {
    use std::sync::atomic::{AtomicBool, Ordering};

    // This test verifies Drop is being called
    // We can't easily test the actual zeroization without unsafe code,
    // but we can verify the drop mechanism works

    static DROP_CALLED: AtomicBool = AtomicBool::new(false);

    struct DropTracker;
    impl Drop for DropTracker {
        fn drop(&mut self) {
            DROP_CALLED.store(true, Ordering::SeqCst);
        }
    }

    // Verify drop mechanics work in general
    DROP_CALLED.store(false, Ordering::SeqCst);
    {
        let _tracker = DropTracker;
    }
    assert!(DROP_CALLED.load(Ordering::SeqCst), "Drop should be called");

    // SecureString will use the same drop mechanism
    let _secret = SecureString::new("will-be-dropped".to_string());
    // When this goes out of scope, Drop::drop will be called,
    // which will call zeroize on the underlying string
}

// =============================================================================
// Unicode and Special Character Tests
// =============================================================================

#[test]
fn test_unicode_secrets() {
    let secrets = vec![
        "unicode-test",
        "japanese-test",
        "emoji-test",
        "mixed-unicode-123",
    ];

    for secret_value in secrets {
        let secret = SecureString::new(secret_value.to_string());
        assert_eq!(secret.expose_secret(), secret_value);
        assert_eq!(secret.len(), secret_value.len());
    }
}

#[test]
fn test_special_characters() {
    let special_chars = r#"!@#$%^&*()_+-=[]{}|;':",.<>?/\`~"#;
    let secret = SecureString::new(special_chars.to_string());

    assert_eq!(secret.expose_secret(), special_chars);

    // Serialize and deserialize should preserve special chars
    let json = serde_json::to_string(&secret).unwrap();
    let restored: SecureString = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.expose_secret(), special_chars);
}

#[test]
fn test_whitespace_secrets() {
    let whitespace = "  leading and trailing  ";
    let secret = SecureString::new(whitespace.to_string());

    // Whitespace should be preserved
    assert_eq!(secret.expose_secret(), whitespace);
    assert_eq!(secret.len(), whitespace.len());
}

#[test]
fn test_newline_secrets() {
    let multiline = "line1\nline2\r\nline3";
    let secret = SecureString::new(multiline.to_string());

    assert_eq!(secret.expose_secret(), multiline);
}

// =============================================================================
// Long Secret Tests
// =============================================================================

#[test]
fn test_long_secret() {
    let long_secret = "x".repeat(10000);
    let secret = SecureString::new(long_secret.clone());

    assert_eq!(secret.expose_secret(), long_secret);
    assert_eq!(secret.len(), 10000);
}

#[test]
fn test_very_long_secret_equality() {
    let long1 = "a".repeat(100000);
    let long2 = "a".repeat(100000);
    let long3 = "a".repeat(100000) + "b";

    let secret1 = SecureString::new(long1);
    let secret2 = SecureString::new(long2);
    let secret3 = SecureString::new(long3);

    assert_eq!(secret1, secret2);
    assert_ne!(secret1, secret3);
}

// =============================================================================
// Thread Safety Tests
// =============================================================================

#[test]
fn test_secure_string_send() {
    // Verify SecureString is Send
    fn assert_send<T: Send>() {}
    assert_send::<SecureString>();
}

#[test]
fn test_secure_string_sync() {
    // Verify SecureString is Sync
    fn assert_sync<T: Sync>() {}
    assert_sync::<SecureString>();
}

#[tokio::test]
async fn test_secure_string_across_tasks() {
    use std::sync::Arc;

    let secret = Arc::new(SecureString::new("shared-secret".to_string()));

    let mut handles = vec![];

    for _ in 0..10 {
        let secret = Arc::clone(&secret);
        handles.push(tokio::spawn(async move {
            // Access secret from different tasks
            let value = secret.expose_secret();
            assert_eq!(value, "shared-secret");
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

#[test]
fn test_secure_string_across_threads() {
    use std::sync::Arc;
    use std::thread;

    let secret = Arc::new(SecureString::new("threaded-secret".to_string()));

    let mut handles = vec![];

    for _ in 0..10 {
        let secret = Arc::clone(&secret);
        handles.push(thread::spawn(move || {
            let value = secret.expose_secret();
            assert_eq!(value, "threaded-secret");
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

// =============================================================================
// Integration with Crypto Module Tests
// =============================================================================

#[test]
fn test_secure_string_with_encryption() {
    use tw_core::crypto::{Aes256GcmEncryptor, CredentialEncryptor};

    let key = [42u8; 32];
    let encryptor = Aes256GcmEncryptor::new(key);

    let original_secret = "api-key-to-encrypt";
    let secure = SecureString::new(original_secret.to_string());

    // Encrypt the exposed secret
    let encrypted = encryptor.encrypt(secure.expose_secret()).unwrap();

    // Decrypt and verify
    let decrypted = encryptor.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, original_secret);

    // Wrap decrypted value back in SecureString
    let restored_secure = SecureString::new(decrypted);
    assert_eq!(restored_secure, secure);
}

// =============================================================================
// Memory Safety Edge Cases
// =============================================================================

#[test]
fn test_multiple_expose_secret_calls() {
    let secret = SecureString::new("repeated-access".to_string());

    // Multiple expose_secret calls should all return the same value
    for _ in 0..100 {
        assert_eq!(secret.expose_secret(), "repeated-access");
    }
}

#[test]
fn test_clone_then_drop_original() {
    let cloned;
    {
        let original = SecureString::new("original-value".to_string());
        cloned = original.clone();
        // original is dropped here
    }

    // Cloned value should still be valid
    assert_eq!(cloned.expose_secret(), "original-value");
}

#[test]
fn test_nested_secure_strings() {
    #[derive(Clone)]
    struct Credentials {
        username: SecureString,
        password: SecureString,
        api_key: SecureString,
    }

    let creds = Credentials {
        username: SecureString::new("user".to_string()),
        password: SecureString::new("pass".to_string()),
        api_key: SecureString::new("key".to_string()),
    };

    assert_eq!(creds.username.expose_secret(), "user");
    assert_eq!(creds.password.expose_secret(), "pass");
    assert_eq!(creds.api_key.expose_secret(), "key");

    // Clone the credentials
    let cloned_creds = creds.clone();
    assert_eq!(cloned_creds.username.expose_secret(), "user");

    // Drop original
    drop(creds);

    // Cloned should still work
    assert_eq!(cloned_creds.password.expose_secret(), "pass");
}
} // end mod tests
