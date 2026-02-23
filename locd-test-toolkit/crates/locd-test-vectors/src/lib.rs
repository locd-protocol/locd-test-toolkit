//! Golden test vectors for the Loc'd Protocol.
//!
//! This crate provides comprehensive test vectors for cross-implementation validation
//! of the Loc'd Protocol. Test vectors include:
//!
//! - **Cryptographic primitives**: Ed25519, X25519, ChaCha20-Poly1305, HKDF, Base64url
//! - **Key hierarchy**: Master, Device, and Session keys with known seeds
//! - **Delegation tokens**: Valid and invalid token examples
//! - **DNS records**: Identity, Revocation, and Rotation record formats
//! - **Verification protocol**: Complete challenge-response flows
//!
//! ## Usage
//!
//! Generate a complete test vector suite:
//!
//! ```rust
//! use locd_test_vectors::generate_suite;
//!
//! let suite = generate_suite();
//! println!("Protocol version: {}", suite.version);
//! println!("Ed25519 test cases: {}", suite.crypto.ed25519.len());
//! ```
//!
//! Export to JSON for use in other implementations:
//!
//! ```rust,no_run
//! use locd_test_vectors::{generate_suite, export_to_json_file};
//!
//! let suite = generate_suite();
//! export_to_json_file(&suite, "test-vectors.json").unwrap();
//! ```
//!
//! ## Test Vector Format
//!
//! All test vectors are deterministic (using known seeds) to enable
//! bit-exact reproduction across different implementations and platforms.
//!
//! ### Encoding
//!
//! - Binary data: Hex strings (lowercase)
//! - Public keys: Hex strings (32 bytes = 64 hex chars)
//! - Signatures: Hex strings (64 bytes = 128 hex chars)
//! - Base64url: No padding (RFC 4648 §5)
//! - CBOR: Hex-encoded binary
//!
//! ### Timestamps
//!
//! Unix timestamps (seconds since epoch) as u64.
//!
//! ## Versioning
//!
//! Test vectors are versioned to match protocol versions. Breaking changes
//! to the protocol require new test vector files.

pub mod generator;
pub mod types;

// Re-export main types
pub use generator::generate_suite;
pub use types::*;

use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Export test vector suite to JSON file
///
/// # Example
///
/// ```rust,no_run
/// use locd_test_vectors::{generate_suite, export_to_json_file};
///
/// let suite = generate_suite();
/// export_to_json_file(&suite, "locd-test-vectors-v0.1.0.json").unwrap();
/// ```
pub fn export_to_json_file<P: AsRef<Path>>(suite: &TestVectorSuite, path: P) -> Result<(), String> {
    let json = serde_json::to_string_pretty(suite)
        .map_err(|e| format!("JSON serialization failed: {}", e))?;

    let mut file =
        File::create(path.as_ref()).map_err(|e| format!("Failed to create file: {}", e))?;

    file.write_all(json.as_bytes())
        .map_err(|e| format!("Failed to write file: {}", e))?;

    Ok(())
}

/// Import test vector suite from JSON file
///
/// # Example
///
/// ```rust,no_run
/// use locd_test_vectors::import_from_json_file;
///
/// let suite = import_from_json_file("locd-test-vectors-v0.1.0.json").unwrap();
/// println!("Loaded {} Ed25519 test cases", suite.crypto.ed25519.len());
/// ```
pub fn import_from_json_file<P: AsRef<Path>>(path: P) -> Result<TestVectorSuite, String> {
    let file = File::open(path.as_ref()).map_err(|e| format!("Failed to open file: {}", e))?;

    let suite: TestVectorSuite =
        serde_json::from_reader(file).map_err(|e| format!("JSON deserialization failed: {}", e))?;

    Ok(suite)
}

/// Export test vector suite to JSON string
///
/// # Example
///
/// ```rust
/// use locd_test_vectors::{generate_suite, export_to_json_string};
///
/// let suite = generate_suite();
/// let json = export_to_json_string(&suite).unwrap();
/// assert!(json.contains("\"version\""));
/// ```
pub fn export_to_json_string(suite: &TestVectorSuite) -> Result<String, String> {
    serde_json::to_string_pretty(suite).map_err(|e| format!("JSON serialization failed: {}", e))
}

/// Import test vector suite from JSON string
///
/// # Example
///
/// ```rust
/// use locd_test_vectors::{generate_suite, export_to_json_string, import_from_json_string};
///
/// let suite1 = generate_suite();
/// let json = export_to_json_string(&suite1).unwrap();
/// let suite2 = import_from_json_string(&json).unwrap();
///
/// assert_eq!(suite1.version, suite2.version);
/// ```
pub fn import_from_json_string(json: &str) -> Result<TestVectorSuite, String> {
    serde_json::from_str(json).map_err(|e| format!("JSON deserialization failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_export() {
        let suite = generate_suite();
        let json = export_to_json_string(&suite).unwrap();

        assert!(json.contains("\"version\""));
        assert!(json.contains("\"crypto\""));
        assert!(json.contains("\"keys\""));
        assert!(json.contains("\"delegation\""));
        assert!(json.contains("\"dns\""));
        assert!(json.contains("\"verification\""));
    }

    #[test]
    fn test_roundtrip() {
        let suite1 = generate_suite();
        let json = export_to_json_string(&suite1).unwrap();
        let suite2 = import_from_json_string(&json).unwrap();

        assert_eq!(suite1.version, suite2.version);
        assert_eq!(suite1.crypto.ed25519.len(), suite2.crypto.ed25519.len());
        assert_eq!(suite1.keys.master_keys.len(), suite2.keys.master_keys.len());
    }

    #[test]
    fn test_deterministic_generation() {
        let suite1 = generate_suite();
        let suite2 = generate_suite();

        // Ed25519 keys from same seed should be identical
        assert_eq!(
            suite1.crypto.ed25519[0].public_key,
            suite2.crypto.ed25519[0].public_key
        );

        // Signatures from same seed and message should be identical
        assert_eq!(
            suite1.crypto.ed25519[0].signature,
            suite2.crypto.ed25519[0].signature
        );
    }

    #[test]
    fn test_json_schema_completeness() {
        let suite = generate_suite();
        let json = export_to_json_string(&suite).unwrap();

        // Verify all major sections are present
        assert!(json.contains("\"ed25519\""));
        assert!(json.contains("\"base64url\""));
        assert!(json.contains("\"master_keys\""));
        assert!(json.contains("\"device_keys\""));
        assert!(json.contains("\"session_keys\""));
        assert!(json.contains("\"tokens\""));
        assert!(json.contains("\"identity_records\""));
        assert!(json.contains("\"revocation_records\""));
        assert!(json.contains("\"flows\""));
        assert!(json.contains("\"hello_messages\""));
        assert!(json.contains("\"challenge_messages\""));
        assert!(json.contains("\"result_messages\""));
    }

    #[test]
    fn test_vector_counts() {
        let suite = generate_suite();

        // Crypto vectors
        assert!(
            suite.crypto.ed25519.len() >= 2,
            "Should have at least 2 Ed25519 test cases"
        );
        assert!(
            suite.crypto.base64url.len() >= 3,
            "Should have at least 3 Base64url test cases"
        );

        // Key vectors
        assert!(
            suite.keys.master_keys.len() >= 2,
            "Should have at least 2 master key cases"
        );
        assert!(
            suite.keys.device_keys.len() >= 2,
            "Should have at least 2 device key cases"
        );
        assert!(
            suite.keys.session_keys.len() >= 1,
            "Should have at least 1 session key case"
        );

        // Delegation vectors
        assert!(
            suite.delegation.tokens.len() >= 1,
            "Should have at least 1 delegation token case"
        );

        // DNS vectors
        assert!(
            suite.dns.identity_records.len() >= 2,
            "Should have at least 2 identity record cases"
        );
        assert!(
            suite.dns.revocation_records.len() >= 2,
            "Should have at least 2 revocation record cases"
        );

        // Verification vectors
        assert!(
            suite.verification.flows.len() >= 1,
            "Should have at least 1 verification flow"
        );
        assert!(suite.verification.messages.hello_messages.len() >= 1);
        assert!(suite.verification.messages.challenge_messages.len() >= 1);
        assert!(suite.verification.messages.result_messages.len() >= 2);
    }
}
