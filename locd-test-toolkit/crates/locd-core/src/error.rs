//! Error types for the Loc'd Protocol

use thiserror::Error;

/// Result type alias using Loc'd Error
pub type Result<T> = std::result::Result<T, Error>;

/// Comprehensive error types for Loc'd Protocol operations
#[derive(Error, Debug)]
pub enum Error {
    /// Cryptographic operation failed
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Invalid key format or encoding
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Invalid delegation token
    #[error("Invalid delegation: {0}")]
    InvalidDelegation(String),

    /// Delegation has expired
    #[error("Delegation expired at {0}")]
    DelegationExpired(u64),

    /// Delegation has been revoked
    #[error("Delegation revoked: {0}")]
    DelegationRevoked(String),

    /// Service not permitted by delegation
    #[error("Service not permitted: {0}")]
    ServiceNotPermitted(String),

    /// Action not permitted by delegation
    #[error("Action not permitted: {0}")]
    ActionNotPermitted(String),

    /// Maximum uses exceeded
    #[error("Maximum uses ({0}) exceeded")]
    MaxUsesExceeded(u64),

    /// DNS lookup failed
    #[error("DNS error: {0}")]
    Dns(String),

    /// DNSSEC validation failed
    #[error("DNSSEC validation failed: {0}")]
    DnssecFailed(String),

    /// Identity record not found
    #[error("Identity not found: {0}")]
    IdentityNotFound(String),

    /// Invalid identity record format
    #[error("Invalid identity record: {0}")]
    InvalidIdentityRecord(String),

    /// Challenge-response verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Nonce mismatch
    #[error("Nonce mismatch")]
    NonceMismatch,

    /// Timestamp out of tolerance window
    #[error("Timestamp out of tolerance: {0}")]
    TimestampOutOfTolerance(u64),

    /// Encoding error (CBOR, COSE, Base64)
    #[error("Encoding error: {0}")]
    Encoding(String),

    /// Decoding error (CBOR, COSE, Base64)
    #[error("Decoding error: {0}")]
    Decoding(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid protocol version
    #[error("Invalid protocol version: expected {expected}, got {got}")]
    InvalidVersion { expected: String, got: String },

    /// Generic error with custom message
    #[error("{0}")]
    Custom(String),
}

impl Error {
    /// Create a custom error with a message
    pub fn custom(msg: impl Into<String>) -> Self {
        Error::Custom(msg.into())
    }

    /// Create a crypto error
    pub fn crypto(msg: impl Into<String>) -> Self {
        Error::Crypto(msg.into())
    }

    /// Create a DNS error
    pub fn dns(msg: impl Into<String>) -> Self {
        Error::Dns(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::DelegationExpired(1234567890);
        assert_eq!(err.to_string(), "Delegation expired at 1234567890");

        let err = Error::custom("test error");
        assert_eq!(err.to_string(), "test error");
    }

    #[test]
    fn test_result_type() {
        fn returns_result() -> Result<i32> {
            Ok(42)
        }
        assert_eq!(returns_result().unwrap(), 42);
    }
}
