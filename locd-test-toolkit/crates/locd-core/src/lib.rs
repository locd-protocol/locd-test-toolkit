//! Core types and errors for the Loc'd Protocol
//!
//! This crate defines the foundational types used across the Loc'd Protocol
//! implementation, including key types, error handling, and protocol constants.

pub mod constants;
pub mod error;
pub mod keys;
pub mod types;

// Re-export commonly used items
pub use error::{Error, Result};
pub use keys::{DeviceKey, KeyTier, MasterKey, SessionKey};
pub use types::{DelegationId, IdentityDomain, ServicePattern};

/// Protocol version constant
pub const PROTOCOL_VERSION: &str = "locd1";

/// Delegation token type identifier
pub const DELEGATION_TYPE: &str = "locd-delegation-v1";

/// Revocation record type identifier
pub const REVOCATION_TYPE: &str = "locd-revoke1";

/// Key rotation record type identifier
pub const ROTATION_TYPE: &str = "locd-rotate1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(PROTOCOL_VERSION, "locd1");
        assert_eq!(DELEGATION_TYPE, "locd-delegation-v1");
    }
}
