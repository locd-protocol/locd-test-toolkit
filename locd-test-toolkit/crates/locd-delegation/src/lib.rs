//! Delegation token creation and validation for the Loc'd Protocol
//!
//! This crate implements the delegation layer (spec §6) including:
//! - CBOR-encoded delegation tokens
//! - COSE Sign1 signature wrapping
//! - Constraint validation (services, actions, expiry, max uses)
//! - Delegation lifecycle management

use std::time::{SystemTime, UNIX_EPOCH};

pub mod token;
pub mod validator;

// Re-export commonly used items
pub use token::{DelegationToken, DelegationTokenBuilder};
pub use validator::{DelegationValidator, ValidationContext};

/// Get current Unix timestamp
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_timestamp() {
        let ts = current_timestamp();
        assert!(ts > 1700000000); // After Nov 2023
        assert!(ts < 2000000000); // Before May 2033
    }
}
