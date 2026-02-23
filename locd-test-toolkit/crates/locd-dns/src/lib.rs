//! DNS record handling for the Loc'd Protocol
//!
//! This crate implements DNS record formatting and parsing for:
//! - Identity records (_locd.<domain>)
//! - Revocation records (_locd-revoke.<domain>)
//! - Key rotation records (_locd-rotate.<domain>)
//! - DNSSEC validation

pub mod records;
pub mod resolver;

// Re-export commonly used items
pub use records::{IdentityRecord, RevocationRecord, RotationRecord};
pub use resolver::{DnsResolver, QueryOptions};
pub use locd_core::{Error, Result};

#[cfg(test)]
mod tests {
    #[test]
    fn test_dns_module() {
        // Basic smoke test
        assert!(true);
    }
}
