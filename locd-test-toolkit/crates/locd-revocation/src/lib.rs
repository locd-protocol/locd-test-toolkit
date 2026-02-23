//! Revocation checking for Loc'd Protocol delegation tokens.
//!
//! This crate implements the Revocation Layer from the Loc'd Protocol specification (§8).
//!
//! ## Overview
//!
//! The revocation system has three layers:
//!
//! 1. **Short-Lived Delegations (Primary)**: Default 24-hour expiry means compromised
//!    devices lose authority automatically even without active revocation.
//!
//! 2. **DNS Revocation Records (Authoritative)**: DNS TXT records at `_locd-revoke.<domain>`
//!    contain comma-separated lists of revoked delegation UUIDs. Verifiers MUST check during
//!    verification.
//!
//! 3. **Supplementary Revocation Lists (Fast)**: HTTPS-published signed JSON documents
//!    provide faster propagation than DNS. The URL is published in the identity record's
//!    `rev` field.
//!
//! ## Architecture
//!
//! - **DefaultRevocationChecker**: Async implementation with DNS and HTTPS support
//! - **BlockingRevocationChecker**: Synchronous wrapper using blocking Tokio runtime
//! - **RevocationCache**: Thread-safe TTL cache to minimize network queries
//! - **Data Sources**: DNS TXT records and HTTPS JSON endpoints
//!
//! ## Example
//!
//! ```rust,no_run
//! use locd_revocation::{BlockingRevocationChecker, SimpleRevocationChecker};
//! use locd_core::DelegationId;
//!
//! // Simple synchronous checker (no network access)
//! let checker = SimpleRevocationChecker::new();
//! let is_revoked = checker.is_revoked("example.com", &DelegationId::new()).unwrap();
//!
//! // Full checker with async support (requires tokio runtime)
//! let blocking_checker = BlockingRevocationChecker::new().unwrap();
//! let is_revoked = blocking_checker.is_revoked_blocking("example.com", &DelegationId::new()).unwrap();
//! ```
//!
//! ## DNS Record Format
//!
//! ```text
//! _locd-revoke.example.com. 300 IN TXT "v=locd-revoke1; ids=uuid1,uuid2,uuid3; t=1739577600"
//! ```
//!
//! ## HTTPS Supplementary List Format
//!
//! ```json
//! {
//!   "v": "locd-revoke-list-v1",
//!   "identity": "example.com",
//!   "revocations": [
//!     {
//!       "delegation_id": "550e8400-e29b-41d4-a716-446655440000",
//!       "revoked_at": 1739577600,
//!       "reason": "device_lost"
//!     }
//!   ],
//!   "published_at": 1739577660,
//!   "signature": "<base64url-Ed25519-signature>"
//! }
//! ```

pub mod cache;
pub mod checker;
pub mod sources;
pub mod types;

// Re-export main types
pub use cache::RevocationCache;
pub use checker::{
    BlockingRevocationChecker, DefaultRevocationChecker, HttpsUrlProvider, MasterKeyProvider,
};
pub use sources::{
    dns_record_to_cached_data, fetch_dns_revocations, fetch_https_revocations,
    parse_dns_revocation_record,
};
pub use types::{
    CachedRevocationData, RevocationEntry, RevocationList, RevocationReason, RevocationSource,
};

use locd_core::{DelegationId, Result};
use std::collections::HashSet;

/// Simple in-memory revocation checker for testing and basic use cases
///
/// This is a minimal implementation that doesn't perform network queries.
/// Use `DefaultRevocationChecker` or `BlockingRevocationChecker` for production.
pub struct SimpleRevocationChecker {
    revoked_ids: HashSet<String>,
}

impl SimpleRevocationChecker {
    /// Create a new checker with no revoked IDs
    pub fn new() -> Self {
        Self {
            revoked_ids: HashSet::new(),
        }
    }

    /// Create a checker with specific revoked delegation IDs
    pub fn with_revoked_ids(revoked_ids: Vec<DelegationId>) -> Self {
        let revoked_set = revoked_ids.iter().map(|id| id.to_string()).collect();
        Self {
            revoked_ids: revoked_set,
        }
    }

    /// Add a delegation ID to the revoked set
    pub fn revoke(&mut self, delegation_id: DelegationId) {
        self.revoked_ids.insert(delegation_id.to_string());
    }

    /// Check if a delegation is revoked (synchronous, no network access)
    pub fn is_revoked(&self, _domain: &str, delegation_id: &DelegationId) -> Result<bool> {
        Ok(self.revoked_ids.contains(&delegation_id.to_string()))
    }

    /// Clear all revocations
    pub fn clear(&mut self) {
        self.revoked_ids.clear();
    }

    /// Get number of revoked delegations
    pub fn len(&self) -> usize {
        self.revoked_ids.len()
    }

    /// Check if there are no revoked delegations
    pub fn is_empty(&self) -> bool {
        self.revoked_ids.is_empty()
    }
}

impl Default for SimpleRevocationChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_revocation_checker() {
        let mut checker = SimpleRevocationChecker::new();
        let domain = "example.com";

        let id1 = DelegationId::new();
        let id2 = DelegationId::new();

        // Initially not revoked
        assert!(!checker.is_revoked(domain, &id1).unwrap());
        assert!(!checker.is_revoked(domain, &id2).unwrap());

        // Revoke id1
        checker.revoke(id1.clone());
        assert!(checker.is_revoked(domain, &id1).unwrap());
        assert!(!checker.is_revoked(domain, &id2).unwrap());

        // Revoke id2
        checker.revoke(id2.clone());
        assert!(checker.is_revoked(domain, &id1).unwrap());
        assert!(checker.is_revoked(domain, &id2).unwrap());

        // Clear
        checker.clear();
        assert!(!checker.is_revoked(domain, &id1).unwrap());
        assert!(!checker.is_revoked(domain, &id2).unwrap());
    }

    #[test]
    fn test_simple_revocation_checker_with_initial_ids() {
        let id1 = DelegationId::new();
        let id2 = DelegationId::new();
        let id3 = DelegationId::new();

        let checker = SimpleRevocationChecker::with_revoked_ids(vec![id1.clone(), id2.clone()]);

        assert_eq!(checker.len(), 2);
        assert!(!checker.is_empty());

        assert!(checker.is_revoked("example.com", &id1).unwrap());
        assert!(checker.is_revoked("example.com", &id2).unwrap());
        assert!(!checker.is_revoked("example.com", &id3).unwrap());
    }

    #[test]
    fn test_simple_revocation_checker_len_empty() {
        let mut checker = SimpleRevocationChecker::new();
        assert_eq!(checker.len(), 0);
        assert!(checker.is_empty());

        checker.revoke(DelegationId::new());
        assert_eq!(checker.len(), 1);
        assert!(!checker.is_empty());

        checker.clear();
        assert_eq!(checker.len(), 0);
        assert!(checker.is_empty());
    }
}
