//! Core protocol types for the Loc'd Protocol

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Delegation identifier (UUID v4)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DelegationId(Uuid);

impl DelegationId {
    /// Create a new random delegation ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Parse a delegation ID from a string
    pub fn from_string(s: &str) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(s)?))
    }

    /// Get the inner UUID
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Convert to string representation
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl Default for DelegationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DelegationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for DelegationId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

/// Identity domain (DNS name)
///
/// Represents either a user-owned domain (e.g., "example.com") or a
/// cooperative namespace entry (e.g., "username.id.locd.net")
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityDomain(String);

impl IdentityDomain {
    /// Create a new identity domain
    pub fn new(domain: impl Into<String>) -> Self {
        Self(domain.into())
    }

    /// Get the domain as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the DNS record name for identity lookup
    ///
    /// Returns "_locd.<domain>"
    pub fn identity_record_name(&self) -> String {
        format!("_locd.{}", self.0)
    }

    /// Get the DNS record name for revocation list
    ///
    /// Returns "_locd-revoke.<domain>"
    pub fn revocation_record_name(&self) -> String {
        format!("_locd-revoke.{}", self.0)
    }

    /// Get the DNS record name for key rotation
    ///
    /// Returns "_locd-rotate.<domain>"
    pub fn rotation_record_name(&self) -> String {
        format!("_locd-rotate.{}", self.0)
    }

    /// Check if this is a cooperative namespace domain
    pub fn is_cooperative_namespace(&self) -> bool {
        self.0.ends_with(".id.locd.net")
    }
}

impl fmt::Display for IdentityDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for IdentityDomain {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for IdentityDomain {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Service pattern for delegation scope
///
/// Supports wildcard patterns like "*.example.com" or exact matches
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServicePattern(String);

impl ServicePattern {
    /// Create a new service pattern
    pub fn new(pattern: impl Into<String>) -> Self {
        Self(pattern.into())
    }

    /// Get the pattern as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if a service matches this pattern
    pub fn matches(&self, service: &str) -> bool {
        if self.0 == "*" {
            // Match all services
            true
        } else if let Some(suffix) = self.0.strip_prefix("*.") {
            // Wildcard subdomain match
            service.ends_with(suffix) || service == suffix
        } else {
            // Exact match
            self.0 == service
        }
    }
}

impl fmt::Display for ServicePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for ServicePattern {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for ServicePattern {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Action pattern for delegation scope
///
/// Represents permitted actions like "read", "write", "delete", etc.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionPattern(String);

impl ActionPattern {
    /// Create a new action pattern
    pub fn new(pattern: impl Into<String>) -> Self {
        Self(pattern.into())
    }

    /// Get the pattern as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if an action matches this pattern
    pub fn matches(&self, action: &str) -> bool {
        if self.0 == "*" {
            // Match all actions
            true
        } else {
            // Exact match
            self.0 == action
        }
    }
}

impl fmt::Display for ActionPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for ActionPattern {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for ActionPattern {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegation_id() {
        let id1 = DelegationId::new();
        let id2 = DelegationId::new();
        assert_ne!(id1, id2);

        let id_str = id1.to_string();
        let id_parsed = DelegationId::from_string(&id_str).unwrap();
        assert_eq!(id1, id_parsed);
    }

    #[test]
    fn test_identity_domain() {
        let domain = IdentityDomain::new("example.com");
        assert_eq!(domain.as_str(), "example.com");
        assert_eq!(domain.identity_record_name(), "_locd.example.com");
        assert_eq!(domain.revocation_record_name(), "_locd-revoke.example.com");
        assert_eq!(domain.rotation_record_name(), "_locd-rotate.example.com");
        assert!(!domain.is_cooperative_namespace());

        let coop = IdentityDomain::new("alice.id.locd.net");
        assert!(coop.is_cooperative_namespace());
    }

    #[test]
    fn test_service_pattern_matching() {
        let exact = ServicePattern::new("api.example.com");
        assert!(exact.matches("api.example.com"));
        assert!(!exact.matches("other.example.com"));

        let wildcard = ServicePattern::new("*.example.com");
        assert!(wildcard.matches("api.example.com"));
        assert!(wildcard.matches("web.example.com"));
        assert!(wildcard.matches("example.com"));
        assert!(!wildcard.matches("example.org"));

        let all = ServicePattern::new("*");
        assert!(all.matches("anything.com"));
        assert!(all.matches("example.org"));
    }

    #[test]
    fn test_action_pattern_matching() {
        let exact = ActionPattern::new("read");
        assert!(exact.matches("read"));
        assert!(!exact.matches("write"));

        let all = ActionPattern::new("*");
        assert!(all.matches("read"));
        assert!(all.matches("write"));
        assert!(all.matches("anything"));
    }
}
