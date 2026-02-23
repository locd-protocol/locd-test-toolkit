//! Data types for revocation records and lists.

use serde::{Deserialize, Serialize};

/// Revocation entry from HTTPS supplementary list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// The delegation ID that was revoked
    pub delegation_id: String,
    /// Unix timestamp when revoked
    pub revoked_at: u64,
    /// Reason for revocation
    pub reason: RevocationReason,
}

/// Reasons for revocation (spec §8.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// Physical device lost or stolen
    DeviceLost,
    /// Device suspected or confirmed compromised
    DeviceCompromised,
    /// Routine key rotation
    KeyRotation,
    /// Delegation scope reduced
    ScopeChange,
    /// User explicitly revoked
    UserInitiated,
}

/// HTTPS supplementary revocation list (spec §8.1)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationList {
    /// Protocol version
    pub v: String,
    /// Identity domain
    pub identity: String,
    /// List of revoked delegations
    pub revocations: Vec<RevocationEntry>,
    /// Unix timestamp when published
    pub published_at: u64,
    /// Ed25519 signature over canonical JSON (base64url)
    pub signature: String,
}

impl RevocationList {
    /// Verify the signature on this revocation list
    pub fn verify_signature(
        &self,
        public_key: &locd_crypto::Ed25519PublicKey,
    ) -> locd_core::Result<()> {
        // Create canonical JSON without signature field
        let canonical = serde_json::json!({
            "v": &self.v,
            "identity": &self.identity,
            "revocations": &self.revocations,
            "published_at": self.published_at,
        });

        let canonical_bytes = serde_json::to_vec(&canonical)
            .map_err(|e| locd_core::Error::Custom(format!("JSON serialization failed: {}", e)))?;

        // Decode signature from base64url
        let signature_bytes = locd_crypto::base64url_decode(&self.signature)
            .map_err(|e| locd_core::Error::Custom(format!("Invalid signature encoding: {}", e)))?;

        let signature = locd_crypto::Ed25519Signature::from_bytes(&signature_bytes)?;

        // Verify
        public_key.verify(&canonical_bytes, &signature)
    }
}

/// Cached revocation data
#[derive(Debug, Clone)]
pub struct CachedRevocationData {
    /// Set of revoked delegation IDs (UUID strings)
    pub revoked_ids: std::collections::HashSet<String>,
    /// Unix timestamp when this cache entry expires
    pub expires_at: u64,
    /// Source of this data
    pub source: RevocationSource,
}

/// Source of revocation data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationSource {
    /// DNS TXT record (authoritative)
    Dns,
    /// HTTPS supplementary list (fast)
    Https,
    /// Merged from multiple sources
    Merged,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_reason_serde() {
        let reason = RevocationReason::DeviceLost;
        let json = serde_json::to_string(&reason).unwrap();
        assert_eq!(json, "\"device_lost\"");

        let parsed: RevocationReason = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, reason);
    }

    #[test]
    fn test_revocation_entry_serde() {
        let entry = RevocationEntry {
            delegation_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            revoked_at: 1739577600,
            reason: RevocationReason::DeviceLost,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: RevocationEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.delegation_id, entry.delegation_id);
        assert_eq!(parsed.revoked_at, entry.revoked_at);
        assert_eq!(parsed.reason, entry.reason);
    }

    #[test]
    fn test_revocation_list_serde() {
        let list = RevocationList {
            v: "locd-revoke-list-v1".to_string(),
            identity: "example.com".to_string(),
            revocations: vec![RevocationEntry {
                delegation_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                revoked_at: 1739577600,
                reason: RevocationReason::DeviceLost,
            }],
            published_at: 1739577660,
            signature: "dGVzdC1zaWduYXR1cmU".to_string(),
        };

        let json = serde_json::to_string(&list).unwrap();
        let parsed: RevocationList = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.v, list.v);
        assert_eq!(parsed.identity, list.identity);
        assert_eq!(parsed.revocations.len(), 1);
        assert_eq!(parsed.published_at, list.published_at);
    }
}
