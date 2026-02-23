//! DNS record formatting and parsing for Loc'd Protocol

use locd_core::{
    error::{Error, Result},
    types::IdentityDomain,
    PROTOCOL_VERSION, REVOCATION_TYPE, ROTATION_TYPE,
};
use locd_crypto::base64url_encode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Identity record (_locd.<domain>)
///
/// Format: v=locd1; k=ed25519; p=<base64url>; t=<timestamp>; [exp=<timestamp>]; [rev=<url>]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRecord {
    /// Protocol version (must be "locd1")
    pub version: String,
    /// Key algorithm (must be "ed25519")
    pub algorithm: String,
    /// Public key (base64url encoded, 32 bytes)
    pub public_key: String,
    /// Publication timestamp (Unix timestamp)
    pub timestamp: u64,
    /// Optional expiry timestamp
    pub expiry: Option<u64>,
    /// Optional revocation endpoint URL
    pub revocation_endpoint: Option<String>,
}

impl IdentityRecord {
    /// Create a new identity record
    pub fn new(public_key_bytes: &[u8], timestamp: u64) -> Self {
        Self {
            version: PROTOCOL_VERSION.to_string(),
            algorithm: "ed25519".to_string(),
            public_key: base64url_encode(public_key_bytes),
            timestamp,
            expiry: None,
            revocation_endpoint: None,
        }
    }

    /// Set expiry timestamp
    pub fn with_expiry(mut self, expiry: u64) -> Self {
        self.expiry = Some(expiry);
        self
    }

    /// Set revocation endpoint
    pub fn with_revocation_endpoint(mut self, url: impl Into<String>) -> Self {
        self.revocation_endpoint = Some(url.into());
        self
    }

    /// Format as DNS TXT record value
    pub fn to_txt_record(&self) -> String {
        let mut parts = vec![
            format!("v={}", self.version),
            format!("k={}", self.algorithm),
            format!("p={}", self.public_key),
            format!("t={}", self.timestamp),
        ];

        if let Some(exp) = self.expiry {
            parts.push(format!("exp={}", exp));
        }

        if let Some(ref rev) = self.revocation_endpoint {
            parts.push(format!("rev={}", rev));
        }

        parts.join("; ")
    }

    /// Parse from DNS TXT record value
    pub fn from_txt_record(txt: &str) -> Result<Self> {
        let fields = parse_txt_fields(txt)?;

        // Validate version
        let version = fields
            .get("v")
            .ok_or_else(|| Error::InvalidIdentityRecord("Missing version".to_string()))?;
        if version != PROTOCOL_VERSION {
            return Err(Error::InvalidVersion {
                expected: PROTOCOL_VERSION.to_string(),
                got: version.clone(),
            });
        }

        // Validate algorithm
        let algorithm = fields
            .get("k")
            .ok_or_else(|| Error::InvalidIdentityRecord("Missing algorithm".to_string()))?;
        if algorithm != "ed25519" {
            return Err(Error::InvalidIdentityRecord(format!(
                "Unsupported algorithm: {}",
                algorithm
            )));
        }

        let public_key = fields
            .get("p")
            .ok_or_else(|| Error::InvalidIdentityRecord("Missing public key".to_string()))?
            .clone();

        let timestamp = fields
            .get("t")
            .ok_or_else(|| Error::InvalidIdentityRecord("Missing timestamp".to_string()))?
            .parse::<u64>()
            .map_err(|_| Error::InvalidIdentityRecord("Invalid timestamp".to_string()))?;

        let expiry = fields.get("exp").and_then(|s| s.parse::<u64>().ok());

        let revocation_endpoint = fields.get("rev").cloned();

        Ok(Self {
            version: version.clone(),
            algorithm: algorithm.clone(),
            public_key,
            timestamp,
            expiry,
            revocation_endpoint,
        })
    }

    /// Get the DNS record name for this domain
    pub fn record_name(domain: &IdentityDomain) -> String {
        domain.identity_record_name()
    }
}

/// Revocation record (_locd-revoke.<domain>)
///
/// Format: v=locd-revoke1; ids=<uuid1>,<uuid2>,...; t=<timestamp>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRecord {
    /// Protocol version
    pub version: String,
    /// Revoked delegation IDs (UUIDs)
    pub revoked_ids: Vec<String>,
    /// Timestamp of revocation list
    pub timestamp: u64,
}

impl RevocationRecord {
    /// Create a new revocation record
    pub fn new(revoked_ids: Vec<String>, timestamp: u64) -> Self {
        Self {
            version: REVOCATION_TYPE.to_string(),
            revoked_ids,
            timestamp,
        }
    }

    /// Format as DNS TXT record value
    pub fn to_txt_record(&self) -> String {
        format!(
            "v={}; ids={}; t={}",
            self.version,
            self.revoked_ids.join(","),
            self.timestamp
        )
    }

    /// Parse from DNS TXT record value
    pub fn from_txt_record(txt: &str) -> Result<Self> {
        let fields = parse_txt_fields(txt)?;

        let version = fields
            .get("v")
            .ok_or_else(|| Error::InvalidIdentityRecord("Missing version".to_string()))?;
        if version != REVOCATION_TYPE {
            return Err(Error::InvalidVersion {
                expected: REVOCATION_TYPE.to_string(),
                got: version.clone(),
            });
        }

        let ids_str = fields
            .get("ids")
            .ok_or_else(|| Error::InvalidIdentityRecord("Missing IDs".to_string()))?;

        let revoked_ids: Vec<String> = if ids_str.is_empty() {
            Vec::new()
        } else {
            ids_str.split(',').map(|s| s.trim().to_string()).collect()
        };

        let timestamp = fields
            .get("t")
            .ok_or_else(|| Error::InvalidIdentityRecord("Missing timestamp".to_string()))?
            .parse::<u64>()
            .map_err(|_| Error::InvalidIdentityRecord("Invalid timestamp".to_string()))?;

        Ok(Self {
            version: version.clone(),
            revoked_ids,
            timestamp,
        })
    }

    /// Get the DNS record name for this domain
    pub fn record_name(domain: &IdentityDomain) -> String {
        domain.revocation_record_name()
    }
}

/// Key rotation record (_locd-rotate.<domain>)
///
/// Format: v=locd-rotate1; old=<base64url>; new=<base64url>; sig=<base64url>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationRecord {
    /// Protocol version
    pub version: String,
    /// Old public key (base64url)
    pub old_key: String,
    /// New public key (base64url)
    pub new_key: String,
    /// Signature of rotation (base64url)
    pub signature: String,
}

impl RotationRecord {
    /// Create a new rotation record
    pub fn new(old_key: String, new_key: String, signature: String) -> Self {
        Self {
            version: ROTATION_TYPE.to_string(),
            old_key,
            new_key,
            signature,
        }
    }

    /// Format as DNS TXT record value
    pub fn to_txt_record(&self) -> String {
        format!(
            "v={}; old={}; new={}; sig={}",
            self.version, self.old_key, self.new_key, self.signature
        )
    }

    /// Parse from DNS TXT record value
    pub fn from_txt_record(txt: &str) -> Result<Self> {
        let fields = parse_txt_fields(txt)?;

        let version = fields
            .get("v")
            .ok_or_else(|| Error::InvalidIdentityRecord("Missing version".to_string()))?;
        if version != ROTATION_TYPE {
            return Err(Error::InvalidVersion {
                expected: ROTATION_TYPE.to_string(),
                got: version.clone(),
            });
        }

        let old_key = fields
            .get("old")
            .ok_or_else(|| Error::InvalidIdentityRecord("Missing old key".to_string()))?
            .clone();

        let new_key = fields
            .get("new")
            .ok_or_else(|| Error::InvalidIdentityRecord("Missing new key".to_string()))?
            .clone();

        let signature = fields
            .get("sig")
            .ok_or_else(|| Error::InvalidIdentityRecord("Missing signature".to_string()))?
            .clone();

        Ok(Self {
            version: version.clone(),
            old_key,
            new_key,
            signature,
        })
    }

    /// Get the DNS record name for this domain
    pub fn record_name(domain: &IdentityDomain) -> String {
        domain.rotation_record_name()
    }
}

/// Parse semicolon-separated key=value fields from DNS TXT record
fn parse_txt_fields(txt: &str) -> Result<HashMap<String, String>> {
    let mut fields = HashMap::new();

    for part in txt.split(';') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(Error::InvalidIdentityRecord(format!(
                "Invalid field: {}",
                trimmed
            )));
        }

        fields.insert(parts[0].trim().to_string(), parts[1].trim().to_string());
    }

    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use locd_crypto::Ed25519KeyPair;

    #[test]
    fn test_identity_record_format() {
        let kp = Ed25519KeyPair::generate();
        let pub_key = kp.public_key().to_bytes();

        let record = IdentityRecord::new(&pub_key, 1234567890)
            .with_expiry(1234567900)
            .with_revocation_endpoint("https://example.com/.well-known/locd/revocations");

        let txt = record.to_txt_record();
        assert!(txt.contains("v=locd1"));
        assert!(txt.contains("k=ed25519"));
        assert!(txt.contains("t=1234567890"));
        assert!(txt.contains("exp=1234567900"));
        assert!(txt.contains("rev=https://example.com/.well-known/locd/revocations"));
    }

    #[test]
    fn test_identity_record_roundtrip() {
        let kp = Ed25519KeyPair::generate();
        let pub_key = kp.public_key().to_bytes();

        let record1 = IdentityRecord::new(&pub_key, 1234567890);
        let txt = record1.to_txt_record();
        let record2 = IdentityRecord::from_txt_record(&txt).unwrap();

        assert_eq!(record1.version, record2.version);
        assert_eq!(record1.algorithm, record2.algorithm);
        assert_eq!(record1.public_key, record2.public_key);
        assert_eq!(record1.timestamp, record2.timestamp);
    }

    #[test]
    fn test_revocation_record_format() {
        let record = RevocationRecord::new(
            vec!["abc-123".to_string(), "def-456".to_string()],
            1234567890,
        );

        let txt = record.to_txt_record();
        assert!(txt.contains("v=locd-revoke1"));
        assert!(txt.contains("ids=abc-123,def-456"));
        assert!(txt.contains("t=1234567890"));
    }

    #[test]
    fn test_revocation_record_roundtrip() {
        let record1 = RevocationRecord::new(
            vec!["id1".to_string(), "id2".to_string(), "id3".to_string()],
            9999999999,
        );

        let txt = record1.to_txt_record();
        let record2 = RevocationRecord::from_txt_record(&txt).unwrap();

        assert_eq!(record1.version, record2.version);
        assert_eq!(record1.revoked_ids, record2.revoked_ids);
        assert_eq!(record1.timestamp, record2.timestamp);
    }

    #[test]
    fn test_rotation_record() {
        let record = RotationRecord::new(
            "old_key_base64url".to_string(),
            "new_key_base64url".to_string(),
            "signature_base64url".to_string(),
        );

        let txt = record.to_txt_record();
        assert!(txt.contains("v=locd-rotate1"));
        assert!(txt.contains("old=old_key_base64url"));
        assert!(txt.contains("new=new_key_base64url"));
        assert!(txt.contains("sig=signature_base64url"));

        let parsed = RotationRecord::from_txt_record(&txt).unwrap();
        assert_eq!(record.old_key, parsed.old_key);
        assert_eq!(record.new_key, parsed.new_key);
        assert_eq!(record.signature, parsed.signature);
    }

    #[test]
    fn test_parse_txt_fields() {
        let fields = parse_txt_fields("a=1; b=2; c=3").unwrap();
        assert_eq!(fields.get("a"), Some(&"1".to_string()));
        assert_eq!(fields.get("b"), Some(&"2".to_string()));
        assert_eq!(fields.get("c"), Some(&"3".to_string()));

        // With extra whitespace
        let fields2 = parse_txt_fields(" a = 1 ; b = 2 ").unwrap();
        assert_eq!(fields2.get("a"), Some(&"1".to_string()));
        assert_eq!(fields2.get("b"), Some(&"2".to_string()));
    }

    #[test]
    fn test_invalid_version() {
        let result = IdentityRecord::from_txt_record("v=locd2; k=ed25519; p=test; t=123");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidVersion { .. }));
    }
}
