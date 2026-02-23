//! Key hierarchy types for the Loc'd Protocol
//!
//! Defines the three-tier key hierarchy:
//! - Tier 1: Master Key (phone secure enclave)
//! - Tier 2: Device Key (laptop/desktop TPM)
//! - Tier 3: Session Key (ephemeral, memory-only)

use serde::{Deserialize, Serialize};
use std::fmt;

/// Key tier in the Loc'd hierarchy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyTier {
    /// Tier 1: Master Key - The root of trust, stored in phone secure enclave
    Master,
    /// Tier 2: Device Key - Device-bound key, stored in TPM/secure enclave
    Device,
    /// Tier 3: Session Key - Ephemeral key for single connection, memory-only
    Session,
}

impl fmt::Display for KeyTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyTier::Master => write!(f, "master"),
            KeyTier::Device => write!(f, "device"),
            KeyTier::Session => write!(f, "session"),
        }
    }
}

/// Master Key (Tier 1) metadata
///
/// The Master Key represents the user's sovereign identity.
/// It is generated and stored in a phone's secure enclave and published to DNS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterKey {
    /// Ed25519 public key (32 bytes)
    pub public_key: Vec<u8>,
    /// Creation timestamp (Unix timestamp)
    pub created_at: u64,
    /// Optional expiry timestamp
    pub expires_at: Option<u64>,
    /// Optional revocation endpoint URL
    pub revocation_endpoint: Option<String>,
}

impl MasterKey {
    /// Create a new Master Key metadata
    pub fn new(
        public_key: Vec<u8>,
        created_at: u64,
        expires_at: Option<u64>,
        revocation_endpoint: Option<String>,
    ) -> Self {
        Self {
            public_key,
            created_at,
            expires_at,
            revocation_endpoint,
        }
    }

    /// Check if the key has expired
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at.map_or(false, |exp| now >= exp)
    }

    /// Get the tier of this key
    pub fn tier(&self) -> KeyTier {
        KeyTier::Master
    }
}

/// Device Key (Tier 2) metadata
///
/// Device Keys are generated in device TPMs/secure enclaves and authorized
/// by the Master Key via delegation tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceKey {
    /// Ed25519 public key (32 bytes)
    pub public_key: Vec<u8>,
    /// Device identifier (user-friendly name)
    pub device_id: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Optional TPM attestation data
    pub attestation: Option<Vec<u8>>,
}

impl DeviceKey {
    /// Create a new Device Key metadata
    pub fn new(
        public_key: Vec<u8>,
        device_id: String,
        created_at: u64,
        attestation: Option<Vec<u8>>,
    ) -> Self {
        Self {
            public_key,
            device_id,
            created_at,
            attestation,
        }
    }

    /// Get the tier of this key
    pub fn tier(&self) -> KeyTier {
        KeyTier::Device
    }
}

/// Session Key (Tier 3) metadata
///
/// Session Keys are ephemeral keys used for a single connection.
/// They exist only in memory and are never persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKey {
    /// Ed25519 public key (32 bytes)
    pub public_key: Vec<u8>,
    /// Session identifier
    pub session_id: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Expiry timestamp (typically short-lived, e.g., 1 hour)
    pub expires_at: u64,
}

impl SessionKey {
    /// Create a new Session Key metadata
    pub fn new(public_key: Vec<u8>, session_id: String, created_at: u64, expires_at: u64) -> Self {
        Self {
            public_key,
            session_id,
            created_at,
            expires_at,
        }
    }

    /// Check if the session key has expired
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Get the tier of this key
    pub fn tier(&self) -> KeyTier {
        KeyTier::Session
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_tier_display() {
        assert_eq!(KeyTier::Master.to_string(), "master");
        assert_eq!(KeyTier::Device.to_string(), "device");
        assert_eq!(KeyTier::Session.to_string(), "session");
    }

    #[test]
    fn test_master_key_expiry() {
        let key = MasterKey::new(vec![0u8; 32], 1000, Some(2000), None);
        assert!(!key.is_expired(1500));
        assert!(key.is_expired(2000));
        assert!(key.is_expired(2500));

        let no_expiry = MasterKey::new(vec![0u8; 32], 1000, None, None);
        assert!(!no_expiry.is_expired(9999999999));
    }

    #[test]
    fn test_session_key_expiry() {
        let key = SessionKey::new(vec![0u8; 32], "sess-123".to_string(), 1000, 2000);
        assert!(!key.is_expired(1500));
        assert!(key.is_expired(2000));
        assert!(key.is_expired(2500));
    }

    #[test]
    fn test_key_tiers() {
        let master = MasterKey::new(vec![0u8; 32], 0, None, None);
        assert_eq!(master.tier(), KeyTier::Master);

        let device = DeviceKey::new(vec![0u8; 32], "laptop".to_string(), 0, None);
        assert_eq!(device.tier(), KeyTier::Device);

        let session = SessionKey::new(vec![0u8; 32], "sess-1".to_string(), 0, 3600);
        assert_eq!(session.tier(), KeyTier::Session);
    }
}
