//! Protocol constants for the Loc'd Protocol

/// Maximum delegation duration in seconds (30 days)
pub const MAX_DELEGATION_DURATION_SECS: u64 = 30 * 24 * 60 * 60;

/// Default delegation duration in seconds (24 hours)
pub const DEFAULT_DELEGATION_DURATION_SECS: u64 = 24 * 60 * 60;

/// Timestamp tolerance for challenge-response (60 seconds)
pub const TIMESTAMP_TOLERANCE_SECS: u64 = 60;

/// Ed25519 public key size in bytes
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 private key size in bytes
pub const ED25519_PRIVATE_KEY_SIZE: usize = 32;

/// Ed25519 signature size in bytes
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// X25519 public key size in bytes
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// X25519 private key size in bytes
pub const X25519_PRIVATE_KEY_SIZE: usize = 32;

/// ChaCha20-Poly1305 key size in bytes
pub const CHACHA20_POLY1305_KEY_SIZE: usize = 32;

/// ChaCha20-Poly1305 nonce size in bytes
pub const CHACHA20_POLY1305_NONCE_SIZE: usize = 12;

/// ChaCha20-Poly1305 tag size in bytes
pub const CHACHA20_POLY1305_TAG_SIZE: usize = 16;

/// XChaCha20-Poly1305 nonce size in bytes
pub const XCHACHA20_POLY1305_NONCE_SIZE: usize = 24;

/// Challenge nonce size in bytes
pub const CHALLENGE_NONCE_SIZE: usize = 32;

/// DNS TXT record TTL for active identity (seconds)
pub const DNS_IDENTITY_TTL: u32 = 300;

/// DNS TXT record TTL for revocation (seconds)
pub const DNS_REVOCATION_TTL: u32 = 60;

/// DNS TXT record prefix for identity records
pub const DNS_IDENTITY_PREFIX: &str = "_locd";

/// DNS TXT record prefix for revocation records
pub const DNS_REVOCATION_PREFIX: &str = "_locd-revoke";

/// DNS TXT record prefix for rotation records
pub const DNS_ROTATION_PREFIX: &str = "_locd-rotate";

/// Cooperative namespace domain
pub const COOPERATIVE_NAMESPACE: &str = "id.locd.net";

/// CBOR map key for delegation type
pub const CBOR_KEY_TYPE: i64 = 1;

/// CBOR map key for delegator public key
pub const CBOR_KEY_DELEGATOR: i64 = 2;

/// CBOR map key for delegate public key
pub const CBOR_KEY_DELEGATE: i64 = 3;

/// CBOR map key for issued-at timestamp
pub const CBOR_KEY_ISSUED_AT: i64 = 4;

/// CBOR map key for expires-at timestamp
pub const CBOR_KEY_EXPIRES_AT: i64 = 5;

/// CBOR map key for delegation ID
pub const CBOR_KEY_DELEGATION_ID: i64 = 6;

/// CBOR map key for services
pub const CBOR_KEY_SERVICES: i64 = 7;

/// CBOR map key for actions
pub const CBOR_KEY_ACTIONS: i64 = 8;

/// CBOR map key for max uses
pub const CBOR_KEY_MAX_USES: i64 = 9;

/// CBOR map key for device attestation
pub const CBOR_KEY_ATTESTATION: i64 = 10;

/// CBOR map key for can-sub-delegate
pub const CBOR_KEY_CAN_SUB_DELEGATE: i64 = 11;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_sizes() {
        assert_eq!(ED25519_PUBLIC_KEY_SIZE, 32);
        assert_eq!(ED25519_SIGNATURE_SIZE, 64);
        assert_eq!(X25519_PUBLIC_KEY_SIZE, 32);
    }

    #[test]
    fn test_delegation_durations() {
        assert_eq!(DEFAULT_DELEGATION_DURATION_SECS, 86400); // 24 hours
        assert_eq!(MAX_DELEGATION_DURATION_SECS, 2592000); // 30 days
    }

    #[test]
    fn test_dns_constants() {
        assert_eq!(DNS_IDENTITY_PREFIX, "_locd");
        assert_eq!(DNS_REVOCATION_PREFIX, "_locd-revoke");
        assert_eq!(COOPERATIVE_NAMESPACE, "id.locd.net");
    }
}
