//! Key Derivation Functions

use hkdf::Hkdf;
use locd_core::{Error, Result};
use sha2::Sha256;

/// HKDF-SHA256 key derivation
///
/// Derives a key from input key material using HKDF-SHA256 (RFC 5869)
///
/// # Arguments
/// * `ikm` - Input key material
/// * `salt` - Optional salt (use empty slice if none)
/// * `info` - Context and application specific information
/// * `output_len` - Length of output key material
///
/// # Returns
/// Derived key material of specified length
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);

    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm)
        .map_err(|e| Error::crypto(format!("HKDF expansion failed: {}", e)))?;

    Ok(okm)
}

/// Derive an encryption key from a shared secret
///
/// This is a convenience wrapper around hkdf_sha256 for deriving
/// encryption keys from X25519 key agreement
pub fn derive_encryption_key(shared_secret: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    hkdf_sha256(
        shared_secret,
        b"locd-encryption-v1", // salt
        context,              // info
        32,                   // ChaCha20-Poly1305 key size
    )
}

/// Derive a MAC key from a shared secret
pub fn derive_mac_key(shared_secret: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    hkdf_sha256(
        shared_secret,
        b"locd-mac-v1", // salt
        context,        // info
        32,             // key size
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha256() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"context";

        let okm = hkdf_sha256(ikm, salt, info, 32).unwrap();
        assert_eq!(okm.len(), 32);

        // Same inputs produce same output
        let okm2 = hkdf_sha256(ikm, salt, info, 32).unwrap();
        assert_eq!(okm, okm2);

        // Different info produces different output
        let okm3 = hkdf_sha256(ikm, salt, b"different", 32).unwrap();
        assert_ne!(okm, okm3);
    }

    #[test]
    fn test_derive_encryption_key() {
        let shared_secret = b"shared secret from key agreement";
        let context = b"session-12345";

        let key1 = derive_encryption_key(shared_secret, context).unwrap();
        assert_eq!(key1.len(), 32);

        // Same inputs produce same key
        let key2 = derive_encryption_key(shared_secret, context).unwrap();
        assert_eq!(key1, key2);

        // Different context produces different key
        let key3 = derive_encryption_key(shared_secret, b"different").unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_derive_mac_key() {
        let shared_secret = b"shared secret";
        let context = b"session-id";

        let key = derive_mac_key(shared_secret, context).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_variable_output_length() {
        let ikm = b"test";
        let salt = b"";
        let info = b"";

        let okm16 = hkdf_sha256(ikm, salt, info, 16).unwrap();
        assert_eq!(okm16.len(), 16);

        let okm64 = hkdf_sha256(ikm, salt, info, 64).unwrap();
        assert_eq!(okm64.len(), 64);
    }
}
