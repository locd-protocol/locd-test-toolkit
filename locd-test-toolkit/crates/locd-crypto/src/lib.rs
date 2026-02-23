//! Cryptographic primitives for the Loc'd Protocol
//!
//! This crate provides RFC-compliant cryptographic operations including:
//! - Ed25519 signatures (RFC 8032)
//! - X25519 key agreement (RFC 7748)
//! - ChaCha20-Poly1305 AEAD
//! - XChaCha20-Poly1305 (for recovery)
//! - HKDF-SHA256 key derivation
//! - Argon2id password hashing

pub mod aead;
pub mod ed25519;
pub mod encoding;
pub mod kdf;
pub mod password;
pub mod x25519;

// Re-export commonly used items
pub use aead::{ChaCha20Poly1305, XChaCha20Poly1305};
pub use ed25519::{Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature};
pub use encoding::{base64url_decode, base64url_encode};
pub use kdf::hkdf_sha256;
pub use locd_core::{Error, Result};
pub use password::{hash_password, verify_password};
pub use x25519::{X25519KeyPair, X25519PublicKey, X25519SecretKey};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_roundtrip() {
        let keypair = Ed25519KeyPair::generate();
        let message = b"test message";
        let signature = keypair.sign(message);
        assert!(keypair.public_key().verify(message, &signature).is_ok());
    }

    #[test]
    fn test_x25519_key_agreement() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        let alice_shared = alice.key_agreement(&bob.public_key());
        let bob_shared = bob.key_agreement(&alice.public_key());

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_aead_roundtrip() {
        let key = ChaCha20Poly1305::generate_key();
        let plaintext = b"secret message";
        let aad = b"additional data";

        let (ciphertext, nonce) = ChaCha20Poly1305::encrypt(&key, plaintext, aad).unwrap();
        let decrypted = ChaCha20Poly1305::decrypt(&key, &ciphertext, &nonce, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_base64url_encoding() {
        let data = b"test data";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }
}
