//! Authenticated Encryption with Associated Data (AEAD)

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    ChaCha20Poly1305 as ChaCha20Poly1305Cipher,
    XChaCha20Poly1305 as XChaCha20Poly1305Cipher,
};
use locd_core::{Error, Result};

/// ChaCha20-Poly1305 AEAD operations
pub struct ChaCha20Poly1305;

impl ChaCha20Poly1305 {
    /// Generate a random key (32 bytes)
    pub fn generate_key() -> Vec<u8> {
        ChaCha20Poly1305Cipher::generate_key(&mut OsRng).to_vec()
    }

    /// Encrypt plaintext with associated data
    ///
    /// Returns (ciphertext, nonce)
    pub fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if key.len() != 32 {
            return Err(Error::crypto(format!(
                "Key must be 32 bytes, got {}",
                key.len()
            )));
        }

        let cipher = ChaCha20Poly1305Cipher::new_from_slice(key)
            .map_err(|e| Error::crypto(format!("Invalid key: {}", e)))?;

        let nonce = ChaCha20Poly1305Cipher::generate_nonce(&mut OsRng);

        let payload = Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|e| Error::crypto(format!("Encryption failed: {}", e)))?;

        Ok((ciphertext, nonce.to_vec()))
    }

    /// Decrypt ciphertext with associated data
    pub fn decrypt(key: &[u8], ciphertext: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 {
            return Err(Error::crypto(format!(
                "Key must be 32 bytes, got {}",
                key.len()
            )));
        }

        if nonce.len() != 12 {
            return Err(Error::crypto(format!(
                "Nonce must be 12 bytes, got {}",
                nonce.len()
            )));
        }

        let cipher = ChaCha20Poly1305Cipher::new_from_slice(key)
            .map_err(|e| Error::crypto(format!("Invalid key: {}", e)))?;

        let nonce_array = nonce.try_into()
            .map_err(|_| Error::crypto("Invalid nonce length"))?;

        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        let plaintext = cipher
            .decrypt(nonce_array, payload)
            .map_err(|e| Error::crypto(format!("Decryption failed: {}", e)))?;

        Ok(plaintext)
    }
}

/// XChaCha20-Poly1305 AEAD operations (for recovery)
pub struct XChaCha20Poly1305;

impl XChaCha20Poly1305 {
    /// Generate a random key (32 bytes)
    pub fn generate_key() -> Vec<u8> {
        XChaCha20Poly1305Cipher::generate_key(&mut OsRng).to_vec()
    }

    /// Encrypt plaintext with associated data
    ///
    /// Returns (ciphertext, nonce)
    pub fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if key.len() != 32 {
            return Err(Error::crypto(format!(
                "Key must be 32 bytes, got {}",
                key.len()
            )));
        }

        let cipher = XChaCha20Poly1305Cipher::new_from_slice(key)
            .map_err(|e| Error::crypto(format!("Invalid key: {}", e)))?;

        let nonce = XChaCha20Poly1305Cipher::generate_nonce(&mut OsRng);

        let payload = Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|e| Error::crypto(format!("Encryption failed: {}", e)))?;

        Ok((ciphertext, nonce.to_vec()))
    }

    /// Decrypt ciphertext with associated data
    pub fn decrypt(key: &[u8], ciphertext: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 {
            return Err(Error::crypto(format!(
                "Key must be 32 bytes, got {}",
                key.len()
            )));
        }

        if nonce.len() != 24 {
            return Err(Error::crypto(format!(
                "Nonce must be 24 bytes, got {}",
                nonce.len()
            )));
        }

        let cipher = XChaCha20Poly1305Cipher::new_from_slice(key)
            .map_err(|e| Error::crypto(format!("Invalid key: {}", e)))?;

        let nonce_array = nonce.try_into()
            .map_err(|_| Error::crypto("Invalid nonce length"))?;

        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        let plaintext = cipher
            .decrypt(nonce_array, payload)
            .map_err(|e| Error::crypto(format!("Decryption failed: {}", e)))?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20poly1305_roundtrip() {
        let key = ChaCha20Poly1305::generate_key();
        assert_eq!(key.len(), 32);

        let plaintext = b"secret message";
        let aad = b"additional data";

        let (ciphertext, nonce) = ChaCha20Poly1305::encrypt(&key, plaintext, aad).unwrap();
        assert_eq!(nonce.len(), 12);
        assert!(ciphertext.len() > plaintext.len()); // includes auth tag

        let decrypted = ChaCha20Poly1305::decrypt(&key, &ciphertext, &nonce, aad).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_chacha20poly1305_wrong_key() {
        let key1 = ChaCha20Poly1305::generate_key();
        let key2 = ChaCha20Poly1305::generate_key();

        let plaintext = b"secret";
        let aad = b"";

        let (ciphertext, nonce) = ChaCha20Poly1305::encrypt(&key1, plaintext, aad).unwrap();

        let result = ChaCha20Poly1305::decrypt(&key2, &ciphertext, &nonce, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_xchacha20poly1305_roundtrip() {
        let key = XChaCha20Poly1305::generate_key();
        assert_eq!(key.len(), 32);

        let plaintext = b"recovery data";
        let aad = b"metadata";

        let (ciphertext, nonce) = XChaCha20Poly1305::encrypt(&key, plaintext, aad).unwrap();
        assert_eq!(nonce.len(), 24); // XChaCha uses 24-byte nonce

        let decrypted = XChaCha20Poly1305::decrypt(&key, &ciphertext, &nonce, aad).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_invalid_key_sizes() {
        let short_key = vec![0u8; 16];
        assert!(ChaCha20Poly1305::encrypt(&short_key, b"test", b"").is_err());
        assert!(XChaCha20Poly1305::encrypt(&short_key, b"test", b"").is_err());
    }
}
