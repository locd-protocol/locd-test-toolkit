//! Ed25519 signature operations (RFC 8032)

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use locd_core::{Error, Result};
use rand::rngs::OsRng;

/// Ed25519 key pair for signing
pub struct Ed25519KeyPair {
    signing_key: SigningKey,
}

impl Ed25519KeyPair {
    /// Generate a new random Ed25519 key pair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create a key pair from a secret key (32 bytes)
    pub fn from_secret_bytes(secret: &[u8]) -> Result<Self> {
        if secret.len() != 32 {
            return Err(Error::InvalidKey(format!(
                "Expected 32 bytes, got {}",
                secret.len()
            )));
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(secret);

        Ok(Self {
            signing_key: SigningKey::from_bytes(&bytes),
        })
    }

    /// Get the secret key bytes
    pub fn secret_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    /// Get the public key
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey {
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let signature = self.signing_key.sign(message);
        Ed25519Signature { signature }
    }

    /// Sign a message and return signature bytes
    pub fn sign_bytes(&self, message: &[u8]) -> Vec<u8> {
        self.sign(message).to_bytes()
    }
}

/// Ed25519 public key for verification
#[derive(Clone, Debug)]
pub struct Ed25519PublicKey {
    verifying_key: VerifyingKey,
}

impl Ed25519PublicKey {
    /// Create a public key from bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidKey(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);

        let verifying_key =
            VerifyingKey::from_bytes(&key_bytes).map_err(|e| Error::InvalidKey(e.to_string()))?;

        Ok(Self { verifying_key })
    }

    /// Get the public key bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<()> {
        self.verifying_key
            .verify(message, &signature.signature)
            .map_err(|e| Error::crypto(format!("Signature verification failed: {}", e)))
    }

    /// Verify a signature from bytes
    pub fn verify_bytes(&self, message: &[u8], signature_bytes: &[u8]) -> Result<()> {
        let signature = Ed25519Signature::from_bytes(signature_bytes)?;
        self.verify(message, &signature)
    }
}

/// Ed25519 signature (64 bytes)
#[derive(Clone, Debug)]
pub struct Ed25519Signature {
    signature: Signature,
}

impl Ed25519Signature {
    /// Create a signature from bytes (64 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(Error::crypto(format!(
                "Expected 64 bytes for signature, got {}",
                bytes.len()
            )));
        }

        let signature = Signature::from_slice(bytes)
            .map_err(|e| Error::crypto(format!("Invalid signature: {}", e)))?;

        Ok(Self { signature })
    }

    /// Get the signature bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.signature.to_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() {
        let kp = Ed25519KeyPair::generate();
        assert_eq!(kp.public_key().to_bytes().len(), 32);
        assert_eq!(kp.secret_bytes().len(), 32);
    }

    #[test]
    fn test_sign_verify() {
        let kp = Ed25519KeyPair::generate();
        let message = b"Hello, Loc'd!";

        let sig = kp.sign(message);
        assert_eq!(sig.to_bytes().len(), 64);

        assert!(kp.public_key().verify(message, &sig).is_ok());

        let wrong_message = b"Wrong message";
        assert!(kp.public_key().verify(wrong_message, &sig).is_err());
    }

    #[test]
    fn test_from_bytes() {
        let kp1 = Ed25519KeyPair::generate();
        let secret = kp1.secret_bytes();
        let public = kp1.public_key().to_bytes();

        let kp2 = Ed25519KeyPair::from_secret_bytes(&secret).unwrap();
        assert_eq!(kp2.public_key().to_bytes(), public);

        let pk = Ed25519PublicKey::from_bytes(&public).unwrap();
        assert_eq!(pk.to_bytes(), public);
    }

    #[test]
    fn test_sign_verify_bytes() {
        let kp = Ed25519KeyPair::generate();
        let message = b"test message";

        let sig_bytes = kp.sign_bytes(message);
        assert_eq!(sig_bytes.len(), 64);

        assert!(kp.public_key().verify_bytes(message, &sig_bytes).is_ok());
    }

    #[test]
    fn test_invalid_key_sizes() {
        assert!(Ed25519KeyPair::from_secret_bytes(&[0u8; 16]).is_err());
        assert!(Ed25519PublicKey::from_bytes(&[0u8; 16]).is_err());
        assert!(Ed25519Signature::from_bytes(&[0u8; 32]).is_err());
    }
}
