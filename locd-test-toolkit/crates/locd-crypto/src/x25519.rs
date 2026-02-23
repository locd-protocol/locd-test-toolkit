//! X25519 key agreement operations (RFC 7748)

use locd_core::{Error, Result};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

/// X25519 key pair for key agreement
pub struct X25519KeyPair {
    secret: StaticSecret,
}

impl X25519KeyPair {
    /// Generate a new random X25519 key pair
    pub fn generate() -> Self {
        Self {
            secret: StaticSecret::random_from_rng(OsRng),
        }
    }

    /// Create a key pair from secret bytes (32 bytes)
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidKey(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(bytes);

        Ok(Self {
            secret: StaticSecret::from(secret_bytes),
        })
    }

    /// Get the secret key bytes
    pub fn secret_bytes(&self) -> Vec<u8> {
        self.secret.to_bytes().to_vec()
    }

    /// Get the public key
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey {
            public: PublicKey::from(&self.secret),
        }
    }

    /// Perform key agreement with another public key
    ///
    /// Returns the shared secret (32 bytes)
    pub fn key_agreement(&self, their_public: &X25519PublicKey) -> Vec<u8> {
        self.secret.diffie_hellman(&their_public.public).to_bytes().to_vec()
    }
}

/// X25519 public key
#[derive(Clone, Debug)]
pub struct X25519PublicKey {
    public: PublicKey,
}

impl X25519PublicKey {
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

        Ok(Self {
            public: PublicKey::from(key_bytes),
        })
    }

    /// Get the public key bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.public.to_bytes().to_vec()
    }
}

/// X25519 secret key (for storage)
pub struct X25519SecretKey {
    secret: StaticSecret,
}

impl X25519SecretKey {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidKey(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(bytes);

        Ok(Self {
            secret: StaticSecret::from(secret_bytes),
        })
    }

    /// Get the secret key bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.secret.to_bytes().to_vec()
    }

    /// Convert to a key pair
    pub fn to_keypair(self) -> X25519KeyPair {
        X25519KeyPair {
            secret: self.secret,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() {
        let kp = X25519KeyPair::generate();
        assert_eq!(kp.public_key().to_bytes().len(), 32);
        assert_eq!(kp.secret_bytes().len(), 32);
    }

    #[test]
    fn test_key_agreement() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        let alice_shared = alice.key_agreement(&bob.public_key());
        let bob_shared = bob.key_agreement(&alice.public_key());

        assert_eq!(alice_shared, bob_shared);
        assert_eq!(alice_shared.len(), 32);
    }

    #[test]
    fn test_from_bytes() {
        let kp1 = X25519KeyPair::generate();
        let secret = kp1.secret_bytes();
        let public = kp1.public_key().to_bytes();

        let kp2 = X25519KeyPair::from_secret_bytes(&secret).unwrap();
        assert_eq!(kp2.public_key().to_bytes(), public);

        let pk = X25519PublicKey::from_bytes(&public).unwrap();
        assert_eq!(pk.to_bytes(), public);
    }

    #[test]
    fn test_invalid_key_sizes() {
        assert!(X25519KeyPair::from_secret_bytes(&[0u8; 16]).is_err());
        assert!(X25519PublicKey::from_bytes(&[0u8; 16]).is_err());
    }

    #[test]
    fn test_secret_key() {
        let kp = X25519KeyPair::generate();
        let secret_bytes = kp.secret_bytes();

        let secret = X25519SecretKey::from_bytes(&secret_bytes).unwrap();
        assert_eq!(secret.to_bytes(), secret_bytes);

        let kp2 = secret.to_keypair();
        assert_eq!(kp2.public_key().to_bytes(), kp.public_key().to_bytes());
    }
}
