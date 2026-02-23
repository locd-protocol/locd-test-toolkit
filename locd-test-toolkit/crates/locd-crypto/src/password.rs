//! Password hashing using Argon2id

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use locd_core::{Error, Result};
use rand::rngs::OsRng;

/// Hash a password using Argon2id
///
/// Returns the PHC-formatted hash string suitable for storage
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| Error::crypto(format!("Password hashing failed: {}", e)))?;

    Ok(hash.to_string())
}

/// Verify a password against a hash
///
/// Returns Ok(()) if the password matches, Err otherwise
pub fn verify_password(password: &str, hash: &str) -> Result<()> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| Error::crypto(format!("Invalid password hash: {}", e)))?;

    let argon2 = Argon2::default();

    argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|e| Error::crypto(format!("Password verification failed: {}", e)))
}

/// Hash a password with custom Argon2id parameters
///
/// This allows tuning memory, iterations, and parallelism for
/// different security/performance requirements
pub fn hash_password_custom(
    password: &str,
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
) -> Result<String> {
    use argon2::{Algorithm, Params, Version};

    let salt = SaltString::generate(&mut OsRng);

    let params = Params::new(memory_cost, time_cost, parallelism, None)
        .map_err(|e| Error::crypto(format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| Error::crypto(format!("Password hashing failed: {}", e)))?;

    Ok(hash.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_verify() {
        let password = "correct horse battery staple";
        let hash = hash_password(password).unwrap();

        // Verify correct password
        assert!(verify_password(password, &hash).is_ok());

        // Verify wrong password
        assert!(verify_password("wrong password", &hash).is_err());
    }

    #[test]
    fn test_different_hashes() {
        let password = "test password";

        let hash1 = hash_password(password).unwrap();
        let hash2 = hash_password(password).unwrap();

        // Hashes should be different (different salts)
        assert_ne!(hash1, hash2);

        // But both should verify
        assert!(verify_password(password, &hash1).is_ok());
        assert!(verify_password(password, &hash2).is_ok());
    }

    #[test]
    fn test_custom_params() {
        let password = "test";

        // Light parameters for testing
        let hash = hash_password_custom(password, 19456, 2, 1).unwrap();
        assert!(verify_password(password, &hash).is_ok());
    }

    #[test]
    fn test_invalid_hash() {
        let result = verify_password("test", "invalid hash string");
        assert!(result.is_err());
    }
}
