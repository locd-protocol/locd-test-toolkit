//! # locd-verification
//!
//! Challenge-response verification protocol for the Loc'd identity system (§7).
//!
//! ## Overview
//!
//! This crate implements the verification layer that allows a Verifier to authenticate
//! a Claimant's identity through a challenge-response protocol.
//!
//! ## Protocol Flow
//!
//! ```text
//! Claimant                                    Verifier
//!    │                                           │
//!    │──── 1. HELLO (identity domain) ──────────▶│
//!    │                                           │
//!    │                          2. DNS lookup: _locd.<domain>
//!    │                             Verify DNSSEC chain
//!    │                             Extract public key
//!    │                                           │
//!    │◀─── 3. CHALLENGE (nonce, timestamp) ──────│
//!    │                                           │
//!    │     4. Sign challenge with Device Key     │
//!    │        Attach Delegation Token            │
//!    │                                           │
//!    │──── 5. RESPONSE (signature, delegation) ─▶│
//!    │                                           │
//!    │                          6. Verify delegation:
//!    │                             - Signed by published Master Key?
//!    │                             - Delegation not expired?
//!    │                             - Delegation not revoked?
//!    │                             - Service within scope?
//!    │                             - Action within scope?
//!    │                          7. Verify response signature:
//!    │                             - Signed by delegated Device Key?
//!    │                             - Nonce matches?
//!    │                             - Timestamp within tolerance?
//!    │                                           │
//!    │◀─── 8. VERIFIED / REJECTED ──────────────│
//! ```
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use locd_verification::{Claimant, Verifier, ReasonCode};
//! use locd_core::IdentityDomain;
//! use locd_crypto::Ed25519KeyPair;
//! use locd_delegation::DelegationToken;
//!
//! // Claimant side
//! let device_key = Ed25519KeyPair::generate();
//! let device_pubkey = device_key.public_key().to_bytes();
//! let claimant = Claimant::new(
//!     device_key,
//!     IdentityDomain::new("alice.example.com")
//! );
//!
//! // Send HELLO
//! let hello = claimant.create_hello().unwrap();
//!
//! // Verifier side
//! let verifier = Verifier::new(
//!     IdentityDomain::new("service.example.com"),
//!     vec![1, 2, 3, 4, 5], // WireGuard public key
//!     None, // No revocation checker for this example
//! );
//!
//! // Receive HELLO, send CHALLENGE
//! let challenge = verifier.handle_hello(&hello).unwrap();
//!
//! // Claimant receives challenge and creates response
//! // (with delegation token from somewhere)
//! let master_key = Ed25519KeyPair::generate();
//! let token = DelegationToken::builder()
//!     .delegator(master_key.public_key().to_bytes())
//!     .delegate(device_pubkey)
//!     .expires_in(86400)
//!     .service("service.example.com")
//!     .action("read")
//!     .build()
//!     .unwrap();
//! let signed_token = token.sign(&master_key).unwrap();
//!
//! let response = claimant.create_response(
//!     &challenge,
//!     signed_token,
//!     Vec::new() // No sub-delegation chain
//! ).unwrap();
//!
//! // Verifier verifies the response
//! // Note: This will fail with DNS lookup error in this example
//! // since we haven't provided a real DNS resolver
//! let result = verifier.verify_response(
//!     &hello,
//!     &challenge,
//!     &response,
//!     "service.example.com",
//!     "read"
//! ).unwrap();
//! ```
//!
//! ## Message Formats
//!
//! All protocol messages are CBOR-encoded with integer keys for space efficiency.
//!
//! See the [`messages`] module for detailed message format specifications.

pub mod claimant;
pub mod messages;
pub mod verifier;

// Re-export main types
pub use claimant::{Claimant, VerificationOutcome};
pub use messages::{ChallengeMessage, HelloMessage, ReasonCode, ResponseMessage, ResultMessage};
pub use verifier::{MockRevocationChecker, RevocationChecker, Verifier};

// Re-export from dependencies for convenience
pub use locd_core::{Error, Result};

#[cfg(test)]
mod tests {
    use super::*;
    use locd_core::IdentityDomain;
    use locd_crypto::Ed25519KeyPair;
    use locd_delegation::DelegationToken;

    #[test]
    fn test_verification_module() {
        // This test ensures the module can be imported and basic types work
        let device_key = Ed25519KeyPair::generate();
        let claimant = Claimant::new(device_key, IdentityDomain::new("test"));

        let hello = claimant.create_hello().unwrap();
        assert_eq!(hello.identity_domain, "test");
    }

    #[test]
    fn test_end_to_end_message_flow() {
        // Setup
        let master_key = Ed25519KeyPair::generate();
        let device_key = Ed25519KeyPair::generate();
        let device_pubkey = device_key.public_key().to_bytes();

        // Claimant
        let claimant = Claimant::new(device_key, IdentityDomain::new("alice.com"));

        // Verifier
        let verifier = Verifier::new(
            IdentityDomain::new("service.com"),
            vec![1, 2, 3, 4, 5],
            None,
        );

        // 1. HELLO
        let hello = claimant.create_hello().unwrap();
        let hello_bytes = hello.encode().unwrap();
        let hello_decoded = HelloMessage::decode(&hello_bytes).unwrap();
        assert_eq!(hello.identity_domain, hello_decoded.identity_domain);

        // 2. CHALLENGE
        let challenge = verifier.handle_hello(&hello_decoded).unwrap();
        let challenge_bytes = challenge.encode().unwrap();
        let challenge_decoded = ChallengeMessage::decode(&challenge_bytes).unwrap();
        assert_eq!(challenge.nonce, challenge_decoded.nonce);

        // 3. RESPONSE
        let token = DelegationToken::builder()
            .delegator(master_key.public_key().to_bytes())
            .delegate(device_pubkey)
            .expires_in(86400)
            .service("service.com")
            .action("read")
            .build()
            .unwrap();
        let signed_token = token.sign(&master_key).unwrap();

        let response = claimant
            .create_response(&challenge_decoded, signed_token, Vec::new())
            .unwrap();
        let response_bytes = response.encode().unwrap();
        let response_decoded = ResponseMessage::decode(&response_bytes).unwrap();
        assert_eq!(response.signature, response_decoded.signature);

        // 4. RESULT (would happen in verifier, but we can test the message)
        let result = ResultMessage::success(vec![6, 7, 8, 9, 10]);
        let result_bytes = result.encode().unwrap();
        let result_decoded = ResultMessage::decode(&result_bytes).unwrap();
        assert!(result_decoded.verified);
        assert_eq!(result_decoded.reason, ReasonCode::Ok);
    }

    #[test]
    fn test_verification_failure_cases() {
        let result_expired = ResultMessage::failure(ReasonCode::DelegationExpired);
        assert!(!result_expired.verified);
        assert_eq!(result_expired.reason, ReasonCode::DelegationExpired);

        let result_revoked = ResultMessage::failure(ReasonCode::DelegationRevoked);
        assert!(!result_revoked.verified);
        assert_eq!(result_revoked.reason, ReasonCode::DelegationRevoked);

        let result_scope = ResultMessage::failure(ReasonCode::ScopeViolation);
        assert!(!result_scope.verified);
        assert_eq!(result_scope.reason, ReasonCode::ScopeViolation);
    }
}
