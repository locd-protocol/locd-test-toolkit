//! Claimant logic for the Loc'd verification protocol

use crate::messages::{ChallengeMessage, HelloMessage, ResponseMessage, ResultMessage};
use locd_core::{Error, IdentityDomain, Result};
use locd_crypto::Ed25519KeyPair;

/// Claimant in the challenge-response protocol
///
/// The claimant proves its identity by responding to challenges from the verifier.
pub struct Claimant {
    device_key: Ed25519KeyPair,
    identity_domain: IdentityDomain,
}

impl Claimant {
    pub fn new(device_key: Ed25519KeyPair, identity_domain: IdentityDomain) -> Self {
        Self {
            device_key,
            identity_domain,
        }
    }

    /// Generate a HELLO message to initiate verification
    pub fn create_hello(&self) -> Result<HelloMessage> {
        Ok(HelloMessage::new(
            self.identity_domain.as_str().to_string(),
            self.device_key.public_key().to_bytes().to_vec(),
        ))
    }

    /// Generate a RESPONSE to a challenge
    ///
    /// The response includes:
    /// - Signature over (nonce || timestamp || verifier_domain)
    /// - Delegation token (COSE Sign1)
    /// - Sub-delegation chain (if any)
    pub fn create_response(
        &self,
        challenge: &ChallengeMessage,
        delegation_token: Vec<u8>,
        sub_delegation_chain: Vec<Vec<u8>>,
    ) -> Result<ResponseMessage> {
        // Check timestamp tolerance
        if !challenge.is_timestamp_valid() {
            return Err(Error::Custom(
                "challenge timestamp outside tolerance".to_string(),
            ));
        }

        // Build signature payload: nonce || timestamp || verifier_domain
        let mut payload = Vec::new();
        payload.extend_from_slice(&challenge.nonce);
        payload.extend_from_slice(&challenge.timestamp.to_le_bytes());
        payload.extend_from_slice(challenge.verifier_domain.as_bytes());

        // Sign with device key
        let signature = self.device_key.sign(&payload);

        Ok(ResponseMessage::new(
            signature.to_bytes().to_vec(),
            delegation_token,
            sub_delegation_chain,
        ))
    }

    /// Handle a RESULT message from the verifier
    pub fn handle_result(&self, result: &ResultMessage) -> Result<VerificationOutcome> {
        Ok(VerificationOutcome {
            verified: result.verified,
            reason: result.reason.clone(),
            wireguard_public_key: result.wireguard_public_key.clone(),
        })
    }

    pub fn device_key(&self) -> &Ed25519KeyPair {
        &self.device_key
    }

    pub fn identity_domain(&self) -> &IdentityDomain {
        &self.identity_domain
    }
}

/// Outcome of the verification process from claimant's perspective
#[derive(Debug, Clone)]
pub struct VerificationOutcome {
    pub verified: bool,
    pub reason: crate::messages::ReasonCode,
    pub wireguard_public_key: Option<Vec<u8>>,
}

impl VerificationOutcome {
    pub fn is_success(&self) -> bool {
        self.verified
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use locd_delegation::DelegationToken;

    #[test]
    fn test_claimant_create_hello() {
        let device_key = Ed25519KeyPair::generate();
        let identity_domain = IdentityDomain::new("example.com");
        let claimant = Claimant::new(device_key, identity_domain);

        let hello = claimant.create_hello().unwrap();

        assert_eq!(hello.identity_domain, "example.com");
        assert_eq!(
            hello.device_public_key,
            claimant.device_key().public_key().to_bytes().to_vec()
        );
    }

    #[test]
    fn test_claimant_create_response() {
        let device_key = Ed25519KeyPair::generate();
        let device_pubkey = device_key.public_key().to_bytes();
        let master_key = Ed25519KeyPair::generate();
        let identity_domain = IdentityDomain::new("example.com");
        let claimant = Claimant::new(device_key, identity_domain);

        // Create a delegation token
        let token = DelegationToken::builder()
            .delegator(master_key.public_key().to_bytes())
            .delegate(device_pubkey)
            .expires_in(86400)
            .service("api.example.com")
            .action("read")
            .build()
            .unwrap();

        let signed_token = token.sign(&master_key).unwrap();

        // Create a challenge
        let challenge = ChallengeMessage::generate("verifier.com".to_string()).unwrap();

        // Generate response
        let response = claimant
            .create_response(&challenge, signed_token, Vec::new())
            .unwrap();

        // Verify signature length (Ed25519 signatures are 64 bytes)
        assert_eq!(response.signature.len(), 64);

        // Verify the response signature manually
        let mut payload = Vec::new();
        payload.extend_from_slice(&challenge.nonce);
        payload.extend_from_slice(&challenge.timestamp.to_le_bytes());
        payload.extend_from_slice(challenge.verifier_domain.as_bytes());

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&response.signature);
        let signature = locd_crypto::Ed25519Signature::from_bytes(&sig_bytes).unwrap();
        assert!(claimant
            .device_key()
            .public_key()
            .verify(&payload, &signature)
            .is_ok());
    }

    #[test]
    fn test_claimant_reject_stale_challenge() {
        let device_key = Ed25519KeyPair::generate();
        let identity_domain = IdentityDomain::new("example.com");
        let claimant = Claimant::new(device_key, identity_domain);

        // Create a stale challenge (2 minutes ago)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let stale_challenge =
            ChallengeMessage::new(vec![0u8; 32], now - 120, "verifier.com".to_string()).unwrap();

        let result = claimant.create_response(&stale_challenge, Vec::new(), Vec::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_verification_outcome() {
        use crate::messages::ReasonCode;

        let outcome = VerificationOutcome {
            verified: true,
            reason: ReasonCode::Ok,
            wireguard_public_key: Some(vec![1, 2, 3]),
        };

        assert!(outcome.is_success());
        assert!(outcome.wireguard_public_key.is_some());

        let failure = VerificationOutcome {
            verified: false,
            reason: ReasonCode::DelegationExpired,
            wireguard_public_key: None,
        };

        assert!(!failure.is_success());
        assert!(failure.wireguard_public_key.is_none());
    }
}
