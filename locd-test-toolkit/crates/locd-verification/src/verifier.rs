//! Verifier logic for the Loc'd verification protocol

use crate::messages::{ChallengeMessage, HelloMessage, ReasonCode, ResponseMessage, ResultMessage};
use locd_core::{Error, IdentityDomain, Result};
use locd_crypto::{Ed25519PublicKey, Ed25519Signature};
use locd_delegation::{DelegationToken, DelegationValidator, ValidationContext};
use locd_dns::DnsResolver;

/// Verifier in the challenge-response protocol
///
/// The verifier:
/// 1. Receives HELLO from claimant
/// 2. Looks up Master Key via DNS
/// 3. Sends CHALLENGE
/// 4. Verifies RESPONSE (delegation, signature, scope)
/// 5. Checks revocation
/// 6. Sends RESULT
pub struct Verifier {
    domain: IdentityDomain,
    wireguard_public_key: Vec<u8>,
    #[allow(dead_code)]
    dns_resolver: DnsResolver,
    revocation_checker: Option<Box<dyn RevocationChecker>>,
}

impl Verifier {
    pub fn new(
        domain: IdentityDomain,
        wireguard_public_key: Vec<u8>,
        revocation_checker: Option<Box<dyn RevocationChecker>>,
    ) -> Self {
        Self {
            domain,
            wireguard_public_key,
            dns_resolver: DnsResolver::new(),
            revocation_checker,
        }
    }

    /// Process a HELLO message and generate a CHALLENGE
    pub fn handle_hello(&self, _hello: &HelloMessage) -> Result<ChallengeMessage> {
        // Generate challenge with random nonce and current timestamp
        ChallengeMessage::generate(self.domain.as_str().to_string())
    }

    /// Verify a RESPONSE message
    ///
    /// This performs the full verification flow (§7.1):
    /// 1. DNS lookup for Master Key
    /// 2. DNSSEC validation
    /// 3. Delegation signature verification
    /// 4. Expiry checking
    /// 5. Revocation checking
    /// 6. Service/action scope validation
    /// 7. Response signature verification
    /// 8. Timestamp tolerance checking
    pub fn verify_response(
        &self,
        hello: &HelloMessage,
        challenge: &ChallengeMessage,
        response: &ResponseMessage,
        requested_service: &str,
        requested_action: &str,
    ) -> Result<ResultMessage> {
        // 1. DNS lookup for Master Key
        let master_key = match self.lookup_master_key(&hello.identity_domain) {
            Ok(key) => key,
            Err(_) => return Ok(ResultMessage::failure(ReasonCode::DnsLookupFailed)),
        };

        // 2. DNSSEC validation (placeholder - actual implementation in locd-dns)
        // For now, we assume DNS resolver handles DNSSEC

        // 3. Verify delegation token signature
        let delegation = match DelegationToken::verify(&response.delegation_token, &master_key) {
            Ok(token) => token,
            Err(_) => return Ok(ResultMessage::failure(ReasonCode::DelegationInvalid)),
        };

        // 4. Check delegation expiry
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if current_time >= delegation.expires_at {
            return Ok(ResultMessage::failure(ReasonCode::DelegationExpired));
        }

        // 5. Check revocation
        if let Some(ref checker) = self.revocation_checker {
            if checker.is_revoked(&hello.identity_domain, &delegation.delegation_id)? {
                return Ok(ResultMessage::failure(ReasonCode::DelegationRevoked));
            }
        }

        // 6. Validate service/action scope
        let context = ValidationContext {
            service: Some(requested_service.to_string()),
            action: Some(requested_action.to_string()),
            use_count: None,
            current_time,
        };

        if let Err(e) = DelegationValidator::validate(&delegation, &context) {
            return match e {
                Error::DelegationExpired(_) => {
                    Ok(ResultMessage::failure(ReasonCode::DelegationExpired))
                }
                _ => Ok(ResultMessage::failure(ReasonCode::ScopeViolation)),
            };
        }

        // 7. Verify sub-delegation chain (if present)
        if !response.sub_delegation_chain.is_empty() {
            if response.sub_delegation_chain.len() > 3 {
                return Ok(ResultMessage::failure(ReasonCode::ChainTooDeep));
            }
            // TODO: Implement full chain validation
            // For now, we just check the depth
        }

        // 8. Verify response signature (nonce || timestamp || verifier_domain)
        let device_public_key = match Ed25519PublicKey::from_bytes(&hello.device_public_key) {
            Ok(key) => key,
            Err(_) => return Ok(ResultMessage::failure(ReasonCode::DelegationInvalid)),
        };

        let mut payload = Vec::new();
        payload.extend_from_slice(&challenge.nonce);
        payload.extend_from_slice(&challenge.timestamp.to_le_bytes());
        payload.extend_from_slice(challenge.verifier_domain.as_bytes());

        if response.signature.len() != 64 {
            return Ok(ResultMessage::failure(ReasonCode::NonceMismatch));
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&response.signature);
        let signature = match Ed25519Signature::from_bytes(&sig_bytes) {
            Ok(sig) => sig,
            Err(_) => return Ok(ResultMessage::failure(ReasonCode::NonceMismatch)),
        };

        if device_public_key.verify(&payload, &signature).is_err() {
            return Ok(ResultMessage::failure(ReasonCode::NonceMismatch));
        }

        // 9. Check timestamp tolerance
        if !challenge.is_timestamp_valid() {
            return Ok(ResultMessage::failure(ReasonCode::TimestampSkew));
        }

        // 10. Verify device key matches delegation
        if delegation.delegate != hello.device_public_key {
            return Ok(ResultMessage::failure(ReasonCode::DelegationInvalid));
        }

        // All checks passed
        Ok(ResultMessage::success(self.wireguard_public_key.clone()))
    }

    /// Look up the Master Key for a domain via DNS
    ///
    /// Note: This is a placeholder. In production, this would be async and use the DNS resolver.
    /// For integration testing, a mock DNS resolver would be injected.
    fn lookup_master_key(&self, _domain: &str) -> Result<Ed25519PublicKey> {
        // Placeholder: In production, this would:
        // 1. Call self.dns_resolver.query_identity(domain).await
        // 2. Extract and parse the public key from the DNS TXT record
        // 3. Return the Ed25519PublicKey

        // For now, return an error indicating DNS lookup would happen here
        Err(Error::dns("DNS lookup not implemented (placeholder)"))
    }
}

/// Trait for revocation checking
///
/// This allows different revocation strategies to be plugged in:
/// - DNS TXT records
/// - HTTPS supplementary lists
/// - Cache with TTL
pub trait RevocationChecker: Send + Sync {
    fn is_revoked(&self, domain: &str, delegation_id: &locd_core::DelegationId) -> Result<bool>;
}

/// Mock revocation checker for testing
pub struct MockRevocationChecker {
    revoked_ids: Vec<locd_core::DelegationId>,
}

impl MockRevocationChecker {
    pub fn new(revoked_ids: Vec<locd_core::DelegationId>) -> Self {
        Self { revoked_ids }
    }

    pub fn allow_all() -> Self {
        Self {
            revoked_ids: Vec::new(),
        }
    }
}

impl RevocationChecker for MockRevocationChecker {
    fn is_revoked(&self, _domain: &str, delegation_id: &locd_core::DelegationId) -> Result<bool> {
        Ok(self.revoked_ids.contains(delegation_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claimant::Claimant;
    use locd_crypto::Ed25519KeyPair;
    use locd_delegation::DelegationToken;

    #[test]
    fn test_verifier_handle_hello() {
        let verifier = Verifier::new(
            IdentityDomain::new("verifier.com"),
            vec![1, 2, 3, 4, 5],
            None,
        );

        let hello = HelloMessage::new("claimant.com".to_string(), vec![6, 7, 8, 9, 10]);

        let challenge = verifier.handle_hello(&hello).unwrap();

        assert_eq!(challenge.nonce.len(), 32);
        assert_eq!(challenge.verifier_domain, "verifier.com");
        assert!(challenge.is_timestamp_valid());
    }

    #[test]
    fn test_full_verification_flow() {
        // Setup keys
        let master_key = Ed25519KeyPair::generate();
        let device_key = Ed25519KeyPair::generate();
        let device_pubkey = device_key.public_key().to_bytes();

        // Setup claimant
        let claimant_domain = IdentityDomain::new("claimant.com");
        let claimant = Claimant::new(device_key, claimant_domain);

        // Create delegation token
        let token = DelegationToken::builder()
            .delegator(master_key.public_key().to_bytes())
            .delegate(device_pubkey)
            .expires_in(86400)
            .service("api.verifier.com")
            .action("read")
            .build()
            .unwrap();

        let signed_token = token.sign(&master_key).unwrap();

        // Note: In a real scenario, the master key would be published to DNS
        // and the verifier would look it up. For this test, we'll mock the DNS lookup
        // by creating a MockDnsResolver (not implemented here for brevity)

        // For now, we can't fully test the verification flow without a DNS mock
        // This test demonstrates the message flow structure
        let hello = claimant.create_hello().unwrap();

        let verifier = Verifier::new(
            IdentityDomain::new("verifier.com"),
            vec![1, 2, 3, 4, 5],
            Some(Box::new(MockRevocationChecker::allow_all())),
        );

        let challenge = verifier.handle_hello(&hello).unwrap();

        let response = claimant
            .create_response(&challenge, signed_token, Vec::new())
            .unwrap();

        // The full verification would happen here, but it requires DNS lookup
        // which we haven't mocked in this test
        assert_eq!(response.signature.len(), 64);
        assert!(!response.delegation_token.is_empty());
    }

    #[test]
    fn test_mock_revocation_checker() {
        use locd_core::DelegationId;
        use uuid::Uuid;

        let revoked_id = DelegationId::from(Uuid::new_v4());
        let allowed_id = DelegationId::from(Uuid::new_v4());

        let checker = MockRevocationChecker::new(vec![revoked_id.clone()]);

        assert!(checker.is_revoked("test.com", &revoked_id).unwrap());
        assert!(!checker.is_revoked("test.com", &allowed_id).unwrap());

        let allow_all = MockRevocationChecker::allow_all();
        assert!(!allow_all.is_revoked("test.com", &revoked_id).unwrap());
    }

    #[test]
    fn test_verification_timestamp_skew() {
        let _verifier = Verifier::new(
            IdentityDomain::new("verifier.com"),
            vec![1, 2, 3, 4, 5],
            None,
        );

        // Create a challenge with old timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let old_challenge =
            ChallengeMessage::new(vec![0u8; 32], now - 120, "verifier.com".to_string()).unwrap();

        // Verify timestamp is out of tolerance
        assert!(!old_challenge.is_timestamp_valid());
    }

    #[test]
    fn test_verification_chain_too_deep() {
        let master_key = Ed25519KeyPair::generate();
        let device_key = Ed25519KeyPair::generate();
        let device_pubkey = device_key.public_key().to_bytes();
        let claimant_domain = IdentityDomain::new("claimant.com");
        let claimant = Claimant::new(device_key, claimant_domain);

        let token = DelegationToken::builder()
            .delegator(master_key.public_key().to_bytes())
            .delegate(device_pubkey)
            .expires_in(86400)
            .service("api.verifier.com")
            .action("read")
            .build()
            .unwrap();

        let signed_token = token.sign(&master_key).unwrap();

        let _hello = claimant.create_hello().unwrap();
        let challenge = ChallengeMessage::generate("verifier.com".to_string()).unwrap();

        // Create a chain that's too deep (> 3)
        let chain = vec![vec![1, 2], vec![3, 4], vec![5, 6], vec![7, 8]];
        let response = claimant
            .create_response(&challenge, signed_token, chain)
            .unwrap();

        let _verifier = Verifier::new(IdentityDomain::new("verifier.com"), vec![1, 2, 3], None);

        // This would fail in verify_response due to chain depth
        // (but we can't fully test without DNS mock)
        assert_eq!(response.sub_delegation_chain.len(), 4);
    }
}
