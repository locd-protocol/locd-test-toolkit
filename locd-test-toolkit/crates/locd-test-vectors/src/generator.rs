//! Test vector generation functions.

use crate::types::*;
use locd_core::DelegationId;
use locd_crypto::{base64url_encode, Ed25519KeyPair};
use rand::RngCore;

/// Generate a complete test vector suite
pub fn generate_suite() -> TestVectorSuite {
    TestVectorSuite {
        version: "0.1.0".to_string(),
        created_at: current_timestamp(),
        crypto: generate_crypto_vectors(),
        keys: generate_key_vectors(),
        delegation: generate_delegation_vectors(),
        dns: generate_dns_vectors(),
        verification: generate_verification_vectors(),
    }
}

/// Generate cryptographic primitive test vectors
fn generate_crypto_vectors() -> CryptoVectors {
    CryptoVectors {
        ed25519: vec![
            Ed25519TestCase {
                description: "Ed25519 signature with known seed".to_string(),
                seed: hex::encode([42u8; 32]),
                private_key: hex::encode(keypair_from_seed([42u8; 32]).secret_bytes()),
                public_key: hex::encode(keypair_from_seed([42u8; 32]).public_key().to_bytes()),
                message: hex::encode(b"Hello, Loc'd Protocol!"),
                signature: {
                    let kp = keypair_from_seed([42u8; 32]);
                    let sig = kp.sign(b"Hello, Loc'd Protocol!");
                    hex::encode(sig.to_bytes())
                },
                should_verify: true,
            },
            Ed25519TestCase {
                description: "Ed25519 signature with different seed".to_string(),
                seed: hex::encode([7u8; 32]),
                private_key: hex::encode(keypair_from_seed([7u8; 32]).secret_bytes()),
                public_key: hex::encode(keypair_from_seed([7u8; 32]).public_key().to_bytes()),
                message: hex::encode(b"Test message"),
                signature: {
                    let kp = keypair_from_seed([7u8; 32]);
                    let sig = kp.sign(b"Test message");
                    hex::encode(sig.to_bytes())
                },
                should_verify: true,
            },
        ],
        x25519: vec![],            // X25519 test cases would go here
        chacha20_poly1305: vec![], // AEAD test cases
        hkdf: vec![],              // HKDF test cases
        base64url: vec![
            Base64UrlTestCase {
                description: "Empty string".to_string(),
                input: hex::encode(b""),
                output: base64url_encode(b""),
            },
            Base64UrlTestCase {
                description: "Simple ASCII".to_string(),
                input: hex::encode(b"hello"),
                output: base64url_encode(b"hello"),
            },
            Base64UrlTestCase {
                description: "32 random bytes".to_string(),
                input: hex::encode([
                    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55,
                    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0xa1, 0xb2,
                    0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
                ]),
                output: base64url_encode(&[
                    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55,
                    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0xa1, 0xb2,
                    0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
                ]),
            },
        ],
    }
}

/// Generate key hierarchy test vectors
fn generate_key_vectors() -> KeyVectors {
    let now = current_timestamp();

    KeyVectors {
        master_keys: vec![
            KeyTestCase {
                description: "Master key with seed [1; 32]".to_string(),
                seed: hex::encode([1u8; 32]),
                public_key: hex::encode(keypair_from_seed([1u8; 32]).public_key().to_bytes()),
                created_at: now,
                expires_at: None,
                is_expired: false,
            },
            KeyTestCase {
                description: "Master key with seed [2; 32]".to_string(),
                seed: hex::encode([2u8; 32]),
                public_key: hex::encode(keypair_from_seed([2u8; 32]).public_key().to_bytes()),
                created_at: now - 86400,
                expires_at: None,
                is_expired: false,
            },
        ],
        device_keys: vec![
            KeyTestCase {
                description: "Device key with seed [10; 32]".to_string(),
                seed: hex::encode([10u8; 32]),
                public_key: hex::encode(keypair_from_seed([10u8; 32]).public_key().to_bytes()),
                created_at: now,
                expires_at: Some(now + 86400 * 30), // 30 days
                is_expired: false,
            },
            KeyTestCase {
                description: "Expired device key".to_string(),
                seed: hex::encode([11u8; 32]),
                public_key: hex::encode(keypair_from_seed([11u8; 32]).public_key().to_bytes()),
                created_at: now - 86400 * 60,
                expires_at: Some(now - 86400), // Expired 1 day ago
                is_expired: true,
            },
        ],
        session_keys: vec![KeyTestCase {
            description: "Session key with seed [20; 32]".to_string(),
            seed: hex::encode([20u8; 32]),
            public_key: hex::encode(keypair_from_seed([20u8; 32]).public_key().to_bytes()),
            created_at: now,
            expires_at: Some(now + 3600), // 1 hour
            is_expired: false,
        }],
    }
}

/// Generate delegation token test vectors
fn generate_delegation_vectors() -> DelegationVectors {
    let now = current_timestamp();

    let master_key = keypair_from_seed([1u8; 32]);
    let device_key = keypair_from_seed([10u8; 32]);

    let delegation_id = DelegationId::new();

    // Build and sign a delegation token
    let token = locd_delegation::DelegationToken::builder()
        .delegator(master_key.public_key().to_bytes())
        .delegate(device_key.public_key().to_bytes())
        .delegation_id(delegation_id.clone())
        .issued_at(now)
        .expires_at(now + 86400)
        .service("api.example.com")
        .action("read")
        .build()
        .expect("Failed to build token");

    let signed = token.sign(&master_key).expect("Failed to sign token");

    DelegationVectors {
        tokens: vec![DelegationTestCase {
            description: "Valid delegation token for api.example.com".to_string(),
            master_key_seed: hex::encode([1u8; 32]),
            master_key_public: hex::encode(master_key.public_key().to_bytes()),
            device_key_seed: hex::encode([10u8; 32]),
            device_key_public: hex::encode(device_key.public_key().to_bytes()),
            delegation_id: delegation_id.to_string(),
            created_at: now,
            expires_at: now + 86400,
            services: vec!["api.example.com".to_string()],
            actions: vec!["read".to_string()],
            max_uses: None,
            token_cbor: hex::encode(&signed),
            signature: "".to_string(), // Would need to extract from CBOR
            should_verify: true,
        }],
    }
}

/// Generate DNS record test vectors
fn generate_dns_vectors() -> DnsVectors {
    let now = current_timestamp();
    let master_key = keypair_from_seed([1u8; 32]);
    let public_key_b64 = base64url_encode(&master_key.public_key().to_bytes());

    DnsVectors {
        identity_records: vec![
            IdentityRecordTestCase {
                description: "Valid identity record for example.com".to_string(),
                domain: "example.com".to_string(),
                dns_name: "_locd.example.com".to_string(),
                public_key: public_key_b64.clone(),
                timestamp: now,
                txt_record: format!("v=locd1; k=ed25519; p={}; t={}", public_key_b64, now),
                should_parse: true,
            },
            IdentityRecordTestCase {
                description: "Invalid format (missing version)".to_string(),
                domain: "bad.example.com".to_string(),
                dns_name: "_locd.bad.example.com".to_string(),
                public_key: public_key_b64.clone(),
                timestamp: now,
                txt_record: format!("k=ed25519; p={}; t={}", public_key_b64, now),
                should_parse: false,
            },
        ],
        revocation_records: vec![
            RevocationRecordTestCase {
                description: "Revocation record with 2 IDs".to_string(),
                domain: "example.com".to_string(),
                dns_name: "_locd-revoke.example.com".to_string(),
                revoked_ids: vec![
                    "550e8400-e29b-41d4-a716-446655440000".to_string(),
                    "660e8400-e29b-41d4-a716-446655440001".to_string(),
                ],
                timestamp: now,
                txt_record: format!("v=locd-revoke1; ids=550e8400-e29b-41d4-a716-446655440000,660e8400-e29b-41d4-a716-446655440001; t={}", now),
                should_parse: true,
            },
            RevocationRecordTestCase {
                description: "Empty revocation list".to_string(),
                domain: "example.com".to_string(),
                dns_name: "_locd-revoke.example.com".to_string(),
                revoked_ids: vec![],
                timestamp: now,
                txt_record: format!("v=locd-revoke1; ids=; t={}", now),
                should_parse: true,
            },
        ],
        rotation_records: vec![],
    }
}

/// Generate verification protocol test vectors
fn generate_verification_vectors() -> VerificationVectors {
    let now = current_timestamp();
    let device_key = keypair_from_seed([10u8; 32]);

    let mut nonce = [0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut nonce);

    VerificationVectors {
        flows: vec![VerificationFlowTestCase {
            description: "Successful verification flow".to_string(),
            claimant_domain: "alice.example.com".to_string(),
            claimant_device_key_seed: hex::encode([10u8; 32]),
            claimant_device_key_public: hex::encode(device_key.public_key().to_bytes()),
            verifier_domain: "service.example.com".to_string(),
            verifier_wg_public_key: hex::encode([99u8; 32]),
            challenge_nonce: hex::encode(nonce),
            challenge_timestamp: now,
            delegation_id: DelegationId::new().to_string(),
            response_signature: hex::encode([0u8; 64]), // Placeholder
            expected_result: true,
            expected_reason: "Success".to_string(),
        }],
        messages: MessageVectors {
            hello_messages: vec![HelloMessageTestCase {
                description: "HELLO message from alice.example.com".to_string(),
                identity_domain: "alice.example.com".to_string(),
                device_public_key: hex::encode(device_key.public_key().to_bytes()),
                cbor_encoded: hex::encode(vec![0xa2, 0x01]), // Placeholder CBOR
                should_parse: true,
            }],
            challenge_messages: vec![ChallengeMessageTestCase {
                description: "CHALLENGE with 32-byte nonce".to_string(),
                nonce: hex::encode(nonce),
                timestamp: now,
                verifier_domain: "service.example.com".to_string(),
                cbor_encoded: hex::encode(vec![0xa3, 0x01]), // Placeholder CBOR
                should_parse: true,
            }],
            response_messages: vec![],
            result_messages: vec![
                ResultMessageTestCase {
                    description: "RESULT message - verified".to_string(),
                    verified: true,
                    reason: "Success".to_string(),
                    wireguard_key: Some(hex::encode([99u8; 32])),
                    cbor_encoded: hex::encode(vec![0xa3, 0x01]), // Placeholder CBOR
                    should_parse: true,
                },
                ResultMessageTestCase {
                    description: "RESULT message - failed (expired)".to_string(),
                    verified: false,
                    reason: "DelegationExpired".to_string(),
                    wireguard_key: None,
                    cbor_encoded: hex::encode(vec![0xa2, 0x01]), // Placeholder CBOR
                    should_parse: true,
                },
            ],
        },
    }
}

/// Create Ed25519 keypair from deterministic seed
fn keypair_from_seed(seed: [u8; 32]) -> Ed25519KeyPair {
    Ed25519KeyPair::from_secret_bytes(&seed).expect("Valid seed")
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_suite() {
        let suite = generate_suite();

        assert_eq!(suite.version, "0.1.0");
        assert!(suite.created_at > 0);

        // Crypto vectors
        assert_eq!(suite.crypto.ed25519.len(), 2);
        assert_eq!(suite.crypto.base64url.len(), 3);

        // Key vectors
        assert_eq!(suite.keys.master_keys.len(), 2);
        assert_eq!(suite.keys.device_keys.len(), 2);
        assert_eq!(suite.keys.session_keys.len(), 1);

        // Delegation vectors
        assert_eq!(suite.delegation.tokens.len(), 1);

        // DNS vectors
        assert_eq!(suite.dns.identity_records.len(), 2);
        assert_eq!(suite.dns.revocation_records.len(), 2);

        // Verification vectors
        assert_eq!(suite.verification.flows.len(), 1);
        assert_eq!(suite.verification.messages.hello_messages.len(), 1);
        assert_eq!(suite.verification.messages.result_messages.len(), 2);
    }

    #[test]
    fn test_ed25519_vectors_deterministic() {
        let suite1 = generate_crypto_vectors();
        let suite2 = generate_crypto_vectors();

        // Ed25519 vectors should be deterministic (same seed = same keys)
        assert_eq!(suite1.ed25519[0].public_key, suite2.ed25519[0].public_key);
        assert_eq!(suite1.ed25519[0].signature, suite2.ed25519[0].signature);
    }

    #[test]
    fn test_base64url_vectors() {
        let suite = generate_crypto_vectors();

        for case in &suite.base64url {
            let input = hex::decode(&case.input).expect("Valid hex");
            let encoded = base64url_encode(&input);
            assert_eq!(encoded, case.output, "Failed: {}", case.description);
        }
    }

    #[test]
    fn test_key_vectors() {
        let vectors = generate_key_vectors();

        // Master keys should not expire
        for key in &vectors.master_keys {
            assert!(key.expires_at.is_none());
            assert!(!key.is_expired);
        }

        // Should have at least one expired key
        assert!(vectors.device_keys.iter().any(|k| k.is_expired));
    }

    #[test]
    fn test_delegation_vectors() {
        let vectors = generate_delegation_vectors();

        assert_eq!(vectors.tokens.len(), 1);

        let token = &vectors.tokens[0];
        assert!(token.should_verify);
        assert_eq!(token.services.len(), 1);
        assert_eq!(token.actions.len(), 1);
    }

    #[test]
    fn test_dns_vectors() {
        let vectors = generate_dns_vectors();

        // Should have valid and invalid examples
        assert!(vectors.identity_records.iter().any(|r| r.should_parse));
        assert!(vectors.identity_records.iter().any(|r| !r.should_parse));

        // Revocation records
        assert_eq!(vectors.revocation_records.len(), 2);
    }

    #[test]
    fn test_verification_vectors() {
        let vectors = generate_verification_vectors();

        assert_eq!(vectors.flows.len(), 1);
        assert_eq!(vectors.messages.hello_messages.len(), 1);
        assert_eq!(vectors.messages.challenge_messages.len(), 1);
        assert_eq!(vectors.messages.result_messages.len(), 2);
    }
}
