//! Data structures for test vectors.

use serde::{Deserialize, Serialize};

/// Complete test vector suite for the Loc'd Protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestVectorSuite {
    /// Protocol version these vectors are for
    pub version: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Cryptographic primitive test vectors
    pub crypto: CryptoVectors,
    /// Key hierarchy test vectors
    pub keys: KeyVectors,
    /// Delegation token test vectors
    pub delegation: DelegationVectors,
    /// DNS record format test vectors
    pub dns: DnsVectors,
    /// Challenge-response protocol test vectors
    pub verification: VerificationVectors,
}

/// Cryptographic primitive test vectors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoVectors {
    /// Ed25519 signature test cases
    pub ed25519: Vec<Ed25519TestCase>,
    /// X25519 key agreement test cases
    pub x25519: Vec<X25519TestCase>,
    /// ChaCha20-Poly1305 AEAD test cases
    pub chacha20_poly1305: Vec<AeadTestCase>,
    /// HKDF-SHA256 test cases
    pub hkdf: Vec<HkdfTestCase>,
    /// Base64url encoding test cases
    pub base64url: Vec<Base64UrlTestCase>,
}

/// Ed25519 signature test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ed25519TestCase {
    pub description: String,
    pub seed: String,        // Hex
    pub private_key: String, // Hex
    pub public_key: String,  // Hex (32 bytes)
    pub message: String,     // Hex
    pub signature: String,   // Hex (64 bytes)
    pub should_verify: bool,
}

/// X25519 key agreement test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X25519TestCase {
    pub description: String,
    pub alice_private: String, // Hex
    pub alice_public: String,  // Hex
    pub bob_private: String,   // Hex
    pub bob_public: String,    // Hex
    pub shared_secret: String, // Hex
}

/// AEAD encryption test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeadTestCase {
    pub description: String,
    pub key: String,        // Hex (32 bytes)
    pub nonce: String,      // Hex (12 bytes for ChaCha20)
    pub plaintext: String,  // Hex
    pub aad: String,        // Hex (additional authenticated data)
    pub ciphertext: String, // Hex (includes auth tag)
}

/// HKDF key derivation test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HkdfTestCase {
    pub description: String,
    pub ikm: String,   // Input key material (hex)
    pub salt: String,  // Salt (hex)
    pub info: String,  // Context info (hex)
    pub length: usize, // Output length in bytes
    pub okm: String,   // Output key material (hex)
}

/// Base64url encoding test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Base64UrlTestCase {
    pub description: String,
    pub input: String,  // Hex
    pub output: String, // Base64url (no padding)
}

/// Key hierarchy test vectors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVectors {
    pub master_keys: Vec<KeyTestCase>,
    pub device_keys: Vec<KeyTestCase>,
    pub session_keys: Vec<KeyTestCase>,
}

/// Key test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyTestCase {
    pub description: String,
    pub seed: String,            // Hex seed for deterministic generation
    pub public_key: String,      // Hex (32 bytes)
    pub created_at: u64,         // Unix timestamp
    pub expires_at: Option<u64>, // Unix timestamp
    pub is_expired: bool,        // At time of vector creation
}

/// Delegation token test vectors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationVectors {
    pub tokens: Vec<DelegationTestCase>,
}

/// Delegation token test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationTestCase {
    pub description: String,
    pub master_key_seed: String,   // Hex seed
    pub master_key_public: String, // Hex
    pub device_key_seed: String,   // Hex seed
    pub device_key_public: String, // Hex
    pub delegation_id: String,     // UUID
    pub created_at: u64,
    pub expires_at: u64,
    pub services: Vec<String>,
    pub actions: Vec<String>,
    pub max_uses: Option<u32>,
    pub token_cbor: String, // Hex-encoded CBOR
    pub signature: String,  // Hex (64 bytes)
    pub should_verify: bool,
}

/// DNS record test vectors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsVectors {
    pub identity_records: Vec<IdentityRecordTestCase>,
    pub revocation_records: Vec<RevocationRecordTestCase>,
    pub rotation_records: Vec<RotationRecordTestCase>,
}

/// Identity record test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRecordTestCase {
    pub description: String,
    pub domain: String,
    pub dns_name: String,   // _locd.domain
    pub public_key: String, // Base64url
    pub timestamp: u64,
    pub txt_record: String, // Full TXT record value
    pub should_parse: bool,
}

/// Revocation record test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRecordTestCase {
    pub description: String,
    pub domain: String,
    pub dns_name: String,         // _locd-revoke.domain
    pub revoked_ids: Vec<String>, // UUIDs
    pub timestamp: u64,
    pub txt_record: String, // Full TXT record value
    pub should_parse: bool,
}

/// Rotation record test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationRecordTestCase {
    pub description: String,
    pub domain: String,
    pub dns_name: String, // _locd-rotate.domain
    pub old_key: String,  // Base64url
    pub new_key: String,  // Base64url
    pub timestamp: u64,
    pub signature: String,  // Base64url (by old key)
    pub txt_record: String, // Full TXT record value
    pub should_parse: bool,
}

/// Verification protocol test vectors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationVectors {
    pub flows: Vec<VerificationFlowTestCase>,
    pub messages: MessageVectors,
}

/// Complete verification flow test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationFlowTestCase {
    pub description: String,
    pub claimant_domain: String,
    pub claimant_device_key_seed: String,
    pub claimant_device_key_public: String,
    pub verifier_domain: String,
    pub verifier_wg_public_key: String,
    pub challenge_nonce: String, // Hex (32 bytes)
    pub challenge_timestamp: u64,
    pub delegation_id: String,      // UUID
    pub response_signature: String, // Hex (64 bytes)
    pub expected_result: bool,      // Should verification succeed?
    pub expected_reason: String,    // ReasonCode name
}

/// Protocol message test vectors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageVectors {
    pub hello_messages: Vec<HelloMessageTestCase>,
    pub challenge_messages: Vec<ChallengeMessageTestCase>,
    pub response_messages: Vec<ResponseMessageTestCase>,
    pub result_messages: Vec<ResultMessageTestCase>,
}

/// HELLO message test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloMessageTestCase {
    pub description: String,
    pub identity_domain: String,
    pub device_public_key: String, // Hex (32 bytes)
    pub cbor_encoded: String,      // Hex
    pub should_parse: bool,
}

/// CHALLENGE message test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeMessageTestCase {
    pub description: String,
    pub nonce: String, // Hex (32 bytes)
    pub timestamp: u64,
    pub verifier_domain: String,
    pub cbor_encoded: String, // Hex
    pub should_parse: bool,
}

/// RESPONSE message test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMessageTestCase {
    pub description: String,
    pub signature: String,                 // Hex (64 bytes)
    pub delegation_token: String,          // Hex CBOR
    pub sub_delegation_chain: Vec<String>, // Vec of hex CBOR
    pub cbor_encoded: String,              // Hex
    pub should_parse: bool,
}

/// RESULT message test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultMessageTestCase {
    pub description: String,
    pub verified: bool,
    pub reason: String,                // ReasonCode name
    pub wireguard_key: Option<String>, // Hex (32 bytes)
    pub cbor_encoded: String,          // Hex
    pub should_parse: bool,
}
