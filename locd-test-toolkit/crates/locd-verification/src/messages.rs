//! Protocol messages for the Loc'd verification layer (§7.2)

use locd_core::{Error, Result};
use std::io::Cursor;

/// Reason codes for verification results (§7.4)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReasonCode {
    Ok,
    DnsLookupFailed,
    DnssecInvalid,
    IdentityNotFound,
    IdentityExpired,
    DelegationInvalid,
    DelegationExpired,
    DelegationRevoked,
    ScopeViolation,
    NonceMismatch,
    TimestampSkew,
    ChainTooDeep,
    AttestationFailed,
}

impl ReasonCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReasonCode::Ok => "ok",
            ReasonCode::DnsLookupFailed => "dns_lookup_failed",
            ReasonCode::DnssecInvalid => "dnssec_invalid",
            ReasonCode::IdentityNotFound => "identity_not_found",
            ReasonCode::IdentityExpired => "identity_expired",
            ReasonCode::DelegationInvalid => "delegation_invalid",
            ReasonCode::DelegationExpired => "delegation_expired",
            ReasonCode::DelegationRevoked => "delegation_revoked",
            ReasonCode::ScopeViolation => "scope_violation",
            ReasonCode::NonceMismatch => "nonce_mismatch",
            ReasonCode::TimestampSkew => "timestamp_skew",
            ReasonCode::ChainTooDeep => "chain_too_deep",
            ReasonCode::AttestationFailed => "attestation_failed",
        }
    }

    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "ok" => Ok(ReasonCode::Ok),
            "dns_lookup_failed" => Ok(ReasonCode::DnsLookupFailed),
            "dnssec_invalid" => Ok(ReasonCode::DnssecInvalid),
            "identity_not_found" => Ok(ReasonCode::IdentityNotFound),
            "identity_expired" => Ok(ReasonCode::IdentityExpired),
            "delegation_invalid" => Ok(ReasonCode::DelegationInvalid),
            "delegation_expired" => Ok(ReasonCode::DelegationExpired),
            "delegation_revoked" => Ok(ReasonCode::DelegationRevoked),
            "scope_violation" => Ok(ReasonCode::ScopeViolation),
            "nonce_mismatch" => Ok(ReasonCode::NonceMismatch),
            "timestamp_skew" => Ok(ReasonCode::TimestampSkew),
            "chain_too_deep" => Ok(ReasonCode::ChainTooDeep),
            "attestation_failed" => Ok(ReasonCode::AttestationFailed),
            _ => Err(Error::Custom(format!("unknown reason code: {}", s))),
        }
    }
}

/// HELLO message: Claimant → Verifier
///
/// Format (CBOR):
/// ```text
/// {
///   1: "locd-hello-v1",
///   2: "example.com",            ; identity domain
///   3: bytes                     ; Claimant's Device Key public key
/// }
/// ```
#[derive(Debug, Clone)]
pub struct HelloMessage {
    pub identity_domain: String,
    pub device_public_key: Vec<u8>,
}

impl HelloMessage {
    pub fn new(identity_domain: String, device_public_key: Vec<u8>) -> Self {
        Self {
            identity_domain,
            device_public_key,
        }
    }

    /// Encode to CBOR bytes
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut map = Vec::new();
        map.push((
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Text("locd-hello-v1".to_string()),
        ));
        map.push((
            ciborium::Value::Integer(2.into()),
            ciborium::Value::Text(self.identity_domain.clone()),
        ));
        map.push((
            ciborium::Value::Integer(3.into()),
            ciborium::Value::Bytes(self.device_public_key.clone()),
        ));

        let value = ciborium::Value::Map(map);
        let mut buffer = Vec::new();
        ciborium::into_writer(&value, &mut buffer)
            .map_err(|e| Error::Encoding(e.to_string()))?;
        Ok(buffer)
    }

    /// Decode from CBOR bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        let value: ciborium::Value = ciborium::from_reader(Cursor::new(data))
            .map_err(|e| Error::Decoding(e.to_string()))?;

        let map = match value {
            ciborium::Value::Map(m) => m,
            _ => return Err(Error::Custom("expected CBOR map".to_string())),
        };

        let version = get_text_field(&map, 1)?;
        if version != "locd-hello-v1" {
            return Err(Error::Custom(format!(
                "expected locd-hello-v1, got {}",
                version
            )));
        }

        let identity_domain = get_text_field(&map, 2)?;
        let device_public_key = get_bytes_field(&map, 3)?;

        Ok(Self {
            identity_domain,
            device_public_key,
        })
    }
}

/// CHALLENGE message: Verifier → Claimant
///
/// Format (CBOR):
/// ```text
/// {
///   1: "locd-challenge-v1",
///   2: bytes,                    ; 32-byte random nonce
///   3: uint,                     ; Unix timestamp
///   4: text                      ; Verifier's identity domain (for mutual auth)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ChallengeMessage {
    pub nonce: Vec<u8>,
    pub timestamp: u64,
    pub verifier_domain: String,
}

impl ChallengeMessage {
    pub fn new(nonce: Vec<u8>, timestamp: u64, verifier_domain: String) -> Result<Self> {
        if nonce.len() != 32 {
            return Err(Error::Custom(format!(
                "nonce must be 32 bytes, got {}",
                nonce.len()
            )));
        }
        Ok(Self {
            nonce,
            timestamp,
            verifier_domain,
        })
    }

    /// Generate a new challenge with random nonce and current timestamp
    pub fn generate(verifier_domain: String) -> Result<Self> {
        use rand::RngCore;
        let mut nonce = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| Error::Custom(e.to_string()))?
            .as_secs();
        Self::new(nonce, timestamp, verifier_domain)
    }

    /// Encode to CBOR bytes
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut map = Vec::new();
        map.push((
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Text("locd-challenge-v1".to_string()),
        ));
        map.push((
            ciborium::Value::Integer(2.into()),
            ciborium::Value::Bytes(self.nonce.clone()),
        ));
        map.push((
            ciborium::Value::Integer(3.into()),
            ciborium::Value::Integer(self.timestamp.into()),
        ));
        map.push((
            ciborium::Value::Integer(4.into()),
            ciborium::Value::Text(self.verifier_domain.clone()),
        ));

        let value = ciborium::Value::Map(map);
        let mut buffer = Vec::new();
        ciborium::into_writer(&value, &mut buffer)
            .map_err(|e| Error::Encoding(e.to_string()))?;
        Ok(buffer)
    }

    /// Decode from CBOR bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        let value: ciborium::Value = ciborium::from_reader(Cursor::new(data))
            .map_err(|e| Error::Decoding(e.to_string()))?;

        let map = match value {
            ciborium::Value::Map(m) => m,
            _ => return Err(Error::Custom("expected CBOR map".to_string())),
        };

        let version = get_text_field(&map, 1)?;
        if version != "locd-challenge-v1" {
            return Err(Error::Custom(format!(
                "expected locd-challenge-v1, got {}",
                version
            )));
        }

        let nonce = get_bytes_field(&map, 2)?;
        let timestamp = get_uint_field(&map, 3)?;
        let verifier_domain = get_text_field(&map, 4)?;

        Self::new(nonce, timestamp, verifier_domain)
    }

    /// Check if timestamp is within tolerance (60 seconds)
    pub fn is_timestamp_valid(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let diff = if now > self.timestamp {
            now - self.timestamp
        } else {
            self.timestamp - now
        };
        diff <= 60
    }
}

/// RESPONSE message: Claimant → Verifier
///
/// Format (CBOR):
/// ```text
/// {
///   1: "locd-response-v1",
///   2: bytes,                    ; Ed25519 signature over (nonce || timestamp || verifier_domain)
///   3: bytes,                    ; COSE Sign1 Delegation Token
///   4: [bytes]                   ; Sub-delegation chain (if any), ordered root-first
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ResponseMessage {
    pub signature: Vec<u8>,
    pub delegation_token: Vec<u8>,
    pub sub_delegation_chain: Vec<Vec<u8>>,
}

impl ResponseMessage {
    pub fn new(
        signature: Vec<u8>,
        delegation_token: Vec<u8>,
        sub_delegation_chain: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            signature,
            delegation_token,
            sub_delegation_chain,
        }
    }

    /// Encode to CBOR bytes
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut map = Vec::new();
        map.push((
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Text("locd-response-v1".to_string()),
        ));
        map.push((
            ciborium::Value::Integer(2.into()),
            ciborium::Value::Bytes(self.signature.clone()),
        ));
        map.push((
            ciborium::Value::Integer(3.into()),
            ciborium::Value::Bytes(self.delegation_token.clone()),
        ));
        map.push((
            ciborium::Value::Integer(4.into()),
            ciborium::Value::Array(
                self.sub_delegation_chain
                    .iter()
                    .map(|b| ciborium::Value::Bytes(b.clone()))
                    .collect(),
            ),
        ));

        let value = ciborium::Value::Map(map);
        let mut buffer = Vec::new();
        ciborium::into_writer(&value, &mut buffer)
            .map_err(|e| Error::Encoding(e.to_string()))?;
        Ok(buffer)
    }

    /// Decode from CBOR bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        let value: ciborium::Value = ciborium::from_reader(Cursor::new(data))
            .map_err(|e| Error::Decoding(e.to_string()))?;

        let map = match value {
            ciborium::Value::Map(m) => m,
            _ => return Err(Error::Custom("expected CBOR map".to_string())),
        };

        let version = get_text_field(&map, 1)?;
        if version != "locd-response-v1" {
            return Err(Error::Custom(format!(
                "expected locd-response-v1, got {}",
                version
            )));
        }

        let signature = get_bytes_field(&map, 2)?;
        let delegation_token = get_bytes_field(&map, 3)?;

        let sub_delegation_chain = match get_field(&map, 4) {
            Some(ciborium::Value::Array(arr)) => {
                let mut chain = Vec::new();
                for item in arr {
                    match item {
                        ciborium::Value::Bytes(b) => chain.push(b.clone()),
                        _ => {
                            return Err(Error::Custom(
                                "sub-delegation chain must be array of bytes".to_string(),
                            ))
                        }
                    }
                }
                chain
            }
            _ => Vec::new(),
        };

        Ok(Self {
            signature,
            delegation_token,
            sub_delegation_chain,
        })
    }
}

/// RESULT message: Verifier → Claimant
///
/// Format (CBOR):
/// ```text
/// {
///   1: "locd-result-v1",
///   2: bool,                     ; verified (true/false)
///   3: text,                     ; reason code
///   4: bytes                     ; (If verified) Verifier's WireGuard public key
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ResultMessage {
    pub verified: bool,
    pub reason: ReasonCode,
    pub wireguard_public_key: Option<Vec<u8>>,
}

impl ResultMessage {
    pub fn new(verified: bool, reason: ReasonCode, wireguard_public_key: Option<Vec<u8>>) -> Self {
        Self {
            verified,
            reason,
            wireguard_public_key,
        }
    }

    pub fn success(wireguard_public_key: Vec<u8>) -> Self {
        Self {
            verified: true,
            reason: ReasonCode::Ok,
            wireguard_public_key: Some(wireguard_public_key),
        }
    }

    pub fn failure(reason: ReasonCode) -> Self {
        Self {
            verified: false,
            reason,
            wireguard_public_key: None,
        }
    }

    /// Encode to CBOR bytes
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut map = Vec::new();
        map.push((
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Text("locd-result-v1".to_string()),
        ));
        map.push((
            ciborium::Value::Integer(2.into()),
            ciborium::Value::Bool(self.verified),
        ));
        map.push((
            ciborium::Value::Integer(3.into()),
            ciborium::Value::Text(self.reason.as_str().to_string()),
        ));
        if let Some(ref key) = self.wireguard_public_key {
            map.push((
                ciborium::Value::Integer(4.into()),
                ciborium::Value::Bytes(key.clone()),
            ));
        }

        let value = ciborium::Value::Map(map);
        let mut buffer = Vec::new();
        ciborium::into_writer(&value, &mut buffer)
            .map_err(|e| Error::Encoding(e.to_string()))?;
        Ok(buffer)
    }

    /// Decode from CBOR bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        let value: ciborium::Value = ciborium::from_reader(Cursor::new(data))
            .map_err(|e| Error::Decoding(e.to_string()))?;

        let map = match value {
            ciborium::Value::Map(m) => m,
            _ => return Err(Error::Custom("expected CBOR map".to_string())),
        };

        let version = get_text_field(&map, 1)?;
        if version != "locd-result-v1" {
            return Err(Error::Custom(format!(
                "expected locd-result-v1, got {}",
                version
            )));
        }

        let verified = get_bool_field(&map, 2)?;
        let reason_str = get_text_field(&map, 3)?;
        let reason = ReasonCode::from_str(&reason_str)?;

        let wireguard_public_key = match get_field(&map, 4) {
            Some(ciborium::Value::Bytes(b)) => Some(b.clone()),
            _ => None,
        };

        Ok(Self {
            verified,
            reason,
            wireguard_public_key,
        })
    }
}

// Helper functions for CBOR map field extraction

fn get_field(map: &[(ciborium::Value, ciborium::Value)], key: i64) -> Option<&ciborium::Value> {
    for (k, v) in map {
        if let ciborium::Value::Integer(i) = k {
            if i128::from(*i) == key as i128 {
                return Some(v);
            }
        }
    }
    None
}

fn get_text_field(map: &[(ciborium::Value, ciborium::Value)], key: i64) -> Result<String> {
    match get_field(map, key) {
        Some(ciborium::Value::Text(s)) => Ok(s.clone()),
        _ => Err(Error::Custom(format!(
            "missing or invalid text field {}",
            key
        ))),
    }
}

fn get_bytes_field(map: &[(ciborium::Value, ciborium::Value)], key: i64) -> Result<Vec<u8>> {
    match get_field(map, key) {
        Some(ciborium::Value::Bytes(b)) => Ok(b.clone()),
        _ => Err(Error::Custom(format!(
            "missing or invalid bytes field {}",
            key
        ))),
    }
}

fn get_uint_field(map: &[(ciborium::Value, ciborium::Value)], key: i64) -> Result<u64> {
    match get_field(map, key) {
        Some(ciborium::Value::Integer(i)) => {
            let val = i128::from(*i);
            if val < 0 {
                return Err(Error::Custom(format!(
                    "field {} must be non-negative",
                    key
                )));
            }
            Ok(val as u64)
        }
        _ => Err(Error::Custom(format!(
            "missing or invalid uint field {}",
            key
        ))),
    }
}

fn get_bool_field(map: &[(ciborium::Value, ciborium::Value)], key: i64) -> Result<bool> {
    match get_field(map, key) {
        Some(ciborium::Value::Bool(b)) => Ok(*b),
        _ => Err(Error::Custom(format!(
            "missing or invalid bool field {}",
            key
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_message_roundtrip() {
        let msg = HelloMessage::new(
            "example.com".to_string(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        );

        let encoded = msg.encode().unwrap();
        let decoded = HelloMessage::decode(&encoded).unwrap();

        assert_eq!(msg.identity_domain, decoded.identity_domain);
        assert_eq!(msg.device_public_key, decoded.device_public_key);
    }

    #[test]
    fn test_challenge_message_generation() {
        let msg = ChallengeMessage::generate("verifier.com".to_string()).unwrap();

        assert_eq!(msg.nonce.len(), 32);
        assert_eq!(msg.verifier_domain, "verifier.com");
        assert!(msg.is_timestamp_valid());
    }

    #[test]
    fn test_challenge_message_roundtrip() {
        let nonce = vec![0u8; 32];
        let msg = ChallengeMessage::new(nonce.clone(), 1234567890, "verifier.com".to_string()).unwrap();

        let encoded = msg.encode().unwrap();
        let decoded = ChallengeMessage::decode(&encoded).unwrap();

        assert_eq!(msg.nonce, decoded.nonce);
        assert_eq!(msg.timestamp, decoded.timestamp);
        assert_eq!(msg.verifier_domain, decoded.verifier_domain);
    }

    #[test]
    fn test_challenge_invalid_nonce_length() {
        let result = ChallengeMessage::new(vec![0u8; 16], 1234567890, "verifier.com".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_response_message_roundtrip() {
        let msg = ResponseMessage::new(
            vec![1, 2, 3, 4, 5],
            vec![6, 7, 8, 9, 10],
            vec![vec![11, 12], vec![13, 14]],
        );

        let encoded = msg.encode().unwrap();
        let decoded = ResponseMessage::decode(&encoded).unwrap();

        assert_eq!(msg.signature, decoded.signature);
        assert_eq!(msg.delegation_token, decoded.delegation_token);
        assert_eq!(msg.sub_delegation_chain, decoded.sub_delegation_chain);
    }

    #[test]
    fn test_response_message_no_chain() {
        let msg = ResponseMessage::new(vec![1, 2, 3, 4, 5], vec![6, 7, 8, 9, 10], Vec::new());

        let encoded = msg.encode().unwrap();
        let decoded = ResponseMessage::decode(&encoded).unwrap();

        assert_eq!(msg.signature, decoded.signature);
        assert_eq!(msg.delegation_token, decoded.delegation_token);
        assert!(decoded.sub_delegation_chain.is_empty());
    }

    #[test]
    fn test_result_message_success() {
        let msg = ResultMessage::success(vec![1, 2, 3, 4, 5]);

        assert!(msg.verified);
        assert!(matches!(msg.reason, ReasonCode::Ok));
        assert!(msg.wireguard_public_key.is_some());

        let encoded = msg.encode().unwrap();
        let decoded = ResultMessage::decode(&encoded).unwrap();

        assert_eq!(msg.verified, decoded.verified);
        assert_eq!(msg.reason, decoded.reason);
        assert_eq!(msg.wireguard_public_key, decoded.wireguard_public_key);
    }

    #[test]
    fn test_result_message_failure() {
        let msg = ResultMessage::failure(ReasonCode::DelegationExpired);

        assert!(!msg.verified);
        assert!(matches!(msg.reason, ReasonCode::DelegationExpired));
        assert!(msg.wireguard_public_key.is_none());

        let encoded = msg.encode().unwrap();
        let decoded = ResultMessage::decode(&encoded).unwrap();

        assert_eq!(msg.verified, decoded.verified);
        assert_eq!(msg.reason, decoded.reason);
        assert!(decoded.wireguard_public_key.is_none());
    }

    #[test]
    fn test_reason_code_roundtrip() {
        let codes = vec![
            ReasonCode::Ok,
            ReasonCode::DnsLookupFailed,
            ReasonCode::DnssecInvalid,
            ReasonCode::IdentityNotFound,
            ReasonCode::IdentityExpired,
            ReasonCode::DelegationInvalid,
            ReasonCode::DelegationExpired,
            ReasonCode::DelegationRevoked,
            ReasonCode::ScopeViolation,
            ReasonCode::NonceMismatch,
            ReasonCode::TimestampSkew,
            ReasonCode::ChainTooDeep,
            ReasonCode::AttestationFailed,
        ];

        for code in codes {
            let s = code.as_str();
            let decoded = ReasonCode::from_str(s).unwrap();
            assert_eq!(code, decoded);
        }
    }

    #[test]
    fn test_timestamp_tolerance() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Within tolerance
        let msg1 = ChallengeMessage::new(vec![0u8; 32], now, "test.com".to_string()).unwrap();
        assert!(msg1.is_timestamp_valid());

        let msg2 = ChallengeMessage::new(vec![0u8; 32], now - 30, "test.com".to_string()).unwrap();
        assert!(msg2.is_timestamp_valid());

        let msg3 = ChallengeMessage::new(vec![0u8; 32], now + 30, "test.com".to_string()).unwrap();
        assert!(msg3.is_timestamp_valid());

        // Outside tolerance
        let msg4 = ChallengeMessage::new(vec![0u8; 32], now - 120, "test.com".to_string()).unwrap();
        assert!(!msg4.is_timestamp_valid());

        let msg5 = ChallengeMessage::new(vec![0u8; 32], now + 120, "test.com".to_string()).unwrap();
        assert!(!msg5.is_timestamp_valid());
    }
}
