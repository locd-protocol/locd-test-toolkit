//! Delegation token structure and creation

use ciborium::Value;
use locd_core::{
    constants::*,
    error::{Error, Result},
    types::{ActionPattern, DelegationId, ServicePattern},
};
use locd_crypto::{Ed25519KeyPair, Ed25519PublicKey};
use serde::{Deserialize, Serialize};

/// Delegation token structure (spec §6.2)
///
/// This represents a delegation token that grants a Device Key scoped
/// authority to act on behalf of a Master Key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationToken {
    /// Delegator's Master Key public key (32 bytes)
    pub delegator: Vec<u8>,
    /// Delegate's Device Key public key (32 bytes)
    pub delegate: Vec<u8>,
    /// Issued-at timestamp (Unix timestamp)
    pub issued_at: u64,
    /// Expires-at timestamp (Unix timestamp)
    pub expires_at: u64,
    /// Delegation ID (UUID v4)
    pub delegation_id: DelegationId,
    /// Permitted services (domain patterns)
    pub services: Vec<ServicePattern>,
    /// Permitted actions
    pub actions: Vec<ActionPattern>,
    /// Maximum number of uses (0 = unlimited)
    pub max_uses: u64,
    /// Device attestation (optional TPM quote)
    pub attestation: Option<Vec<u8>>,
    /// Can create sub-delegations
    pub can_sub_delegate: bool,
}

impl DelegationToken {
    /// Create a new delegation token builder
    pub fn builder() -> DelegationTokenBuilder {
        DelegationTokenBuilder::new()
    }

    /// Encode the token to CBOR
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut map = Vec::new();

        // Type identifier
        map.push((
            Value::Integer(CBOR_KEY_TYPE.into()),
            Value::Text(locd_core::DELEGATION_TYPE.to_string()),
        ));

        // Delegator public key
        map.push((
            Value::Integer(CBOR_KEY_DELEGATOR.into()),
            Value::Bytes(self.delegator.clone()),
        ));

        // Delegate public key
        map.push((
            Value::Integer(CBOR_KEY_DELEGATE.into()),
            Value::Bytes(self.delegate.clone()),
        ));

        // Issued-at timestamp
        map.push((
            Value::Integer(CBOR_KEY_ISSUED_AT.into()),
            Value::Integer(self.issued_at.into()),
        ));

        // Expires-at timestamp
        map.push((
            Value::Integer(CBOR_KEY_EXPIRES_AT.into()),
            Value::Integer(self.expires_at.into()),
        ));

        // Delegation ID
        map.push((
            Value::Integer(CBOR_KEY_DELEGATION_ID.into()),
            Value::Text(self.delegation_id.to_string()),
        ));

        // Services
        if !self.services.is_empty() {
            let services: Vec<Value> = self
                .services
                .iter()
                .map(|s| Value::Text(s.as_str().to_string()))
                .collect();
            map.push((Value::Integer(CBOR_KEY_SERVICES.into()), Value::Array(services)));
        }

        // Actions
        if !self.actions.is_empty() {
            let actions: Vec<Value> = self
                .actions
                .iter()
                .map(|a| Value::Text(a.as_str().to_string()))
                .collect();
            map.push((Value::Integer(CBOR_KEY_ACTIONS.into()), Value::Array(actions)));
        }

        // Max uses
        if self.max_uses > 0 {
            map.push((
                Value::Integer(CBOR_KEY_MAX_USES.into()),
                Value::Integer(self.max_uses.into()),
            ));
        }

        // Attestation
        if let Some(ref attestation) = self.attestation {
            map.push((
                Value::Integer(CBOR_KEY_ATTESTATION.into()),
                Value::Bytes(attestation.clone()),
            ));
        }

        // Can sub-delegate
        map.push((
            Value::Integer(CBOR_KEY_CAN_SUB_DELEGATE.into()),
            Value::Bool(self.can_sub_delegate),
        ));

        let cbor_value = Value::Map(map);
        let mut buffer = Vec::new();
        ciborium::into_writer(&cbor_value, &mut buffer)
            .map_err(|e| Error::Encoding(format!("CBOR encoding failed: {}", e)))?;

        Ok(buffer)
    }

    /// Decode a token from CBOR
    pub fn from_cbor(cbor: &[u8]) -> Result<Self> {
        let value: Value = ciborium::from_reader(cbor)
            .map_err(|e| Error::Decoding(format!("CBOR decoding failed: {}", e)))?;

        let map_vec = match value {
            Value::Map(m) => m,
            _ => return Err(Error::InvalidDelegation("Expected CBOR map".to_string())),
        };

        // Helper to find value in map by key
        let find_value = |key: i64| -> Option<&Value> {
            for (k, v) in &map_vec {
                if let Value::Integer(i) = k {
                    if *i == key.into() {
                        return Some(v);
                    }
                }
            }
            None
        };

        // Helper to get value from map
        let get_bytes = |key: i64| -> Result<Vec<u8>> {
            match find_value(key) {
                Some(Value::Bytes(b)) => Ok(b.clone()),
                _ => Err(Error::InvalidDelegation(format!("Missing or invalid key {}", key))),
            }
        };

        let get_u64 = |key: i64| -> Result<u64> {
            match find_value(key) {
                Some(Value::Integer(i)) => Ok((*i).try_into().map_err(|_| {
                    Error::InvalidDelegation(format!("Invalid integer for key {}", key))
                })?),
                _ => Err(Error::InvalidDelegation(format!("Missing or invalid key {}", key))),
            }
        };

        let get_text = |key: i64| -> Result<String> {
            match find_value(key) {
                Some(Value::Text(s)) => Ok(s.clone()),
                _ => Err(Error::InvalidDelegation(format!("Missing or invalid key {}", key))),
            }
        };

        let get_bool = |key: i64, default: bool| -> bool {
            match find_value(key) {
                Some(Value::Bool(b)) => *b,
                _ => default,
            }
        };

        // Parse services
        let services = match find_value(CBOR_KEY_SERVICES) {
            Some(Value::Array(arr)) => {
                let mut svc = Vec::new();
                for v in arr {
                    if let Value::Text(s) = v {
                        svc.push(ServicePattern::new(s.clone()));
                    }
                }
                svc
            }
            _ => Vec::new(),
        };

        // Parse actions
        let actions = match find_value(CBOR_KEY_ACTIONS) {
            Some(Value::Array(arr)) => {
                let mut act = Vec::new();
                for v in arr {
                    if let Value::Text(s) = v {
                        act.push(ActionPattern::new(s.clone()));
                    }
                }
                act
            }
            _ => Vec::new(),
        };

        // Parse optional attestation
        let attestation = match find_value(CBOR_KEY_ATTESTATION) {
            Some(Value::Bytes(b)) => Some(b.clone()),
            _ => None,
        };

        let delegation_id =
            DelegationId::from_string(&get_text(CBOR_KEY_DELEGATION_ID)?).map_err(|e| {
                Error::InvalidDelegation(format!("Invalid delegation ID: {}", e))
            })?;

        Ok(Self {
            delegator: get_bytes(CBOR_KEY_DELEGATOR)?,
            delegate: get_bytes(CBOR_KEY_DELEGATE)?,
            issued_at: get_u64(CBOR_KEY_ISSUED_AT)?,
            expires_at: get_u64(CBOR_KEY_EXPIRES_AT)?,
            delegation_id,
            services,
            actions,
            max_uses: find_value(CBOR_KEY_MAX_USES)
                .and_then(|v| match v {
                    Value::Integer(i) => (*i).try_into().ok(),
                    _ => None,
                })
                .unwrap_or(0),
            attestation,
            can_sub_delegate: get_bool(CBOR_KEY_CAN_SUB_DELEGATE, false),
        })
    }

    /// Sign the token with a Master Key, producing a COSE Sign1 structure
    pub fn sign(&self, master_key: &Ed25519KeyPair) -> Result<Vec<u8>> {
        let payload = self.to_cbor()?;

        // For simplicity, we'll create a minimal COSE-like structure manually
        // In production, you'd use proper COSE library integration

        // Create a simple CBOR array: [protected, unprotected, payload, signature]
        // This is a simplified COSE Sign1 structure
        let signature = master_key.sign_bytes(&payload);

        let structure = Value::Array(vec![
            Value::Bytes(vec![]), // empty protected header
            Value::Map(vec![]),    // empty unprotected header
            Value::Bytes(payload),
            Value::Bytes(signature),
        ]);

        let mut buffer = Vec::new();
        ciborium::into_writer(&structure, &mut buffer)
            .map_err(|e| Error::Encoding(format!("COSE Sign1 encoding failed: {}", e)))?;

        Ok(buffer)
    }

    /// Verify a signed delegation token
    pub fn verify(cose_sign1_bytes: &[u8], master_public_key: &Ed25519PublicKey) -> Result<Self> {
        // Deserialize COSE Sign1 structure
        let value: Value = ciborium::from_reader(cose_sign1_bytes)
            .map_err(|e| Error::Decoding(format!("COSE Sign1 decoding failed: {}", e)))?;

        // Extract array elements
        let elements = match value {
            Value::Array(arr) => arr,
            _ => return Err(Error::InvalidDelegation("Expected CBOR array for COSE Sign1".to_string())),
        };

        if elements.len() != 4 {
            return Err(Error::InvalidDelegation("Invalid COSE Sign1 structure".to_string()));
        }

        // Extract payload and signature
        let payload = match &elements[2] {
            Value::Bytes(b) => b,
            _ => return Err(Error::InvalidDelegation("Invalid payload".to_string())),
        };

        let signature = match &elements[3] {
            Value::Bytes(b) => b,
            _ => return Err(Error::InvalidDelegation("Invalid signature".to_string())),
        };

        // Verify signature
        master_public_key
            .verify_bytes(payload, signature)
            .map_err(|_| Error::InvalidDelegation("Signature verification failed".to_string()))?;

        // Decode the delegation token from the payload
        Self::from_cbor(payload)
    }
}

/// Builder for creating delegation tokens
pub struct DelegationTokenBuilder {
    delegator: Option<Vec<u8>>,
    delegate: Option<Vec<u8>>,
    issued_at: Option<u64>,
    expires_at: Option<u64>,
    delegation_id: Option<DelegationId>,
    services: Vec<ServicePattern>,
    actions: Vec<ActionPattern>,
    max_uses: u64,
    attestation: Option<Vec<u8>>,
    can_sub_delegate: bool,
}

impl DelegationTokenBuilder {
    pub fn new() -> Self {
        Self {
            delegator: None,
            delegate: None,
            issued_at: None,
            expires_at: None,
            delegation_id: None,
            services: Vec::new(),
            actions: Vec::new(),
            max_uses: 0,
            attestation: None,
            can_sub_delegate: false,
        }
    }

    pub fn delegator(mut self, public_key: Vec<u8>) -> Self {
        self.delegator = Some(public_key);
        self
    }

    pub fn delegate(mut self, public_key: Vec<u8>) -> Self {
        self.delegate = Some(public_key);
        self
    }

    pub fn issued_at(mut self, timestamp: u64) -> Self {
        self.issued_at = Some(timestamp);
        self
    }

    pub fn expires_at(mut self, timestamp: u64) -> Self {
        self.expires_at = Some(timestamp);
        self
    }

    pub fn expires_in(mut self, duration_secs: u64) -> Self {
        let now = crate::current_timestamp();
        self.expires_at = Some(now + duration_secs);
        if self.issued_at.is_none() {
            self.issued_at = Some(now);
        }
        self
    }

    pub fn delegation_id(mut self, id: DelegationId) -> Self {
        self.delegation_id = Some(id);
        self
    }

    pub fn service(mut self, pattern: impl Into<ServicePattern>) -> Self {
        self.services.push(pattern.into());
        self
    }

    pub fn services(mut self, patterns: Vec<ServicePattern>) -> Self {
        self.services = patterns;
        self
    }

    pub fn action(mut self, pattern: impl Into<ActionPattern>) -> Self {
        self.actions.push(pattern.into());
        self
    }

    pub fn actions(mut self, patterns: Vec<ActionPattern>) -> Self {
        self.actions = patterns;
        self
    }

    pub fn max_uses(mut self, count: u64) -> Self {
        self.max_uses = count;
        self
    }

    pub fn attestation(mut self, data: Vec<u8>) -> Self {
        self.attestation = Some(data);
        self
    }

    pub fn can_sub_delegate(mut self, enabled: bool) -> Self {
        self.can_sub_delegate = enabled;
        self
    }

    pub fn build(self) -> Result<DelegationToken> {
        let delegator = self
            .delegator
            .ok_or_else(|| Error::InvalidDelegation("Missing delegator".to_string()))?;
        let delegate = self
            .delegate
            .ok_or_else(|| Error::InvalidDelegation("Missing delegate".to_string()))?;

        let now = crate::current_timestamp();
        let issued_at = self.issued_at.unwrap_or(now);
        let expires_at = self
            .expires_at
            .unwrap_or(issued_at + DEFAULT_DELEGATION_DURATION_SECS);

        // Validate duration
        if expires_at <= issued_at {
            return Err(Error::InvalidDelegation(
                "Expiry must be after issuance".to_string(),
            ));
        }

        if expires_at - issued_at > MAX_DELEGATION_DURATION_SECS {
            return Err(Error::InvalidDelegation(format!(
                "Duration exceeds maximum of {} seconds",
                MAX_DELEGATION_DURATION_SECS
            )));
        }

        let delegation_id = self.delegation_id.unwrap_or_else(DelegationId::new);

        Ok(DelegationToken {
            delegator,
            delegate,
            issued_at,
            expires_at,
            delegation_id,
            services: self.services,
            actions: self.actions,
            max_uses: self.max_uses,
            attestation: self.attestation,
            can_sub_delegate: self.can_sub_delegate,
        })
    }
}

impl Default for DelegationTokenBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use locd_crypto::Ed25519KeyPair;

    #[test]
    fn test_token_builder() {
        let master = Ed25519KeyPair::generate();
        let device = Ed25519KeyPair::generate();

        let token = DelegationToken::builder()
            .delegator(master.public_key().to_bytes())
            .delegate(device.public_key().to_bytes())
            .expires_in(3600)
            .service("api.example.com")
            .action("read")
            .action("write")
            .max_uses(100)
            .build()
            .unwrap();

        assert_eq!(token.services.len(), 1);
        assert_eq!(token.actions.len(), 2);
        assert_eq!(token.max_uses, 100);
    }

    #[test]
    fn test_cbor_roundtrip() {
        let master = Ed25519KeyPair::generate();
        let device = Ed25519KeyPair::generate();

        let token1 = DelegationToken::builder()
            .delegator(master.public_key().to_bytes())
            .delegate(device.public_key().to_bytes())
            .expires_in(3600)
            .service("*.example.com")
            .action("*")
            .build()
            .unwrap();

        let cbor = token1.to_cbor().unwrap();
        let token2 = DelegationToken::from_cbor(&cbor).unwrap();

        assert_eq!(token1.delegator, token2.delegator);
        assert_eq!(token1.delegate, token2.delegate);
        assert_eq!(token1.issued_at, token2.issued_at);
        assert_eq!(token1.expires_at, token2.expires_at);
        assert_eq!(token1.delegation_id.to_string(), token2.delegation_id.to_string());
    }

    #[test]
    fn test_sign_verify() {
        let master = Ed25519KeyPair::generate();
        let device = Ed25519KeyPair::generate();

        let token = DelegationToken::builder()
            .delegator(master.public_key().to_bytes())
            .delegate(device.public_key().to_bytes())
            .expires_in(3600)
            .service("api.example.com")
            .action("read")
            .build()
            .unwrap();

        let signed = token.sign(&master).unwrap();
        let verified = DelegationToken::verify(&signed, &master.public_key()).unwrap();

        assert_eq!(token.delegator, verified.delegator);
        assert_eq!(token.delegate, verified.delegate);
    }

    #[test]
    fn test_invalid_signature() {
        let master = Ed25519KeyPair::generate();
        let wrong_key = Ed25519KeyPair::generate();
        let device = Ed25519KeyPair::generate();

        let token = DelegationToken::builder()
            .delegator(master.public_key().to_bytes())
            .delegate(device.public_key().to_bytes())
            .expires_in(3600)
            .build()
            .unwrap();

        let signed = token.sign(&master).unwrap();
        let result = DelegationToken::verify(&signed, &wrong_key.public_key());

        assert!(result.is_err());
    }

    #[test]
    fn test_duration_validation() {
        let master = Ed25519KeyPair::generate();
        let device = Ed25519KeyPair::generate();

        // Too long duration
        let result = DelegationToken::builder()
            .delegator(master.public_key().to_bytes())
            .delegate(device.public_key().to_bytes())
            .expires_in(MAX_DELEGATION_DURATION_SECS + 1)
            .build();

        assert!(result.is_err());
    }
}
