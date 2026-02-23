//! Delegation token validation and constraint checking

use locd_core::{
    constants::*,
    error::{Error, Result},
};

use crate::token::DelegationToken;

/// Context for validating a delegation token
pub struct ValidationContext {
    /// Current timestamp for expiry checking
    pub current_time: u64,
    /// Service being accessed
    pub service: Option<String>,
    /// Action being performed
    pub action: Option<String>,
    /// Current use count (for max_uses checking)
    pub use_count: Option<u64>,
}

impl ValidationContext {
    /// Create a new validation context with current time
    pub fn new() -> Self {
        Self {
            current_time: crate::current_timestamp(),
            service: None,
            action: None,
            use_count: None,
        }
    }

    /// Set the service being accessed
    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }

    /// Set the action being performed
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Set the current use count
    pub fn with_use_count(mut self, count: u64) -> Self {
        self.use_count = Some(count);
        self
    }

    /// Set a custom timestamp (for testing)
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.current_time = timestamp;
        self
    }
}

impl Default for ValidationContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Validator for delegation tokens
pub struct DelegationValidator;

impl DelegationValidator {
    /// Validate a delegation token against a context
    ///
    /// Performs all constraint checks:
    /// - Not expired
    /// - Service permitted (if specified)
    /// - Action permitted (if specified)
    /// - Max uses not exceeded (if specified)
    /// - Timestamp tolerance (if issued_at is in future)
    pub fn validate(token: &DelegationToken, context: &ValidationContext) -> Result<()> {
        // Check expiry
        if context.current_time >= token.expires_at {
            return Err(Error::DelegationExpired(token.expires_at));
        }

        // Check issued_at is not too far in the future (clock skew tolerance)
        if token.issued_at > context.current_time + TIMESTAMP_TOLERANCE_SECS {
            return Err(Error::TimestampOutOfTolerance(token.issued_at));
        }

        // Check service scope
        if let Some(ref service) = context.service {
            if !Self::check_service_permitted(token, service)? {
                return Err(Error::ServiceNotPermitted(service.clone()));
            }
        }

        // Check action scope
        if let Some(ref action) = context.action {
            if !Self::check_action_permitted(token, action)? {
                return Err(Error::ActionNotPermitted(action.clone()));
            }
        }

        // Check max uses
        if let Some(use_count) = context.use_count {
            if token.max_uses > 0 && use_count >= token.max_uses {
                return Err(Error::MaxUsesExceeded(token.max_uses));
            }
        }

        Ok(())
    }

    /// Check if a service is permitted by the delegation
    fn check_service_permitted(token: &DelegationToken, service: &str) -> Result<bool> {
        // If no services specified, all services are permitted
        if token.services.is_empty() {
            return Ok(true);
        }

        // Check if any service pattern matches
        for pattern in &token.services {
            if pattern.matches(service) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Check if an action is permitted by the delegation
    fn check_action_permitted(token: &DelegationToken, action: &str) -> Result<bool> {
        // If no actions specified, all actions are permitted
        if token.actions.is_empty() {
            return Ok(true);
        }

        // Check if any action pattern matches
        for pattern in &token.actions {
            if pattern.matches(action) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Check if a delegation has expired
    pub fn is_expired(token: &DelegationToken, now: u64) -> bool {
        now >= token.expires_at
    }

    /// Get remaining validity duration in seconds
    pub fn remaining_validity(token: &DelegationToken, now: u64) -> i64 {
        (token.expires_at as i64) - (now as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use locd_crypto::Ed25519KeyPair;

    fn create_test_token() -> DelegationToken {
        let master = Ed25519KeyPair::generate();
        let device = Ed25519KeyPair::generate();

        DelegationToken::builder()
            .delegator(master.public_key().to_bytes())
            .delegate(device.public_key().to_bytes())
            .expires_in(3600)
            .service("api.example.com")
            .service("*.example.org")
            .action("read")
            .action("write")
            .max_uses(100)
            .build()
            .unwrap()
    }

    #[test]
    fn test_valid_delegation() {
        let token = create_test_token();
        let context = ValidationContext::new()
            .with_service("api.example.com")
            .with_action("read")
            .with_use_count(50);

        assert!(DelegationValidator::validate(&token, &context).is_ok());
    }

    #[test]
    fn test_expired_delegation() {
        let token = create_test_token();
        let context = ValidationContext::new().with_timestamp(token.expires_at + 1);

        let result = DelegationValidator::validate(&token, &context);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::DelegationExpired(_)));
    }

    #[test]
    fn test_service_not_permitted() {
        let token = create_test_token();
        let context = ValidationContext::new()
            .with_service("api.other.com")
            .with_action("read");

        let result = DelegationValidator::validate(&token, &context);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::ServiceNotPermitted(_)));
    }

    #[test]
    fn test_wildcard_service_match() {
        let token = create_test_token();
        let context = ValidationContext::new()
            .with_service("web.example.org")
            .with_action("read");

        assert!(DelegationValidator::validate(&token, &context).is_ok());
    }

    #[test]
    fn test_action_not_permitted() {
        let token = create_test_token();
        let context = ValidationContext::new()
            .with_service("api.example.com")
            .with_action("delete");

        let result = DelegationValidator::validate(&token, &context);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::ActionNotPermitted(_)));
    }

    #[test]
    fn test_max_uses_exceeded() {
        let token = create_test_token();
        let context = ValidationContext::new()
            .with_service("api.example.com")
            .with_action("read")
            .with_use_count(100);

        let result = DelegationValidator::validate(&token, &context);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::MaxUsesExceeded(_)));
    }

    #[test]
    fn test_empty_services_permits_all() {
        let master = Ed25519KeyPair::generate();
        let device = Ed25519KeyPair::generate();

        let token = DelegationToken::builder()
            .delegator(master.public_key().to_bytes())
            .delegate(device.public_key().to_bytes())
            .expires_in(3600)
            .action("read")
            .build()
            .unwrap();

        let context = ValidationContext::new()
            .with_service("any.service.com")
            .with_action("read");

        assert!(DelegationValidator::validate(&token, &context).is_ok());
    }

    #[test]
    fn test_empty_actions_permits_all() {
        let master = Ed25519KeyPair::generate();
        let device = Ed25519KeyPair::generate();

        let token = DelegationToken::builder()
            .delegator(master.public_key().to_bytes())
            .delegate(device.public_key().to_bytes())
            .expires_in(3600)
            .service("api.example.com")
            .build()
            .unwrap();

        let context = ValidationContext::new()
            .with_service("api.example.com")
            .with_action("any_action");

        assert!(DelegationValidator::validate(&token, &context).is_ok());
    }

    #[test]
    fn test_is_expired() {
        let token = create_test_token();
        assert!(!DelegationValidator::is_expired(&token, token.issued_at));
        assert!(DelegationValidator::is_expired(&token, token.expires_at));
        assert!(DelegationValidator::is_expired(
            &token,
            token.expires_at + 100
        ));
    }

    #[test]
    fn test_remaining_validity() {
        let token = create_test_token();
        let remaining = DelegationValidator::remaining_validity(&token, token.issued_at);
        assert!(remaining > 0);
        assert!(remaining <= 3600);

        let remaining_expired =
            DelegationValidator::remaining_validity(&token, token.expires_at + 10);
        assert!(remaining_expired < 0);
    }
}
