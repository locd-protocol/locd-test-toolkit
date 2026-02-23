//! RevocationChecker implementation with DNS and HTTPS support.

use crate::cache::RevocationCache;
use crate::sources::{fetch_dns_revocations, fetch_https_revocations};
use locd_core::{DelegationId, Result};

/// Full-featured revocation checker with DNS, HTTPS, and caching
///
/// Implements the layered revocation strategy from spec §8:
/// - Layer 1: Short-lived delegations (handled by expiry checks)
/// - Layer 2: DNS TXT records (authoritative)
/// - Layer 3: HTTPS supplementary lists (fast)
///
/// Uses a TTL cache to avoid repeated DNS/HTTPS queries
pub struct DefaultRevocationChecker {
    cache: RevocationCache,
    https_url_provider: Option<Box<dyn HttpsUrlProvider>>,
    master_key_provider: Option<Box<dyn MasterKeyProvider>>,
}

/// Trait for providing HTTPS revocation list URLs
pub trait HttpsUrlProvider: Send + Sync {
    fn get_url(&self, domain: &str) -> Option<String>;
}

/// Trait for providing master public keys for signature verification
pub trait MasterKeyProvider: Send + Sync {
    fn get_master_key(&self, domain: &str) -> Option<locd_crypto::Ed25519PublicKey>;
}

impl DefaultRevocationChecker {
    /// Create a new revocation checker with empty cache
    pub fn new() -> Self {
        Self {
            cache: RevocationCache::new(),
            https_url_provider: None,
            master_key_provider: None,
        }
    }

    /// Set HTTPS URL provider for supplementary list fetching
    pub fn with_https_provider(mut self, provider: Box<dyn HttpsUrlProvider>) -> Self {
        self.https_url_provider = Some(provider);
        self
    }

    /// Set master key provider for signature verification
    pub fn with_master_key_provider(mut self, provider: Box<dyn MasterKeyProvider>) -> Self {
        self.master_key_provider = Some(provider);
        self
    }

    /// Check if a delegation is revoked
    ///
    /// Strategy:
    /// 1. Check cache first
    /// 2. If cache miss or expired:
    ///    a. Fetch from DNS (authoritative)
    ///    b. Fetch from HTTPS (if URL available)
    ///    c. Merge results and cache
    /// 3. Return whether delegation ID is in revoked set
    pub async fn is_revoked_async(&self, domain: &str, delegation_id: &DelegationId) -> Result<bool> {
        let delegation_id_str = delegation_id.to_string();

        // Check cache
        if let Some(cached) = self.cache.get(domain) {
            return Ok(cached.revoked_ids.contains(&delegation_id_str));
        }

        // Cache miss - fetch from sources
        let dns_data = fetch_dns_revocations(domain).await?;

        let https_data = if let Some(ref provider) = self.https_url_provider {
            if let Some(url) = provider.get_url(domain) {
                if let Some(ref key_provider) = self.master_key_provider {
                    if let Some(master_key) = key_provider.get_master_key(domain) {
                        fetch_https_revocations(&url, &master_key).await?
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // Check if revoked before merging (since merge consumes the data)
        let is_revoked = dns_data.as_ref().map(|d| d.revoked_ids.contains(&delegation_id_str)).unwrap_or(false)
            || https_data.as_ref().map(|d| d.revoked_ids.contains(&delegation_id_str)).unwrap_or(false);

        // Merge and cache
        self.cache.put_merged(domain.to_string(), dns_data, https_data);

        Ok(is_revoked)
    }

    /// Clear the cache
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Clean up expired cache entries
    pub fn cleanup_cache(&self) {
        self.cache.cleanup();
    }
}

impl Default for DefaultRevocationChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Synchronous wrapper for DefaultRevocationChecker
///
/// Uses blocking tokio runtime for async operations
/// This allows integration with the synchronous RevocationChecker trait
pub struct BlockingRevocationChecker {
    inner: DefaultRevocationChecker,
    runtime: tokio::runtime::Runtime,
}

impl BlockingRevocationChecker {
    /// Create a new blocking revocation checker
    pub fn new() -> Result<Self> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| locd_core::Error::Custom(format!("Failed to create async runtime: {}", e)))?;

        Ok(Self {
            inner: DefaultRevocationChecker::new(),
            runtime,
        })
    }

    /// Set HTTPS URL provider
    pub fn with_https_provider(mut self, provider: Box<dyn HttpsUrlProvider>) -> Self {
        self.inner = self.inner.with_https_provider(provider);
        self
    }

    /// Set master key provider
    pub fn with_master_key_provider(mut self, provider: Box<dyn MasterKeyProvider>) -> Self {
        self.inner = self.inner.with_master_key_provider(provider);
        self
    }

    /// Check if delegation is revoked (blocking)
    pub fn is_revoked_blocking(&self, domain: &str, delegation_id: &DelegationId) -> Result<bool> {
        self.runtime.block_on(self.inner.is_revoked_async(domain, delegation_id))
    }
}

impl Default for BlockingRevocationChecker {
    fn default() -> Self {
        Self::new().expect("Failed to create default BlockingRevocationChecker")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};

    // Mock HTTPS URL provider
    struct MockHttpsProvider {
        urls: HashMap<String, String>,
    }

    impl MockHttpsProvider {
        fn new() -> Self {
            Self {
                urls: HashMap::new(),
            }
        }

        fn with_url(mut self, domain: &str, url: &str) -> Self {
            self.urls.insert(domain.to_string(), url.to_string());
            self
        }
    }

    impl HttpsUrlProvider for MockHttpsProvider {
        fn get_url(&self, domain: &str) -> Option<String> {
            self.urls.get(domain).cloned()
        }
    }

    // Mock master key provider
    struct MockMasterKeyProvider {
        keys: Arc<RwLock<HashMap<String, locd_crypto::Ed25519PublicKey>>>,
    }

    impl MockMasterKeyProvider {
        fn new() -> Self {
            Self {
                keys: Arc::new(RwLock::new(HashMap::new())),
            }
        }

        fn with_key(self, domain: &str, key: locd_crypto::Ed25519PublicKey) -> Self {
            if let Ok(mut keys) = self.keys.write() {
                keys.insert(domain.to_string(), key);
            }
            self
        }
    }

    impl MasterKeyProvider for MockMasterKeyProvider {
        fn get_master_key(&self, domain: &str) -> Option<locd_crypto::Ed25519PublicKey> {
            self.keys.read().ok()?.get(domain).cloned()
        }
    }

    #[tokio::test]
    async fn test_revocation_checker_cache() {
        let checker = DefaultRevocationChecker::new();

        // First check - cache miss, will query (and fail since no providers)
        let domain = "example.com";
        let delegation_id = DelegationId::new();

        let result = checker.is_revoked_async(domain, &delegation_id).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false); // Not revoked (no data sources)
    }

    #[tokio::test]
    async fn test_revocation_checker_with_providers() {
        let master_key = locd_crypto::Ed25519KeyPair::generate();
        let master_pubkey = master_key.public_key();

        let https_provider = MockHttpsProvider::new()
            .with_url("example.com", "https://example.com/.well-known/locd/revocations");

        let key_provider = MockMasterKeyProvider::new()
            .with_key("example.com", master_pubkey);

        let checker = DefaultRevocationChecker::new()
            .with_https_provider(Box::new(https_provider))
            .with_master_key_provider(Box::new(key_provider));

        let domain = "example.com";
        let delegation_id = DelegationId::new();

        // Will attempt to fetch (and fail since URL doesn't exist)
        let result = checker.is_revoked_async(domain, &delegation_id).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_blocking_revocation_checker() {
        let checker = BlockingRevocationChecker::new().unwrap();

        let domain = "example.com";
        let delegation_id = DelegationId::new();

        let result = checker.is_revoked_blocking(domain, &delegation_id);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_cache_cleanup() {
        let checker = DefaultRevocationChecker::new();

        // Add some data to cache (this requires direct cache access in real tests)
        checker.cleanup_cache();
        checker.clear_cache();

        // Just verify the methods work without panicking
    }
}
