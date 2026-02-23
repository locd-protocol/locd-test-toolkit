//! TTL cache for revocation data.

use crate::types::{CachedRevocationData, RevocationSource};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

/// Thread-safe TTL cache for revocation data
#[derive(Clone)]
pub struct RevocationCache {
    inner: Arc<RwLock<HashMap<String, CachedRevocationData>>>,
}

impl RevocationCache {
    /// Create a new empty cache
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get cached revocation data for a domain
    ///
    /// Returns None if not cached or expired
    pub fn get(&self, domain: &str) -> Option<CachedRevocationData> {
        let now = current_timestamp();
        let cache = self.inner.read().ok()?;

        cache.get(domain).and_then(|entry| {
            if entry.expires_at > now {
                Some(entry.clone())
            } else {
                None
            }
        })
    }

    /// Store revocation data in cache
    pub fn put(&self, domain: String, data: CachedRevocationData) {
        if let Ok(mut cache) = self.inner.write() {
            cache.insert(domain, data);
        }
    }

    /// Merge DNS and HTTPS revocation data
    ///
    /// DNS is authoritative, HTTPS provides additional IDs
    /// TTL is minimum of both sources
    pub fn put_merged(
        &self,
        domain: String,
        dns_data: Option<CachedRevocationData>,
        https_data: Option<CachedRevocationData>,
    ) {
        let mut merged_ids = HashSet::new();
        let mut min_expires_at = u64::MAX;

        if let Some(dns) = dns_data {
            merged_ids.extend(dns.revoked_ids);
            min_expires_at = min_expires_at.min(dns.expires_at);
        }

        if let Some(https) = https_data {
            merged_ids.extend(https.revoked_ids);
            min_expires_at = min_expires_at.min(https.expires_at);
        }

        if !merged_ids.is_empty() {
            let merged = CachedRevocationData {
                revoked_ids: merged_ids,
                expires_at: min_expires_at,
                source: RevocationSource::Merged,
            };
            self.put(domain, merged);
        }
    }

    /// Clear expired entries
    pub fn cleanup(&self) {
        let now = current_timestamp();
        if let Ok(mut cache) = self.inner.write() {
            cache.retain(|_, entry| entry.expires_at > now);
        }
    }

    /// Clear all entries
    pub fn clear(&self) {
        if let Ok(mut cache) = self.inner.write() {
            cache.clear();
        }
    }

    /// Get number of cached entries
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.read().map(|c| c.len()).unwrap_or(0)
    }
}

impl Default for RevocationCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Get current Unix timestamp in seconds
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
    fn test_cache_put_get() {
        let cache = RevocationCache::new();
        let domain = "example.com";

        let mut revoked_ids = HashSet::new();
        revoked_ids.insert("id1".to_string());
        revoked_ids.insert("id2".to_string());

        let data = CachedRevocationData {
            revoked_ids: revoked_ids.clone(),
            expires_at: current_timestamp() + 300, // 5 minutes
            source: RevocationSource::Dns,
        };

        cache.put(domain.to_string(), data);

        let cached = cache.get(domain).expect("Should be cached");
        assert_eq!(cached.revoked_ids.len(), 2);
        assert!(cached.revoked_ids.contains("id1"));
        assert!(cached.revoked_ids.contains("id2"));
        assert_eq!(cached.source, RevocationSource::Dns);
    }

    #[test]
    fn test_cache_expiry() {
        let cache = RevocationCache::new();
        let domain = "example.com";

        let data = CachedRevocationData {
            revoked_ids: HashSet::new(),
            expires_at: current_timestamp() - 1, // Already expired
            source: RevocationSource::Dns,
        };

        cache.put(domain.to_string(), data);

        // Should return None for expired entry
        assert!(cache.get(domain).is_none());
    }

    #[test]
    fn test_cache_merge() {
        let cache = RevocationCache::new();
        let domain = "example.com";

        let mut dns_ids = HashSet::new();
        dns_ids.insert("id1".to_string());
        dns_ids.insert("id2".to_string());

        let dns_data = CachedRevocationData {
            revoked_ids: dns_ids,
            expires_at: current_timestamp() + 300,
            source: RevocationSource::Dns,
        };

        let mut https_ids = HashSet::new();
        https_ids.insert("id2".to_string()); // Overlapping
        https_ids.insert("id3".to_string());

        let https_data = CachedRevocationData {
            revoked_ids: https_ids,
            expires_at: current_timestamp() + 600,
            source: RevocationSource::Https,
        };

        cache.put_merged(domain.to_string(), Some(dns_data), Some(https_data));

        let merged = cache.get(domain).expect("Should be cached");
        assert_eq!(merged.revoked_ids.len(), 3); // id1, id2, id3
        assert_eq!(merged.source, RevocationSource::Merged);
        // TTL should be minimum (300)
        assert_eq!(merged.expires_at, current_timestamp() + 300);
    }

    #[test]
    fn test_cache_cleanup() {
        let cache = RevocationCache::new();

        // Add expired entry
        let expired = CachedRevocationData {
            revoked_ids: HashSet::new(),
            expires_at: current_timestamp() - 1,
            source: RevocationSource::Dns,
        };
        cache.put("expired.com".to_string(), expired);

        // Add valid entry
        let valid = CachedRevocationData {
            revoked_ids: HashSet::new(),
            expires_at: current_timestamp() + 300,
            source: RevocationSource::Dns,
        };
        cache.put("valid.com".to_string(), valid);

        assert_eq!(cache.len(), 2);

        cache.cleanup();

        assert_eq!(cache.len(), 1);
        assert!(cache.get("valid.com").is_some());
        assert!(cache.get("expired.com").is_none());
    }

    #[test]
    fn test_cache_clear() {
        let cache = RevocationCache::new();

        let data = CachedRevocationData {
            revoked_ids: HashSet::new(),
            expires_at: current_timestamp() + 300,
            source: RevocationSource::Dns,
        };

        cache.put("example.com".to_string(), data);
        assert_eq!(cache.len(), 1);

        cache.clear();
        assert_eq!(cache.len(), 0);
    }
}
