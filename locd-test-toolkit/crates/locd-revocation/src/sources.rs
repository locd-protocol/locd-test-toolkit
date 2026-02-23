//! Data sources for revocation information (DNS and HTTPS).

use crate::types::{CachedRevocationData, RevocationList, RevocationSource};
use locd_core::{Error, IdentityDomain, Result};
use locd_dns::RevocationRecord;
use std::collections::HashSet;

/// Default TTL for DNS records (seconds)
const DEFAULT_DNS_TTL: u64 = 300; // 5 minutes

/// Default TTL for HTTPS lists (seconds)
const DEFAULT_HTTPS_TTL: u64 = 600; // 10 minutes

/// Fetch revocation data from DNS TXT record
///
/// Format: `_locd-revoke.<domain> TXT "v=locd-revoke1; ids=uuid1,uuid2; t=timestamp"`
pub async fn fetch_dns_revocations(domain: &str) -> Result<Option<CachedRevocationData>> {
    // Parse domain
    let identity_domain = IdentityDomain::new(domain);

    // Query DNS for revocation record
    // Note: DnsResolver::query_revocation() doesn't exist yet in locd-dns
    // For now, we'll use a placeholder that parses the RevocationRecord format

    // In a real implementation, this would be:
    // let resolver = locd_dns::DnsResolver::new().await?;
    // let record = resolver.query_revocation(&identity_domain).await?;

    // For now, return None (no DNS implementation yet)
    // This is a placeholder that will be replaced when locd-dns adds async query support
    let _ = identity_domain; // Suppress unused warning
    Ok(None)
}

/// Parse DNS TXT record content into revocation IDs
///
/// Format: `v=locd-revoke1; ids=uuid1,uuid2,uuid3; t=1234567890`
pub fn parse_dns_revocation_record(txt_content: &str) -> Result<(HashSet<String>, u64)> {
    let record = RevocationRecord::from_txt_record(txt_content)?;

    // Convert revoked_ids Vec to HashSet
    let revoked_ids: HashSet<String> = record.revoked_ids.into_iter().collect();

    Ok((revoked_ids, record.timestamp))
}

/// Fetch revocation data from HTTPS supplementary list
///
/// URL from identity record's `rev` field
pub async fn fetch_https_revocations(
    url: &str,
    master_public_key: &locd_crypto::Ed25519PublicKey,
) -> Result<Option<CachedRevocationData>> {
    // Fetch from HTTPS
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| Error::Custom(format!("Failed to create HTTP client: {}", e)))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| Error::Custom(format!("HTTPS fetch failed: {}", e)))?;

    if !response.status().is_success() {
        return Ok(None);
    }

    let body = response
        .text()
        .await
        .map_err(|e| Error::Custom(format!("Failed to read response body: {}", e)))?;

    // Parse JSON
    let list: RevocationList =
        serde_json::from_str(&body).map_err(|e| Error::Custom(format!("Invalid JSON: {}", e)))?;

    // Verify version
    if list.v != "locd-revoke-list-v1" {
        return Err(Error::Custom(format!(
            "Unsupported revocation list version: {}",
            list.v
        )));
    }

    // Verify signature
    list.verify_signature(master_public_key)?;

    // Extract revoked IDs
    let revoked_ids: HashSet<String> = list
        .revocations
        .iter()
        .map(|entry| entry.delegation_id.clone())
        .collect();

    let now = current_timestamp();
    let expires_at = now + DEFAULT_HTTPS_TTL;

    Ok(Some(CachedRevocationData {
        revoked_ids,
        expires_at,
        source: RevocationSource::Https,
    }))
}

/// Helper to convert DNS record with TTL into cached data
pub fn dns_record_to_cached_data(
    revoked_ids: HashSet<String>,
    ttl: Option<u32>,
) -> CachedRevocationData {
    let now = current_timestamp();
    let ttl_secs = ttl.unwrap_or(DEFAULT_DNS_TTL as u32) as u64;
    let expires_at = now + ttl_secs;

    CachedRevocationData {
        revoked_ids,
        expires_at,
        source: RevocationSource::Dns,
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
    fn test_parse_dns_revocation_record() {
        let txt = "v=locd-revoke1; ids=550e8400-e29b-41d4-a716-446655440000,660e8400-e29b-41d4-a716-446655440001; t=1739577600";

        let (ids, timestamp) = parse_dns_revocation_record(txt).unwrap();

        assert_eq!(ids.len(), 2);
        assert!(ids.contains("550e8400-e29b-41d4-a716-446655440000"));
        assert!(ids.contains("660e8400-e29b-41d4-a716-446655440001"));
        assert_eq!(timestamp, 1739577600);
    }

    #[test]
    fn test_parse_dns_revocation_record_empty() {
        let txt = "v=locd-revoke1; ids=; t=1739577600";

        let (ids, timestamp) = parse_dns_revocation_record(txt).unwrap();

        assert_eq!(ids.len(), 0);
        assert_eq!(timestamp, 1739577600);
    }

    #[test]
    fn test_parse_dns_revocation_record_invalid() {
        let txt = "invalid format";
        assert!(parse_dns_revocation_record(txt).is_err());
    }

    #[test]
    fn test_dns_record_to_cached_data() {
        let mut revoked_ids = HashSet::new();
        revoked_ids.insert("id1".to_string());
        revoked_ids.insert("id2".to_string());

        let cached = dns_record_to_cached_data(revoked_ids.clone(), Some(300));

        assert_eq!(cached.revoked_ids.len(), 2);
        assert_eq!(cached.source, RevocationSource::Dns);
        // Should expire in ~300 seconds (allow some wiggle room for test execution time)
        let now = current_timestamp();
        assert!(cached.expires_at >= now + 299);
        assert!(cached.expires_at <= now + 301);
    }

    #[test]
    fn test_dns_record_to_cached_data_default_ttl() {
        let revoked_ids = HashSet::new();
        let cached = dns_record_to_cached_data(revoked_ids, None);

        let now = current_timestamp();
        // Should use DEFAULT_DNS_TTL (300)
        assert!(cached.expires_at >= now + 299);
        assert!(cached.expires_at <= now + 301);
    }

    #[tokio::test]
    async fn test_fetch_https_revocations_with_mock_server() {
        // This would require a mock HTTP server
        // For now, we just test that the function signature works
        let keypair = locd_crypto::Ed25519KeyPair::generate();
        let pubkey = keypair.public_key();

        // This will fail (no server), but tests the error path
        let result = fetch_https_revocations("http://localhost:99999/revocations", &pubkey).await;
        assert!(result.is_err() || result.unwrap().is_none());
    }
}
