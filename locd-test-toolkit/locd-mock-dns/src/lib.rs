//! Mock DNS server for local testing

use std::collections::HashMap;
use std::net::SocketAddr;
use locd_dns::{IdentityRecord, RevocationRecord};

pub struct MockDnsServer {
    records: HashMap<String, Vec<DnsRecord>>,
    #[allow(dead_code)]
    addr: SocketAddr,
}

pub enum DnsRecord {
    Identity(IdentityRecord),
    Revocation(RevocationRecord),
}

impl MockDnsServer {
    pub fn new(port: u16) -> Self {
        Self {
            records: HashMap::new(),
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }

    pub fn add_identity_record(&mut self, domain: &str, record: IdentityRecord) {
        let key = format!("_locd.{}", domain);
        self.records
            .entry(key)
            .or_insert_with(Vec::new)
            .push(DnsRecord::Identity(record));
    }

    pub fn add_revocation_record(&mut self, domain: &str, record: RevocationRecord) {
        let key = format!("_locd-revoke.{}", domain);
        self.records
            .entry(key)
            .or_insert_with(Vec::new)
            .push(DnsRecord::Revocation(record));
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        // TODO: Implement DNS server loop using trust-dns-server
        // Listen on port 5353 (mDNS)
        // Respond to TXT queries with mock data
        todo!("Implement DNS server loop")
    }

    pub fn clear(&mut self) {
        self.records.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use locd_crypto::Ed25519KeyPair;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_mock_dns_creation() {
        let server = MockDnsServer::new(5353);
        assert_eq!(server.records.len(), 0);
    }

    #[test]
    fn test_add_identity_record() {
        let mut server = MockDnsServer::new(5353);
        let keypair = Ed25519KeyPair::generate();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let record = IdentityRecord::new(&keypair.public_key().to_bytes(), timestamp);
        server.add_identity_record("example.com", record);

        assert_eq!(server.records.len(), 1);
        assert!(server.records.contains_key("_locd.example.com"));
    }

    #[test]
    fn test_add_revocation_record() {
        use locd_core::types::DelegationId;

        let mut server = MockDnsServer::new(5353);
        let ids = vec![DelegationId::new().to_string()];
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let record = RevocationRecord::new(ids, timestamp);
        server.add_revocation_record("example.com", record);

        assert_eq!(server.records.len(), 1);
        assert!(server.records.contains_key("_locd-revoke.example.com"));
    }

    #[test]
    fn test_clear() {
        let mut server = MockDnsServer::new(5353);
        let keypair = Ed25519KeyPair::generate();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let record = IdentityRecord::new(&keypair.public_key().to_bytes(), timestamp);
        server.add_identity_record("example.com", record);

        assert_eq!(server.records.len(), 1);

        server.clear();
        assert_eq!(server.records.len(), 0);
    }
}
