//! Mock DNS server for local testing

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use locd_dns::{IdentityRecord, RevocationRecord};
use trust_dns_server::{
    authority::MessageResponseBuilder,
    proto::{
        op::{Header, ResponseCode},
        rr::{Name, RData, Record, RecordType},
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    ServerFuture,
};
use tokio::net::UdpSocket;

/// Mock DNS server for testing Loc'd Protocol
pub struct MockDnsServer {
    records: Arc<RwLock<HashMap<String, Vec<DnsRecord>>>>,
    addr: SocketAddr,
}

/// DNS record types supported by the mock server
#[derive(Clone)]
pub enum DnsRecord {
    Identity(IdentityRecord),
    Revocation(RevocationRecord),
}

impl MockDnsServer {
    /// Create a new mock DNS server listening on the specified port
    pub fn new(port: u16) -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }

    /// Add an identity record for a domain
    pub fn add_identity_record(&mut self, domain: &str, record: IdentityRecord) {
        let key = format!("_locd.{}", domain);
        self.records
            .write()
            .unwrap()
            .entry(key)
            .or_insert_with(Vec::new)
            .push(DnsRecord::Identity(record));
    }

    /// Add a revocation record for a domain
    pub fn add_revocation_record(&mut self, domain: &str, record: RevocationRecord) {
        let key = format!("_locd-revoke.{}", domain);
        self.records
            .write()
            .unwrap()
            .entry(key)
            .or_insert_with(Vec::new)
            .push(DnsRecord::Revocation(record));
    }

    /// Start the DNS server
    pub async fn start(&self) -> Result<(), anyhow::Error> {
        let socket = UdpSocket::bind(&self.addr).await?;
        println!("✓ Mock DNS server listening on {}", self.addr);

        let handler = MockDnsHandler {
            records: Arc::clone(&self.records),
        };

        let mut server = ServerFuture::new(handler);
        server.register_socket(socket);

        println!("✓ Ready to handle DNS queries for _locd.* domains");
        println!("  Press Ctrl+C to stop");

        // Run the server (this will block)
        server.block_until_done().await?;

        Ok(())
    }

    /// Clear all records
    pub fn clear(&mut self) {
        self.records.write().unwrap().clear();
    }

    /// Get a shared reference to the records (for testing)
    pub fn records(&self) -> Arc<RwLock<HashMap<String, Vec<DnsRecord>>>> {
        Arc::clone(&self.records)
    }
}

/// DNS request handler for the mock server
struct MockDnsHandler {
    records: Arc<RwLock<HashMap<String, Vec<DnsRecord>>>>,
}

#[async_trait::async_trait]
impl RequestHandler for MockDnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let request_message = request.request_info();
        let query = request.query();

        // Build response header
        let mut header = Header::response_from_request(request_message.header);
        header.set_authoritative(true);

        // Only handle TXT queries
        if query.query_type() != RecordType::TXT {
            header.set_response_code(ResponseCode::NotImp);
            let response = MessageResponseBuilder::from_message_request(request).build_no_records(header);
            return response_handle.send_response(response).await.unwrap_or_else(|e| {
                eprintln!("Error sending response: {}", e);
                header.into()
            });
        }

        let mut name_str = query.name().to_string();

        // Remove trailing dot from FQDN if present
        if name_str.ends_with('.') {
            name_str.pop();
        }

        // Clone records we need, then release the lock
        let dns_records_opt = {
            let records = self.records.read().unwrap();
            records.get(&name_str).cloned()
        };

        // Look up the record
        if let Some(dns_records) = dns_records_opt {
            let mut answers = Vec::new();

            for record in &dns_records {
                let txt_data = match record {
                    DnsRecord::Identity(id_record) => id_record.to_txt_record(),
                    DnsRecord::Revocation(rev_record) => rev_record.to_txt_record(),
                };

                // Create DNS record
                let name: Name = query.name().clone().into();
                let mut dns_record = Record::with(
                    name,
                    RecordType::TXT,
                    300, // TTL: 5 minutes
                );
                dns_record.set_data(Some(RData::TXT(
                    trust_dns_server::proto::rr::rdata::TXT::new(vec![txt_data]),
                )));

                answers.push(dns_record);
            }

            header.set_response_code(ResponseCode::NoError);
            let response = MessageResponseBuilder::from_message_request(request)
                .build(header, answers.iter(), &[], &[], &[]);

            println!("✓ Responded to query: {} ({} records)", name_str, answers.len());

            return response_handle.send_response(response).await.unwrap_or_else(|e| {
                eprintln!("Error sending response: {}", e);
                header.into()
            });
        }

        // No record found
        header.set_response_code(ResponseCode::NXDomain);
        let response = MessageResponseBuilder::from_message_request(request).build_no_records(header);

        println!("✗ No records found for: {}", name_str);

        response_handle.send_response(response).await.unwrap_or_else(|e| {
            eprintln!("Error sending response: {}", e);
            header.into()
        })
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
        let records = server.records.read().unwrap();
        assert_eq!(records.len(), 0);
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

        let records = server.records.read().unwrap();
        assert_eq!(records.len(), 1);
        assert!(records.contains_key("_locd.example.com"));
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

        let records = server.records.read().unwrap();
        assert_eq!(records.len(), 1);
        assert!(records.contains_key("_locd-revoke.example.com"));
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

        {
            let records = server.records.read().unwrap();
            assert_eq!(records.len(), 1);
        }

        server.clear();
        let records = server.records.read().unwrap();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_multiple_records() {
        let mut server = MockDnsServer::new(5353);
        let keypair1 = Ed25519KeyPair::generate();
        let keypair2 = Ed25519KeyPair::generate();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add two identity records for the same domain
        let record1 = IdentityRecord::new(&keypair1.public_key().to_bytes(), timestamp);
        let record2 = IdentityRecord::new(&keypair2.public_key().to_bytes(), timestamp);

        server.add_identity_record("example.com", record1);
        server.add_identity_record("example.com", record2);

        let records = server.records.read().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records.get("_locd.example.com").unwrap().len(), 2);
    }
}
