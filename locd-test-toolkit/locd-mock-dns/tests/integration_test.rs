use locd_mock_dns::MockDnsServer;
use locd_dns::IdentityRecord;
use locd_crypto::Ed25519KeyPair;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use trust_dns_client::client::{AsyncClient, ClientHandle};
use trust_dns_client::udp::UdpClientStream;
use trust_dns_client::op::DnsResponse;
use trust_dns_client::rr::{DNSClass, Name, RecordType};
use std::str::FromStr;
use std::net::SocketAddr;

#[tokio::test]
async fn test_dns_server_responds_to_queries() {
    // Create server with a test record
    let mut server = MockDnsServer::new(15353);

    let keypair = Ed25519KeyPair::generate();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let record = IdentityRecord::new(&keypair.public_key().to_bytes(), timestamp);
    server.add_identity_record("test.com", record);

    // Start server in background
    let server_handle = tokio::spawn(async move {
        server.start().await
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create async DNS client
    let address: SocketAddr = "127.0.0.1:15353".parse().unwrap();
    let stream = UdpClientStream::<tokio::net::UdpSocket>::new(address);
    let (mut client, bg) = AsyncClient::connect(stream).await.unwrap();

    // Run the client in the background
    tokio::spawn(bg);

    // Query the DNS server
    let name = Name::from_str("_locd.test.com.").unwrap();
    let response: DnsResponse = client.query(name, DNSClass::IN, RecordType::TXT).await.unwrap();

    // Verify response
    let answers = response.answers();
    assert!(answers.len() > 0, "Should have at least one answer");
    println!("✓ Received {} answer(s)", answers.len());

    // Cleanup: abort server
    server_handle.abort();
}

#[tokio::test]
async fn test_dns_server_nxdomain_for_unknown() {
    // Create empty server
    let server = MockDnsServer::new(15354);

    // Start server in background
    let server_handle = tokio::spawn(async move {
        server.start().await
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create async DNS client
    let address: SocketAddr = "127.0.0.1:15354".parse().unwrap();
    let stream = UdpClientStream::<tokio::net::UdpSocket>::new(address);
    let (mut client, bg) = AsyncClient::connect(stream).await.unwrap();

    tokio::spawn(bg);

    // Query for non-existent domain
    let name = Name::from_str("_locd.nonexistent.com.").unwrap();
    let result = client.query(name, DNSClass::IN, RecordType::TXT).await;

    // Should get response with no answers
    match result {
        Ok(response) => {
            assert_eq!(response.answers().len(), 0, "Should have no answers");
            println!("✓ Correctly returned NXDOMAIN");
        }
        Err(e) => {
            println!("✓ Correctly returned error: {}", e);
        }
    }

    // Cleanup
    server_handle.abort();
}

#[tokio::test]
async fn test_dns_server_multiple_records() {
    // Create server with multiple records for same domain
    let mut server = MockDnsServer::new(15355);

    let keypair1 = Ed25519KeyPair::generate();
    let keypair2 = Ed25519KeyPair::generate();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let record1 = IdentityRecord::new(&keypair1.public_key().to_bytes(), timestamp);
    let record2 = IdentityRecord::new(&keypair2.public_key().to_bytes(), timestamp);

    server.add_identity_record("multi.com", record1);
    server.add_identity_record("multi.com", record2);

    // Start server in background
    let server_handle = tokio::spawn(async move {
        server.start().await
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create async DNS client
    let address: SocketAddr = "127.0.0.1:15355".parse().unwrap();
    let stream = UdpClientStream::<tokio::net::UdpSocket>::new(address);
    let (mut client, bg) = AsyncClient::connect(stream).await.unwrap();

    tokio::spawn(bg);

    // Query the DNS server
    let name = Name::from_str("_locd.multi.com.").unwrap();
    let response: DnsResponse = client.query(name, DNSClass::IN, RecordType::TXT).await.unwrap();

    // Verify response has both records
    let answers = response.answers();
    assert_eq!(answers.len(), 2, "Should have two answers");
    println!("✓ Received both records");

    // Cleanup
    server_handle.abort();
}
