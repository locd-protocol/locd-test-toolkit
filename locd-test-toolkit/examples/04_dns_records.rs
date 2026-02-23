//! Example 4: DNS Record Generation
//!
//! Demonstrates creating and parsing DNS TXT records.
//!
//! Run with: cargo run --example 04_dns_records

use locd_crypto::Ed25519KeyPair;
use locd_dns::IdentityRecord;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== DNS Records Example ===\n");

    // Generate key
    let keypair = Ed25519KeyPair::generate();
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    // Create identity record
    let record = IdentityRecord::new(&keypair.public_key().to_bytes(), timestamp);
    let txt = record.to_txt_record();
    println!("✓ Created identity record");
    println!("  TXT: {}", txt);
    println!("  Length: {} bytes", txt.len());

    // Parse it back
    let parsed = IdentityRecord::from_txt_record(&txt)?;
    println!("✓ Parsed record");
    println!(
        "  Public key matches: {}",
        parsed.public_key == record.public_key
    );
    println!(
        "  Timestamp matches: {}",
        parsed.timestamp == record.timestamp
    );

    println!("\nDNS Query: dig @dns.example.com _locd.example.com TXT");

    Ok(())
}
