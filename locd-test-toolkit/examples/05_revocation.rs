//! Example 5: Revocation Checking
//!
//! Demonstrates revocation list management.
//!
//! Run with: cargo run --example 05_revocation

use locd_core::types::DelegationId;
use locd_dns::RevocationRecord;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Revocation Example ===\n");

    // Create delegation IDs
    let id1 = DelegationId::new();
    let id2 = DelegationId::new();
    let id3 = DelegationId::new();

    println!("Created 3 delegation IDs:");
    println!("  1. {}", id1);
    println!("  2. {}", id2);
    println!("  3. {}", id3);

    // Create revocation record
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let revoked = vec![id1.to_string(), id2.to_string()];
    let record = RevocationRecord::new(revoked, timestamp);

    println!("\n✓ Created revocation record");
    println!("  Revoked: {} delegations", record.revoked_ids.len());

    // Convert to DNS TXT record
    let txt = record.to_txt_record();
    println!("  TXT: {}...", &txt[..50]);

    // Parse back
    let parsed = RevocationRecord::from_txt_record(&txt)?;
    println!("✓ Parsed revocation record");

    // Check revocations
    println!("\nChecking delegations:");
    println!(
        "  ID 1 revoked: {}",
        parsed.revoked_ids.contains(&id1.to_string())
    );
    println!(
        "  ID 2 revoked: {}",
        parsed.revoked_ids.contains(&id2.to_string())
    );
    println!(
        "  ID 3 revoked: {}",
        parsed.revoked_ids.contains(&id3.to_string())
    );

    Ok(())
}
