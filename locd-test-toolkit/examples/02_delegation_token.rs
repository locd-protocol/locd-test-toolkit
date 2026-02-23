//! Example 2: Delegation Token Creation
//!
//! Demonstrates creating and signing a delegation token.
//!
//! Run with: cargo run --example 02_delegation_token

use locd_core::types::{ActionPattern, DelegationId, ServicePattern};
use locd_crypto::Ed25519KeyPair;
use locd_delegation::DelegationToken;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Delegation Token Example ===\n");

    // Generate keys
    let master = Ed25519KeyPair::generate();
    let device = Ed25519KeyPair::generate();

    // Create delegation token
    let token = DelegationToken::builder()
        .delegator(master.public_key().to_bytes())
        .delegate(device.public_key().to_bytes())
        .delegation_id(DelegationId::new())
        .expires_in(86400) // 24 hours
        .service(ServicePattern::new("api.example.com"))
        .action(ActionPattern::new("read"))
        .action(ActionPattern::new("write"))
        .build()?;

    println!("✓ Created delegation token");
    println!("  Services: {:?}", token.services);
    println!("  Actions: {:?}", token.actions);
    println!("  Expires: {}", token.expires_at);

    // Sign the token
    let signed = token.sign(&master)?;
    println!("✓ Signed token");
    println!("  Size: {} bytes", signed.len());

    // Verify signature
    let verified = DelegationToken::verify(&signed, &master.public_key())?;
    println!("✓ Verified signature");
    println!("  Delegation ID: {}", verified.delegation_id);

    Ok(())
}
