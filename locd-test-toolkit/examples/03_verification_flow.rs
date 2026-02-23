//! Example 3: Verification Flow (Simplified)
//!
//! Demonstrates the HELLO and CHALLENGE messages of the verification protocol.
//!
//! Run with: cargo run --example 03_verification_flow

use locd_core::types::IdentityDomain;
use locd_crypto::Ed25519KeyPair;
use locd_verification::{Claimant, Verifier};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Verification Flow Example ===\n");

    // Setup
    let device = Ed25519KeyPair::generate();
    let domain = IdentityDomain::new("example.com");

    // Claimant creates HELLO
    let claimant = Claimant::new(device, domain.clone());
    let hello = claimant.create_hello()?;
    println!("1. Claimant sends HELLO");
    println!("   Domain: {}", hello.identity_domain);
    println!("   Device key: {} bytes", hello.device_public_key.len());

    // Verifier creates CHALLENGE
    let verifier = Verifier::new(domain, vec![1, 2, 3, 4], None);
    let challenge = verifier.handle_hello(&hello)?;
    println!("\n2. Verifier sends CHALLENGE");
    println!("   Nonce: {} bytes", challenge.nonce.len());
    println!("   Timestamp: {}", challenge.timestamp);
    println!("   Verifier domain: {}", challenge.verifier_domain);

    println!("\n✓ HELLO and CHALLENGE flow successful!");
    println!("  (Full flow requires delegation token and DNS setup)");

    Ok(())
}
