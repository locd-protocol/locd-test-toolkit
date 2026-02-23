//! Example 6: Complete End-to-End Workflow
//!
//! Demonstrates a complete use case from key generation to verification.
//!
//! Run with: cargo run --example 06_complete_workflow

use locd_core::types::{ActionPattern, DelegationId, IdentityDomain, ServicePattern};
use locd_crypto::Ed25519KeyPair;
use locd_delegation::DelegationToken;
use locd_dns::IdentityRecord;
use locd_verification::{Claimant, Verifier};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Complete Workflow Example ===\n");
    println!("Scenario: Device accessing API with delegated permissions\n");

    // Step 1: Setup (happens once)
    println!("SETUP PHASE");
    println!("──────────");

    let master = Ed25519KeyPair::generate();
    let device = Ed25519KeyPair::generate();
    let domain = IdentityDomain::new("mycompany.com");

    println!("✓ Generated master key");
    println!("✓ Generated device key");
    println!("✓ Registered domain: {}", domain.as_str());

    // Step 2: Publish identity to DNS
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let identity = IdentityRecord::new(&master.public_key().to_bytes(), timestamp);
    let dns_record = identity.to_txt_record();

    println!("✓ Created DNS identity record");
    println!("  Publish to: _locd.{}", domain.as_str());
    println!("  TXT value: {}...", &dns_record[..50]);

    // Step 3: Create delegation token
    println!("\nDELEGATION PHASE");
    println!("────────────────");

    let token = DelegationToken::builder()
        .delegator(master.public_key().to_bytes())
        .delegate(device.public_key().to_bytes())
        .delegation_id(DelegationId::new())
        .expires_in(3600) // 1 hour
        .service(ServicePattern::new("api.mycompany.com"))
        .action(ActionPattern::new("read"))
        .action(ActionPattern::new("write"))
        .build()?;

    let signed_token = token.sign(&master)?;
    println!("✓ Created delegation token");
    println!("  Delegate: device key");
    println!("  Services: {:?}", token.services);
    println!("  Actions: {:?}", token.actions);
    println!("  Valid for: 1 hour");

    // Step 4: Verification protocol (simplified)
    println!("\nVERIFICATION PHASE (simplified)");
    println!("────────────────────────────────");

    let claimant = Claimant::new(device, domain.clone());
    let verifier = Verifier::new(domain, vec![1, 2, 3, 4], None);

    // 4a: HELLO
    let hello = claimant.create_hello()?;
    println!("1. Device → Server: HELLO");
    println!("   Domain: {}", hello.identity_domain);

    // 4b: CHALLENGE
    let challenge = verifier.handle_hello(&hello)?;
    println!("2. Server → Device: CHALLENGE");
    println!("   Nonce: {} bytes", challenge.nonce.len());

    // 4c: RESPONSE (requires delegation token)
    let response = claimant.create_response(&challenge, signed_token, vec![])?;
    println!("3. Device → Server: RESPONSE");
    println!("   Signature present: {}", response.signature.len() > 0);

    println!("\n🎉 Complete workflow successful!");
    println!("   Device can now access API with delegated permissions");
    println!("\nNote: Full verification requires DNS setup and revocation checking.");
    println!("      See the protocol specification (SPEC.md) for complete details.");

    Ok(())
}
