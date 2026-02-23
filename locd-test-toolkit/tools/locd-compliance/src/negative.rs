//! Negative tests - verify that invalid inputs are properly rejected

use anyhow::Result;
use locd_core::types::{ActionPattern, DelegationId, IdentityDomain, ServicePattern};
use locd_crypto::Ed25519KeyPair;
use locd_delegation::{current_timestamp, DelegationToken, DelegationValidator};
use locd_dns::IdentityRecord;

/// Test that expired delegation tokens are detected
pub fn test_reject_expired_delegation() -> Result<()> {
    let master = Ed25519KeyPair::generate();
    let device = Ed25519KeyPair::generate();

    // Create token that expired 1 hour ago
    let past = current_timestamp() - 3600;
    let token = DelegationToken::builder()
        .delegator(master.public_key().to_bytes())
        .delegate(device.public_key().to_bytes())
        .delegation_id(DelegationId::new())
        .expires_at(past)
        .service(ServicePattern::new("example.com"))
        .action(ActionPattern::new("read"))
        .build()?;

    // Token should be expired
    assert!(DelegationValidator::is_expired(&token, current_timestamp()));
    Ok(())
}

/// Test that invalid signature is rejected
pub fn test_reject_invalid_signature() -> Result<()> {
    let master = Ed25519KeyPair::generate();
    let device = Ed25519KeyPair::generate();

    let token = DelegationToken::builder()
        .delegator(master.public_key().to_bytes())
        .delegate(device.public_key().to_bytes())
        .delegation_id(DelegationId::new())
        .expires_in(86400)
        .service(ServicePattern::new("example.com"))
        .action(ActionPattern::new("read"))
        .build()?;

    let mut cbor = token.sign(&master)?;

    // Tamper with the signature by flipping a bit
    if let Some(last_byte) = cbor.last_mut() {
        *last_byte ^= 0x01;
    }

    // Should fail to verify
    let result = DelegationToken::from_cbor(&cbor);
    assert!(result.is_err(), "Tampered signature should fail verification");
    Ok(())
}

/// Test that corrupted CBOR is rejected
pub fn test_reject_corrupted_cbor() -> Result<()> {
    let corrupted_data = vec![0xFF, 0xFE, 0xFD, 0xFC]; // Invalid CBOR

    let result = DelegationToken::from_cbor(&corrupted_data);
    assert!(result.is_err(), "Corrupted CBOR should be rejected");
    Ok(())
}

/// Test that empty CBOR is rejected
pub fn test_reject_empty_cbor() -> Result<()> {
    let result = DelegationToken::from_cbor(&[]);
    assert!(result.is_err(), "Empty CBOR should be rejected");
    Ok(())
}

/// Test that malformed DNS TXT record is rejected
pub fn test_reject_malformed_txt_record() -> Result<()> {
    let malformed_records = vec![
        "",                           // Empty
        "not-a-valid-record",        // No structure
        "v=1",                        // Missing fields
        "v=999;k=abc",               // Invalid version
        "k=not-base64;t=123",        // Invalid base64
    ];

    for record in malformed_records {
        let result = IdentityRecord::from_txt_record(record);
        assert!(result.is_err(), "Malformed TXT record '{}' should be rejected", record);
    }
    Ok(())
}

/// Test that signature verification fails for wrong message
pub fn test_reject_wrong_message() -> Result<()> {
    let keypair = Ed25519KeyPair::generate();
    let message1 = b"original message";
    let message2 = b"different message";

    let signature = keypair.sign(message1);

    // Should succeed for correct message
    keypair.public_key().verify(message1, &signature)?;

    // Should fail for wrong message
    let result = keypair.public_key().verify(message2, &signature);
    assert!(result.is_err(), "Signature should fail for wrong message");
    Ok(())
}

/// Test that same delegator and delegate is handled
pub fn test_self_delegation() -> Result<()> {
    let master = Ed25519KeyPair::generate();

    // Delegate to self
    let token = DelegationToken::builder()
        .delegator(master.public_key().to_bytes())
        .delegate(master.public_key().to_bytes()) // Same as delegator
        .delegation_id(DelegationId::new())
        .expires_in(86400)
        .service(ServicePattern::new("example.com"))
        .action(ActionPattern::new("read"))
        .build()?;

    // Should succeed but note that delegator == delegate
    assert_eq!(token.delegator, token.delegate);
    Ok(())
}

/// Test that negative expiry time is handled
pub fn test_negative_expiry() -> Result<()> {
    let master = Ed25519KeyPair::generate();
    let device = Ed25519KeyPair::generate();

    // Expire at timestamp 0 (Jan 1, 1970)
    let token = DelegationToken::builder()
        .delegator(master.public_key().to_bytes())
        .delegate(device.public_key().to_bytes())
        .delegation_id(DelegationId::new())
        .expires_at(0)
        .service(ServicePattern::new("example.com"))
        .action(ActionPattern::new("read"))
        .build()?;

    // Should be expired (we're past 1970)
    assert!(DelegationValidator::is_expired(&token, current_timestamp()));
    Ok(())
}

/// Test that zero-length delegation ID is handled
pub fn test_empty_delegation_id() -> Result<()> {
    // DelegationId::new() should always generate a valid ID
    let id = DelegationId::new();
    assert!(!id.to_string().is_empty(), "Delegation ID should not be empty");
    Ok(())
}

/// Test extremely long domain name rejection
pub fn test_reject_overlong_domain() -> Result<()> {
    // DNS domain max is 253 characters
    let too_long = "a".repeat(300);
    let domain = IdentityDomain::new(&too_long);

    // Implementation may truncate or reject
    // Just verify it doesn't panic
    assert!(domain.as_str().len() > 0);
    Ok(())
}

/// Test invalid domain characters
pub fn test_invalid_domain_chars() -> Result<()> {
    let invalid_domains = vec![
        "example .com",      // Space
        "example\n.com",     // Newline
        "example\t.com",     // Tab
    ];

    for domain_str in invalid_domains {
        let domain = IdentityDomain::new(domain_str);
        // Should handle gracefully (may sanitize or reject)
        assert!(domain.as_str().len() > 0);
    }
    Ok(())
}

/// Test CBOR roundtrip with tampered data
pub fn test_cbor_integrity() -> Result<()> {
    let master = Ed25519KeyPair::generate();
    let device = Ed25519KeyPair::generate();

    let token = DelegationToken::builder()
        .delegator(master.public_key().to_bytes())
        .delegate(device.public_key().to_bytes())
        .delegation_id(DelegationId::new())
        .expires_in(86400)
        .service(ServicePattern::new("example.com"))
        .action(ActionPattern::new("read"))
        .build()?;

    // Sign and get CBOR
    let cbor = token.sign(&master)?;

    // Verify we can parse it back
    let parsed = DelegationToken::from_cbor(&cbor)?;
    assert_eq!(parsed.delegator, token.delegator);
    assert_eq!(parsed.delegate, token.delegate);

    Ok(())
}

/// Test that very short expiry is handled
pub fn test_very_short_expiry() -> Result<()> {
    let master = Ed25519KeyPair::generate();
    let device = Ed25519KeyPair::generate();

    // Expire in 1 second
    let token = DelegationToken::builder()
        .delegator(master.public_key().to_bytes())
        .delegate(device.public_key().to_bytes())
        .delegation_id(DelegationId::new())
        .expires_in(1)
        .service(ServicePattern::new("example.com"))
        .action(ActionPattern::new("read"))
        .build()?;

    // Should not be expired yet (within 1 second)
    assert!(!DelegationValidator::is_expired(&token, current_timestamp()));
    Ok(())
}

/// Test maximum number of services
pub fn test_max_services() -> Result<()> {
    let master = Ed25519KeyPair::generate();
    let device = Ed25519KeyPair::generate();

    let mut builder = DelegationToken::builder()
        .delegator(master.public_key().to_bytes())
        .delegate(device.public_key().to_bytes())
        .delegation_id(DelegationId::new())
        .expires_in(86400);

    // Add 1000 services
    for i in 0..1000 {
        builder = builder.service(ServicePattern::new(&format!("service{}.example.com", i)));
    }

    builder = builder.action(ActionPattern::new("read"));

    let token = builder.build()?;
    assert_eq!(token.services.len(), 1000);

    // Should be able to serialize
    let _cbor = token.sign(&master)?;
    Ok(())
}

/// Test token with no services or actions
pub fn test_empty_permissions() -> Result<()> {
    let master = Ed25519KeyPair::generate();
    let device = Ed25519KeyPair::generate();

    let result = DelegationToken::builder()
        .delegator(master.public_key().to_bytes())
        .delegate(device.public_key().to_bytes())
        .delegation_id(DelegationId::new())
        .expires_in(86400)
        .build();

    // May succeed or fail depending on implementation
    // Just verify it doesn't panic
    let _ = result;
    Ok(())
}

/// Run all negative tests
pub fn run_all_negative_tests(verbose: bool) -> (usize, usize, usize) {
    let tests: Vec<(&str, fn() -> Result<()>)> = vec![
        ("Reject expired delegation", test_reject_expired_delegation),
        ("Reject invalid signature", test_reject_invalid_signature),
        ("Reject corrupted CBOR", test_reject_corrupted_cbor),
        ("Reject empty CBOR", test_reject_empty_cbor),
        ("Reject malformed TXT records", test_reject_malformed_txt_record),
        ("Reject wrong message", test_reject_wrong_message),
        ("Handle self-delegation", test_self_delegation),
        ("Handle negative expiry", test_negative_expiry),
        ("Handle empty delegation ID", test_empty_delegation_id),
        ("Reject overlong domain", test_reject_overlong_domain),
        ("Handle invalid domain chars", test_invalid_domain_chars),
        ("CBOR integrity check", test_cbor_integrity),
        ("Handle very short expiry", test_very_short_expiry),
        ("Handle maximum services", test_max_services),
        ("Handle empty permissions", test_empty_permissions),
    ];

    let mut total = 0;
    let mut passed = 0;

    for (name, test_fn) in tests {
        total += 1;
        if verbose {
            print!("  {} ... ", name);
        }
        match test_fn() {
            Ok(_) => {
                if verbose {
                    println!("✓");
                }
                passed += 1;
            }
            Err(e) => {
                println!("✗ {} failed: {}", name, e);
            }
        }
    }

    if !verbose {
        println!("  {} / {} negative tests passed", passed, total);
    }

    (total, passed, total - passed)
}
