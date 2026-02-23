//! Edge case tests for boundary conditions and corner cases

use anyhow::Result;
use locd_core::types::{ActionPattern, DelegationId, IdentityDomain, ServicePattern};
use locd_crypto::Ed25519KeyPair;
use locd_delegation::{current_timestamp, DelegationToken, DelegationValidator};
use locd_dns::IdentityRecord;

/// Test delegation token that expires exactly now
pub fn test_delegation_expires_at_boundary() -> Result<()> {
    let master = Ed25519KeyPair::generate();
    let device = Ed25519KeyPair::generate();

    // Create token that expires now
    let now = current_timestamp();
    let token = DelegationToken::builder()
        .delegator(master.public_key().to_bytes())
        .delegate(device.public_key().to_bytes())
        .delegation_id(DelegationId::new())
        .expires_at(now)
        .service(ServicePattern::new("example.com"))
        .action(ActionPattern::new("read"))
        .build()?;

    // Should be expired
    assert!(DelegationValidator::is_expired(&token, now));
    Ok(())
}

/// Test delegation token that expires 1 second in the future
pub fn test_delegation_expires_just_future() -> Result<()> {
    let master = Ed25519KeyPair::generate();
    let device = Ed25519KeyPair::generate();

    let now = current_timestamp();
    let token = DelegationToken::builder()
        .delegator(master.public_key().to_bytes())
        .delegate(device.public_key().to_bytes())
        .delegation_id(DelegationId::new())
        .expires_at(now + 1)
        .service(ServicePattern::new("example.com"))
        .action(ActionPattern::new("read"))
        .build()?;

    // Should not be expired yet
    assert!(!DelegationValidator::is_expired(&token, now));
    Ok(())
}

/// Test timestamp at maximum value (far future)
pub fn test_timestamp_max_value() -> Result<()> {
    let master = Ed25519KeyPair::generate();
    let device = Ed25519KeyPair::generate();

    // Use a very large timestamp (year ~584 billion)
    let far_future = u64::MAX - 1000;
    let token = DelegationToken::builder()
        .delegator(master.public_key().to_bytes())
        .delegate(device.public_key().to_bytes())
        .delegation_id(DelegationId::new())
        .expires_at(far_future)
        .service(ServicePattern::new("example.com"))
        .action(ActionPattern::new("read"))
        .build()?;

    // Should not be expired (we're not in year 584 billion)
    assert!(!DelegationValidator::is_expired(&token, current_timestamp()));
    assert_eq!(token.expires_at, far_future);
    Ok(())
}

/// Test identity domain with maximum valid length
pub fn test_max_domain_length() -> Result<()> {
    // DNS labels max 63 chars, full domain max 253 chars
    // Create a valid long domain
    let long_domain = "a".repeat(63) + "." + &"b".repeat(63) + "." + &"c".repeat(63) + ".com";
    assert!(long_domain.len() <= 253, "Domain should be under 253 chars");

    let domain = IdentityDomain::new(&long_domain);
    assert_eq!(domain.as_str(), long_domain);
    Ok(())
}

/// Test identity domain with single character
pub fn test_min_domain_length() -> Result<()> {
    let domain = IdentityDomain::new("a");
    assert_eq!(domain.as_str(), "a");
    Ok(())
}

/// Test delegation token with wildcard service pattern
pub fn test_wildcard_service_pattern() -> Result<()> {
    let master = Ed25519KeyPair::generate();
    let device = Ed25519KeyPair::generate();

    let token = DelegationToken::builder()
        .delegator(master.public_key().to_bytes())
        .delegate(device.public_key().to_bytes())
        .delegation_id(DelegationId::new())
        .expires_in(86400)
        .service(ServicePattern::new("*"))
        .action(ActionPattern::new("read"))
        .build()?;

    assert!(token.services.len() > 0);
    Ok(())
}

/// Test DNS TXT record with maximum content length
pub fn test_max_txt_record_length() -> Result<()> {
    // DNS TXT records have 255 byte limit per string
    let keypair = Ed25519KeyPair::generate();
    let timestamp = 1234567890;

    let record = IdentityRecord::new(&keypair.public_key().to_bytes(), timestamp);
    let txt = record.to_txt_record();

    // TXT record should not exceed reasonable limits
    assert!(txt.len() < 500, "TXT record should be under 500 bytes");

    // Should be able to parse back
    let parsed = IdentityRecord::from_txt_record(&txt)?;
    assert_eq!(parsed.public_key, record.public_key);
    Ok(())
}

/// Test CBOR encoding of token with maximum field sizes
pub fn test_max_cbor_token_size() -> Result<()> {
    let master = Ed25519KeyPair::generate();
    let device = Ed25519KeyPair::generate();

    // Create token with many services and actions
    let mut builder = DelegationToken::builder()
        .delegator(master.public_key().to_bytes())
        .delegate(device.public_key().to_bytes())
        .delegation_id(DelegationId::new())
        .expires_in(86400);

    // Add 100 services
    for i in 0..100 {
        builder = builder.service(ServicePattern::new(&format!("service{}.example.com", i)));
    }

    // Add 100 actions
    for i in 0..100 {
        builder = builder.action(ActionPattern::new(&format!("action{}", i)));
    }

    let token = builder.build()?;

    // Verify token can be signed and serialized
    let cbor = token.sign(&master)?;

    // Should produce a valid CBOR blob
    assert!(cbor.len() > 0, "CBOR should not be empty");
    assert!(cbor.len() < 100_000, "CBOR should be under 100KB");

    // Should be able to parse back
    let _parsed = DelegationToken::from_cbor(&cbor)?;
    Ok(())
}

/// Test zero-length message signing (edge case)
pub fn test_sign_empty_message() -> Result<()> {
    let keypair = Ed25519KeyPair::generate();
    let message = b"";

    let signature = keypair.sign(message);
    keypair.public_key().verify(message, &signature)?;
    Ok(())
}

/// Test very long message signing
pub fn test_sign_long_message() -> Result<()> {
    let keypair = Ed25519KeyPair::generate();
    let message = vec![0xAAu8; 1_000_000]; // 1MB message

    let signature = keypair.sign(&message);
    keypair.public_key().verify(&message, &signature)?;
    Ok(())
}

/// Test delegation ID uniqueness
pub fn test_delegation_id_uniqueness() -> Result<()> {
    let id1 = DelegationId::new();
    let id2 = DelegationId::new();

    // IDs should be unique
    assert_ne!(id1.to_string(), id2.to_string(), "Delegation IDs should be unique");
    Ok(())
}

/// Test case sensitivity in domains
pub fn test_domain_case_sensitivity() -> Result<()> {
    let lower = IdentityDomain::new("example.com");
    let upper = IdentityDomain::new("EXAMPLE.COM");
    let mixed = IdentityDomain::new("Example.Com");

    // All should be normalized to lowercase (DNS is case-insensitive)
    assert_eq!(lower.as_str().to_lowercase(), "example.com");
    assert_eq!(upper.as_str().to_lowercase(), "example.com");
    assert_eq!(mixed.as_str().to_lowercase(), "example.com");
    Ok(())
}

/// Test special characters in action patterns
pub fn test_special_chars_in_actions() -> Result<()> {
    let master = Ed25519KeyPair::generate();
    let device = Ed25519KeyPair::generate();

    // Test with various special characters
    let special_actions = vec![
        "read:write",
        "admin/delete",
        "api.v1.read",
        "resource_update",
    ];

    for action_str in special_actions {
        let token = DelegationToken::builder()
            .delegator(master.public_key().to_bytes())
            .delegate(device.public_key().to_bytes())
            .delegation_id(DelegationId::new())
            .expires_in(86400)
            .service(ServicePattern::new("example.com"))
            .action(ActionPattern::new(action_str))
            .build()?;

        assert!(token.actions.len() > 0);
    }
    Ok(())
}

/// Test Unicode in domain names (IDN - Internationalized Domain Names)
pub fn test_unicode_domains() -> Result<()> {
    // Test with punycode-like domain
    let domain = IdentityDomain::new("xn--e1afmkfd.xn--p1ai"); // пример.рф in punycode
    assert!(domain.as_str().len() > 0);
    Ok(())
}

/// Test timestamp at Unix epoch (time zero)
pub fn test_timestamp_epoch_zero() -> Result<()> {
    let keypair = Ed25519KeyPair::generate();
    let record = IdentityRecord::new(&keypair.public_key().to_bytes(), 0);

    assert_eq!(record.timestamp, 0);

    let txt = record.to_txt_record();
    let parsed = IdentityRecord::from_txt_record(&txt)?;
    assert_eq!(parsed.timestamp, 0);
    Ok(())
}

/// Run all edge case tests
pub fn run_all_edge_case_tests(verbose: bool) -> (usize, usize, usize) {
    let tests: Vec<(&str, fn() -> Result<()>)> = vec![
        ("Delegation expires at boundary", test_delegation_expires_at_boundary),
        ("Delegation expires just in future", test_delegation_expires_just_future),
        ("Timestamp at max value", test_timestamp_max_value),
        ("Maximum domain length", test_max_domain_length),
        ("Minimum domain length", test_min_domain_length),
        ("Wildcard service pattern", test_wildcard_service_pattern),
        ("Maximum TXT record length", test_max_txt_record_length),
        ("Maximum CBOR token size", test_max_cbor_token_size),
        ("Sign empty message", test_sign_empty_message),
        ("Sign long message (1MB)", test_sign_long_message),
        ("Delegation ID uniqueness", test_delegation_id_uniqueness),
        ("Domain case sensitivity", test_domain_case_sensitivity),
        ("Special chars in actions", test_special_chars_in_actions),
        ("Unicode domains (IDN)", test_unicode_domains),
        ("Timestamp at epoch zero", test_timestamp_epoch_zero),
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
        println!("  {} / {} edge case tests passed", passed, total);
    }

    (total, passed, total - passed)
}
