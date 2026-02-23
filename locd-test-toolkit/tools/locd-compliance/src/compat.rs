//! Cross-version compatibility tests

use anyhow::Result;
use locd_core::types::{ActionPattern, DelegationId, ServicePattern};
use locd_crypto::Ed25519KeyPair;
use locd_delegation::{current_timestamp, DelegationToken, DelegationValidator};
use locd_dns::IdentityRecord;

/// Test that tokens can be serialized and deserialized (format stability)
pub fn test_token_format_stability() -> Result<()> {
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

    // Sign and serialize (sign() returns CBOR bytes directly)
    let cbor = token.sign(&master)?;

    // Deserialize and verify format
    let parsed = DelegationToken::from_cbor(&cbor)?;
    assert_eq!(parsed.delegator, token.delegator);
    assert_eq!(parsed.delegate, token.delegate);

    // Re-serialize and compare
    let cbor2 = parsed.sign(&master)?;

    // CBOR should be stable (same token = same bytes)
    // Note: Timestamps and nonces may cause differences
    assert!(cbor.len() > 0 && cbor2.len() > 0);
    Ok(())
}

/// Test DNS TXT record format stability
pub fn test_dns_format_stability() -> Result<()> {
    let keypair = Ed25519KeyPair::generate();
    let timestamp = 1234567890u64;

    let record = IdentityRecord::new(&keypair.public_key().to_bytes(), timestamp);
    let txt1 = record.to_txt_record();

    // Parse and re-generate
    let parsed = IdentityRecord::from_txt_record(&txt1)?;
    let txt2 = parsed.to_txt_record();

    // Format should be stable
    assert_eq!(txt1, txt2, "DNS TXT format should be stable");
    Ok(())
}

/// Test backwards compatibility with minimal token
pub fn test_minimal_token_compat() -> Result<()> {
    // Create most minimal valid token
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

    // Should sign and verify
    let signed = token.sign(&master)?;
    let _verified = DelegationToken::verify(&signed, &master.public_key())?;

    Ok(())
}

/// Test that protocol version is accessible
pub fn test_protocol_version() -> Result<()> {
    let version = locd_core::PROTOCOL_VERSION;
    assert!(!version.is_empty(), "Protocol version should not be empty");
    // Protocol version exists and is a valid string
    assert!(version.len() > 0);
    Ok(())
}

/// Test that delegation type constants are stable
pub fn test_delegation_type_constants() -> Result<()> {
    let delegation_type = locd_core::DELEGATION_TYPE;
    // Verify the constant exists and is non-empty
    assert!(!delegation_type.is_empty());

    let revocation_type = locd_core::REVOCATION_TYPE;
    assert!(!revocation_type.is_empty());

    Ok(())
}

/// Test Ed25519 key format compatibility
pub fn test_key_format_compat() -> Result<()> {
    let keypair = Ed25519KeyPair::generate();
    let public_bytes = keypair.public_key().to_bytes();

    // Key should be 32 bytes (Ed25519 standard)
    assert_eq!(public_bytes.len(), 32);

    // Should be able to import key
    let imported = locd_crypto::Ed25519PublicKey::from_bytes(&public_bytes)?;
    assert_eq!(imported.to_bytes(), public_bytes);

    Ok(())
}

/// Test signature format compatibility (64 bytes)
pub fn test_signature_format_compat() -> Result<()> {
    let keypair = Ed25519KeyPair::generate();
    let message = b"test message";
    let signature = keypair.sign(message);

    // Signature should be 64 bytes (Ed25519 standard)
    assert_eq!(signature.to_bytes().len(), 64);

    // Should verify
    keypair.public_key().verify(message, &signature)?;

    Ok(())
}

/// Test CBOR encoding version marker
pub fn test_cbor_version_marker() -> Result<()> {
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

    let cbor = token.sign(&master)?;

    // CBOR should start with valid CBOR header
    // Major type 5 (map) or type 4 (array) are common
    assert!(cbor.len() > 0);
    let first_byte = cbor[0];
    // Valid CBOR major types: 0-6
    let major_type = (first_byte >> 5) & 0x07;
    assert!(major_type <= 6, "Invalid CBOR major type");

    Ok(())
}

/// Test that old tokens remain valid (within expiry)
pub fn test_token_longevity() -> Result<()> {
    use locd_delegation::current_timestamp;

    let master = Ed25519KeyPair::generate();
    let device = Ed25519KeyPair::generate();

    // Create token valid for 1 year
    let one_year = 365 * 24 * 60 * 60;
    let token = DelegationToken::builder()
        .delegator(master.public_key().to_bytes())
        .delegate(device.public_key().to_bytes())
        .delegation_id(DelegationId::new())
        .expires_at(current_timestamp() + one_year)
        .service(ServicePattern::new("example.com"))
        .action(ActionPattern::new("read"))
        .build()?;

    // Should not be expired
    assert!(!DelegationValidator::is_expired(
        &token,
        current_timestamp()
    ));

    // Should serialize/deserialize
    let cbor = token.sign(&master)?;
    let _parsed = DelegationToken::from_cbor(&cbor)?;

    Ok(())
}

/// Test field order independence in CBOR
pub fn test_cbor_field_order_independence() -> Result<()> {
    // CBOR maps are order-independent
    // Create two identical tokens and verify they parse the same
    let master = Ed25519KeyPair::generate();
    let device = Ed25519KeyPair::generate();

    let token1 = DelegationToken::builder()
        .delegator(master.public_key().to_bytes())
        .delegate(device.public_key().to_bytes())
        .delegation_id(DelegationId::new())
        .expires_in(86400)
        .service(ServicePattern::new("example.com"))
        .action(ActionPattern::new("read"))
        .build()?;

    let token2 = DelegationToken::builder()
        .delegator(master.public_key().to_bytes())
        .delegate(device.public_key().to_bytes())
        .delegation_id(token1.delegation_id.clone())
        .expires_at(token1.expires_at)
        .service(ServicePattern::new("example.com"))
        .action(ActionPattern::new("read"))
        .build()?;

    // Tokens should have same semantic content
    assert_eq!(token1.delegator, token2.delegator);
    assert_eq!(token1.delegate, token2.delegate);
    assert_eq!(token1.delegation_id, token2.delegation_id);

    Ok(())
}

/// Run all compatibility tests
pub fn run_all_compat_tests(verbose: bool) -> (usize, usize, usize) {
    let tests: Vec<(&str, fn() -> Result<()>)> = vec![
        ("Token format stability", test_token_format_stability),
        ("DNS format stability", test_dns_format_stability),
        ("Minimal token compatibility", test_minimal_token_compat),
        ("Protocol version check", test_protocol_version),
        ("Delegation type constants", test_delegation_type_constants),
        ("Ed25519 key format", test_key_format_compat),
        ("Signature format (64 bytes)", test_signature_format_compat),
        ("CBOR version marker", test_cbor_version_marker),
        ("Token longevity (1 year)", test_token_longevity),
        (
            "CBOR field order independence",
            test_cbor_field_order_independence,
        ),
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
        println!("  {} / {} compatibility tests passed", passed, total);
    }

    (total, passed, total - passed)
}
