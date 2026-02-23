//! Generate test vectors JSON file

use locd_test_vectors::{export_to_json_file, generate_suite};

fn main() {
    let suite = generate_suite();

    println!("Generated Loc'd Protocol Test Vectors:");
    println!("  Version: {}", suite.version);
    println!("\nCrypto vectors:");
    println!("  Ed25519: {}", suite.crypto.ed25519.len());
    println!("  Base64url: {}", suite.crypto.base64url.len());
    println!("\nKey vectors:");
    println!("  Master keys: {}", suite.keys.master_keys.len());
    println!("  Device keys: {}", suite.keys.device_keys.len());
    println!("  Session keys: {}", suite.keys.session_keys.len());
    println!("\nDelegation tokens: {}", suite.delegation.tokens.len());
    println!("\nDNS records:");
    println!("  Identity: {}", suite.dns.identity_records.len());
    println!("  Revocation: {}", suite.dns.revocation_records.len());
    println!("\nVerification flows: {}", suite.verification.flows.len());

    // Export to file
    let path = "test-vectors/locd-test-vectors-v0.1.0.json";
    std::fs::create_dir_all("test-vectors").expect("Failed to create directory");
    export_to_json_file(&suite, path).expect("Failed to export");
    println!("\n✅ Exported to: {}", path);
}
