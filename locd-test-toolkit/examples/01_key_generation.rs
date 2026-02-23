//! Example 1: Key Generation
//!
//! Demonstrates generating master and device keys.
//!
//! Run with: cargo run --example 01_key_generation

use locd_crypto::Ed25519KeyPair;

fn main() {
    println!("=== Key Generation Example ===\n");

    // Generate a master key pair
    let master_key = Ed25519KeyPair::generate();
    println!("✓ Generated master key");
    println!(
        "  Public key: {} bytes",
        master_key.public_key().to_bytes().len()
    );

    // Generate a device key pair
    let device_key = Ed25519KeyPair::generate();
    println!("✓ Generated device key");
    println!(
        "  Public key: {} bytes",
        device_key.public_key().to_bytes().len()
    );

    println!("\nBoth keys use Ed25519 (32-byte public keys, 64-byte signatures)");
}
