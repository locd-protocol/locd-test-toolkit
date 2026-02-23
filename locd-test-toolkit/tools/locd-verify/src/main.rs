//! locd-verify - Challenge-Response Verification Tool
//!
//! Perform identity verification using the Loc'd Protocol challenge-response flow.

use clap::{Parser, Subcommand};
use anyhow::{Context, Result};
use locd_core::types::IdentityDomain;
use locd_crypto::Ed25519KeyPair;
use locd_verification::{Claimant, Verifier};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "locd-verify")]
#[command(about = "Perform identity verification using the Loc'd Protocol")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Act as a Claimant (prove identity)
    Claimant {
        /// Path to device secret key
        #[arg(long, value_name = "FILE")]
        device: PathBuf,

        /// Identity domain to claim
        #[arg(long, value_name = "DOMAIN")]
        domain: String,

        /// Output hello message to file
        #[arg(long, value_name = "FILE")]
        output_hello: Option<PathBuf>,
    },

    /// Create response to a challenge
    Respond {
        /// Path to device secret key
        #[arg(long, value_name = "FILE")]
        device: PathBuf,

        /// Identity domain
        #[arg(long, value_name = "DOMAIN")]
        domain: String,

        /// Path to challenge file
        #[arg(long, value_name = "FILE")]
        challenge: PathBuf,

        /// Path to delegation token file
        #[arg(long, value_name = "FILE")]
        delegation: PathBuf,

        /// Output response to file
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },

    /// Act as a Verifier (verify identity)
    Verifier {
        /// Verifier's domain
        #[arg(long, value_name = "DOMAIN")]
        domain: String,

        /// Path to hello message file
        #[arg(long, value_name = "FILE")]
        hello: PathBuf,

        /// Output challenge to file
        #[arg(long, value_name = "FILE")]
        output_challenge: Option<PathBuf>,
    },

    /// Verify a response
    Verify {
        /// Verifier's domain
        #[arg(long, value_name = "DOMAIN")]
        domain: String,

        /// Path to hello message file
        #[arg(long, value_name = "FILE")]
        hello: PathBuf,

        /// Path to challenge file
        #[arg(long, value_name = "FILE")]
        challenge: PathBuf,

        /// Path to response file
        #[arg(long, value_name = "FILE")]
        response: PathBuf,

        /// Required service
        #[arg(long, value_name = "SERVICE")]
        service: String,

        /// Required action
        #[arg(long, value_name = "ACTION")]
        action: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Claimant { device, domain, output_hello } => {
            create_hello(device, domain, output_hello)?;
        }
        Commands::Respond { device, domain, challenge, delegation, output } => {
            create_response(device, domain, challenge, delegation, output)?;
        }
        Commands::Verifier { domain, hello, output_challenge } => {
            create_challenge(domain, hello, output_challenge)?;
        }
        Commands::Verify { domain, hello, challenge, response, service, action } => {
            verify_response_cmd(domain, hello, challenge, response, service, action)?;
        }
    }

    Ok(())
}

fn create_hello(
    device_key_path: PathBuf,
    domain_str: String,
    output_hello: Option<PathBuf>,
) -> Result<()> {
    eprintln!("Creating HELLO message...");

    // Load device secret key
    let device_secret = fs::read(&device_key_path)
        .with_context(|| format!("Failed to read device key from {:?}", device_key_path))?;
    let device_keypair = Ed25519KeyPair::from_secret_bytes(&device_secret)?;

    // Create claimant
    let domain = IdentityDomain::new(&domain_str);
    let claimant = Claimant::new(device_keypair, domain);

    // Create hello message
    let hello = claimant.create_hello()?;

    // Encode to CBOR
    let hello_bytes = hello.encode()?;

    if let Some(output_path) = output_hello {
        fs::write(&output_path, &hello_bytes)
            .with_context(|| format!("Failed to write hello to {:?}", output_path))?;
        eprintln!("✓ HELLO message saved to: {:?}", output_path);
        eprintln!("  Size: {} bytes (CBOR encoded)", hello_bytes.len());
    } else {
        // Print hex for stdout
        println!("{}", hex::encode(&hello_bytes));
    }

    Ok(())
}

fn create_response(
    device_key_path: PathBuf,
    domain_str: String,
    challenge_path: PathBuf,
    delegation_path: PathBuf,
    output_path: PathBuf,
) -> Result<()> {
    eprintln!("Creating RESPONSE message...");

    // Load device secret key
    let device_secret = fs::read(&device_key_path)
        .with_context(|| format!("Failed to read device key from {:?}", device_key_path))?;
    let device_keypair = Ed25519KeyPair::from_secret_bytes(&device_secret)?;

    // Create claimant
    let domain = IdentityDomain::new(&domain_str);
    let claimant = Claimant::new(device_keypair, domain);

    // Load challenge (CBOR binary)
    let challenge_bytes = fs::read(&challenge_path)
        .with_context(|| format!("Failed to read challenge from {:?}", challenge_path))?;

    use locd_verification::ChallengeMessage;
    let challenge = ChallengeMessage::decode(&challenge_bytes)?;

    // Load delegation token
    let delegation_bytes = fs::read(&delegation_path)
        .with_context(|| format!("Failed to read delegation from {:?}", delegation_path))?;

    // Create response
    let response = claimant.create_response(&challenge, delegation_bytes, Vec::new())?;

    // Encode to CBOR
    let response_bytes = response.encode()?;

    fs::write(&output_path, &response_bytes)
        .with_context(|| format!("Failed to write response to {:?}", output_path))?;

    eprintln!("✓ RESPONSE message saved to: {:?}", output_path);
    eprintln!("  Size: {} bytes (CBOR encoded)", response_bytes.len());

    Ok(())
}

fn create_challenge(
    domain_str: String,
    hello_path: PathBuf,
    output_challenge: Option<PathBuf>,
) -> Result<()> {
    eprintln!("Creating CHALLENGE message...");

    // Create verifier (no WireGuard key or revocation checker for this demo)
    let domain = IdentityDomain::new(&domain_str);
    let wg_key = vec![0u8; 32]; // Placeholder WireGuard key
    let verifier = Verifier::new(domain, wg_key, None);

    // Load hello message (CBOR binary)
    let hello_bytes = fs::read(&hello_path)
        .with_context(|| format!("Failed to read hello from {:?}", hello_path))?;

    use locd_verification::HelloMessage;
    let hello = HelloMessage::decode(&hello_bytes)?;

    // Create challenge
    let challenge = verifier.handle_hello(&hello)?;

    // Encode to CBOR
    let challenge_bytes = challenge.encode()?;

    if let Some(output_path) = output_challenge {
        fs::write(&output_path, &challenge_bytes)
            .with_context(|| format!("Failed to write challenge to {:?}", output_path))?;
        eprintln!("✓ CHALLENGE message saved to: {:?}", output_path);
        eprintln!("  Size: {} bytes (CBOR encoded)", challenge_bytes.len());
    } else {
        // Print hex for stdout
        println!("{}", hex::encode(&challenge_bytes));
    }

    Ok(())
}

fn verify_response_cmd(
    domain_str: String,
    hello_path: PathBuf,
    challenge_path: PathBuf,
    response_path: PathBuf,
    service: String,
    action: String,
) -> Result<()> {
    eprintln!("Verifying RESPONSE message...");

    // Create verifier
    let domain = IdentityDomain::new(&domain_str);
    let wg_key = vec![0u8; 32]; // Placeholder WireGuard key
    let verifier = Verifier::new(domain, wg_key, None);

    // Load messages (all CBOR binary)
    use locd_verification::{HelloMessage, ChallengeMessage, ResponseMessage};

    let hello_bytes = fs::read(&hello_path)
        .with_context(|| format!("Failed to read hello from {:?}", hello_path))?;
    let hello = HelloMessage::decode(&hello_bytes)?;

    let challenge_bytes = fs::read(&challenge_path)
        .with_context(|| format!("Failed to read challenge from {:?}", challenge_path))?;
    let challenge = ChallengeMessage::decode(&challenge_bytes)?;

    let response_bytes = fs::read(&response_path)
        .with_context(|| format!("Failed to read response from {:?}", response_path))?;
    let response = ResponseMessage::decode(&response_bytes)?;

    // Note: This will fail with DNS lookup errors since we don't have a real DNS setup
    // In production, you'd need proper DNS infrastructure
    eprintln!("⚠️  Note: DNS verification will fail without proper DNS infrastructure");
    eprintln!("Attempting verification...");

    match verifier.verify_response(&hello, &challenge, &response, &service, &action) {
        Ok(result) => {
            eprintln!("\n✓ Verification successful!");
            println!("{:#?}", result);
        }
        Err(e) => {
            eprintln!("\n✗ Verification failed: {}", e);
            eprintln!("\nThis is expected if you don't have:");
            eprintln!("  - DNS records published for the claimant's domain");
            eprintln!("  - DNSSEC enabled");
            eprintln!("  - Proper revocation infrastructure");
            return Err(e.into());
        }
    }

    Ok(())
}
