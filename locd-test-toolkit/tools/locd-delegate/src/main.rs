//! locd-delegate - Delegation Token Creation and Management
//!
//! Create, sign, verify, and inspect delegation tokens for the Loc'd Protocol.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use locd_core::types::{ActionPattern, DelegationId, ServicePattern};
use locd_crypto::{Ed25519KeyPair, Ed25519PublicKey};
use locd_delegation::{current_timestamp, DelegationToken};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "locd-delegate")]
#[command(about = "Create and manage delegation tokens for the Loc'd Protocol")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new delegation token
    Create {
        /// Path to master secret key
        #[arg(long, value_name = "FILE")]
        master: PathBuf,

        /// Path to device public key
        #[arg(long, value_name = "FILE")]
        device: PathBuf,

        /// Service patterns (can be specified multiple times)
        #[arg(short, long, value_name = "PATTERN")]
        service: Vec<String>,

        /// Action patterns (can be specified multiple times)
        #[arg(short, long, value_name = "ACTION")]
        action: Vec<String>,

        /// Expiry duration in seconds
        #[arg(long, value_name = "SECONDS")]
        expires_in: Option<u64>,

        /// Maximum number of uses (0 = unlimited)
        #[arg(long, value_name = "COUNT", default_value = "0")]
        max_uses: u64,

        /// Allow sub-delegation
        #[arg(long)]
        sub_delegate: bool,

        /// Output file for the signed token
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },

    /// Verify a signed delegation token
    Verify {
        /// Path to the signed token file
        token_file: PathBuf,

        /// Path to master public key
        #[arg(long, value_name = "FILE")]
        master: PathBuf,
    },

    /// Display information about a delegation token
    Info {
        /// Path to the signed token file
        token_file: PathBuf,

        /// Path to master public key (for verification)
        #[arg(long, value_name = "FILE")]
        master: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Create {
            master,
            device,
            service,
            action,
            expires_in,
            max_uses,
            sub_delegate,
            output,
        } => {
            create_delegation(
                master,
                device,
                service,
                action,
                expires_in,
                max_uses,
                sub_delegate,
                output,
            )?;
        }
        Commands::Verify { token_file, master } => {
            verify_delegation(token_file, master)?;
        }
        Commands::Info { token_file, master } => {
            show_delegation_info(token_file, master)?;
        }
    }

    Ok(())
}

fn create_delegation(
    master_key_path: PathBuf,
    device_key_path: PathBuf,
    services: Vec<String>,
    actions: Vec<String>,
    expires_in: Option<u64>,
    max_uses: u64,
    sub_delegate: bool,
    output: PathBuf,
) -> Result<()> {
    eprintln!("Creating delegation token...");

    // Load master secret key
    let master_secret = fs::read(&master_key_path)
        .with_context(|| format!("Failed to read master key from {:?}", master_key_path))?;
    let master_keypair = Ed25519KeyPair::from_secret_bytes(&master_secret)?;

    // Load device public key
    let device_public = fs::read(&device_key_path)
        .with_context(|| format!("Failed to read device key from {:?}", device_key_path))?;
    let device_pubkey = Ed25519PublicKey::from_bytes(&device_public)?;

    // Build delegation token
    let mut builder = DelegationToken::builder()
        .delegator(master_keypair.public_key().to_bytes())
        .delegate(device_pubkey.to_bytes())
        .delegation_id(DelegationId::new())
        .max_uses(max_uses)
        .can_sub_delegate(sub_delegate);

    // Set expiry
    if let Some(duration) = expires_in {
        builder = builder.expires_in(duration);
    } else {
        // Default to 24 hours
        builder = builder.expires_in(86400);
    }

    // Add services
    for svc in services {
        builder = builder.service(ServicePattern::new(svc));
    }

    // Add actions
    for act in actions {
        builder = builder.action(ActionPattern::new(act));
    }

    // Build and sign token
    let token = builder.build()?;
    let signed_token = token.sign(&master_keypair)?;

    // Save to file
    fs::write(&output, &signed_token)
        .with_context(|| format!("Failed to write token to {:?}", output))?;

    eprintln!("✓ Delegation token created and signed");
    eprintln!("  Output: {:?}", output);
    eprintln!("  Delegation ID: {}", token.delegation_id);
    eprintln!(
        "  Expires in: {} seconds",
        token.expires_at - token.issued_at
    );
    eprintln!("  Services: {}", token.services.len());
    eprintln!("  Actions: {}", token.actions.len());
    eprintln!(
        "  Max uses: {}",
        if token.max_uses == 0 {
            "unlimited".to_string()
        } else {
            token.max_uses.to_string()
        }
    );

    Ok(())
}

fn verify_delegation(token_file: PathBuf, master_key_path: PathBuf) -> Result<()> {
    eprintln!("Verifying delegation token...");

    // Load master public key
    let master_public = fs::read(&master_key_path)
        .with_context(|| format!("Failed to read master key from {:?}", master_key_path))?;
    let master_pubkey = Ed25519PublicKey::from_bytes(&master_public)?;

    // Load signed token
    let token_bytes = fs::read(&token_file)
        .with_context(|| format!("Failed to read token from {:?}", token_file))?;

    // Verify and decode token
    let token = DelegationToken::verify(&token_bytes, &master_pubkey)?;

    eprintln!("✓ Token signature is valid");
    eprintln!("\nToken Information:");
    eprintln!("  Delegation ID: {}", token.delegation_id);
    eprintln!("  Delegator: {}", hex::encode(&token.delegator));
    eprintln!("  Delegate: {}", hex::encode(&token.delegate));
    eprintln!("  Issued at: {} (Unix timestamp)", token.issued_at);
    eprintln!("  Expires at: {} (Unix timestamp)", token.expires_at);

    let now = current_timestamp();
    if now > token.expires_at {
        eprintln!("  Status: ⚠️  EXPIRED");
    } else {
        eprintln!(
            "  Status: ✓ VALID (expires in {} seconds)",
            token.expires_at - now
        );
    }

    eprintln!("\nConstraints:");
    eprintln!(
        "  Services: {}",
        if token.services.is_empty() {
            "any".to_string()
        } else {
            token
                .services
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    eprintln!(
        "  Actions: {}",
        if token.actions.is_empty() {
            "any".to_string()
        } else {
            token
                .actions
                .iter()
                .map(|a| a.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    eprintln!(
        "  Max uses: {}",
        if token.max_uses == 0 {
            "unlimited".to_string()
        } else {
            token.max_uses.to_string()
        }
    );
    eprintln!("  Can sub-delegate: {}", token.can_sub_delegate);

    Ok(())
}

fn show_delegation_info(token_file: PathBuf, master_key_path: Option<PathBuf>) -> Result<()> {
    eprintln!("Reading delegation token...");

    // Load signed token
    let token_bytes = fs::read(&token_file)
        .with_context(|| format!("Failed to read token from {:?}", token_file))?;

    // If master key provided, verify signature
    let token = if let Some(master_path) = master_key_path {
        let master_public = fs::read(&master_path)
            .with_context(|| format!("Failed to read master key from {:?}", master_path))?;
        let master_pubkey = Ed25519PublicKey::from_bytes(&master_public)?;

        let token = DelegationToken::verify(&token_bytes, &master_pubkey)?;
        eprintln!("✓ Token signature verified");
        token
    } else {
        eprintln!("⚠️  No master key provided - signature not verified");
        // Attempt to decode without verification (risky in production!)
        // For now, we require verification
        anyhow::bail!("Master key required for token inspection. Use --master <key>");
    };

    println!("\n=== Delegation Token Information ===");
    println!("Delegation ID: {}", token.delegation_id);
    println!("Delegator (master): {}", hex::encode(&token.delegator));
    println!("Delegate (device): {}", hex::encode(&token.delegate));
    println!("Issued at: {} (Unix timestamp)", token.issued_at);
    println!("Expires at: {} (Unix timestamp)", token.expires_at);
    println!("Duration: {} seconds", token.expires_at - token.issued_at);

    let now = current_timestamp();
    if now > token.expires_at {
        println!("Status: EXPIRED ({} seconds ago)", now - token.expires_at);
    } else {
        println!(
            "Status: VALID (expires in {} seconds)",
            token.expires_at - now
        );
    }

    println!("\n=== Constraints ===");
    println!("Services ({}):", token.services.len());
    if token.services.is_empty() {
        println!("  (any service allowed)");
    } else {
        for svc in &token.services {
            println!("  - {}", svc.as_str());
        }
    }

    println!("Actions ({}):", token.actions.len());
    if token.actions.is_empty() {
        println!("  (any action allowed)");
    } else {
        for act in &token.actions {
            println!("  - {}", act.as_str());
        }
    }

    println!(
        "Max uses: {}",
        if token.max_uses == 0 {
            "unlimited".to_string()
        } else {
            token.max_uses.to_string()
        }
    );
    println!("Can create sub-delegations: {}", token.can_sub_delegate);

    Ok(())
}
