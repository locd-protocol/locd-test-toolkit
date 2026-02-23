//! locd-keygen - Key Generation and Management Tool
//!
//! Generate, import, export, and inspect Ed25519 keys for the Loc'd Protocol.

use clap::{Parser, Subcommand};
use anyhow::{Context, Result};
use locd_crypto::{Ed25519KeyPair, Ed25519PublicKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "locd-keygen")]
#[command(about = "Generate and manage Ed25519 keys for the Loc'd Protocol")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 key pair
    Generate {
        /// Type of key (master, device, session)
        #[arg(short, long, value_name = "TYPE")]
        key_type: Option<String>,

        /// Output file for the secret key
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,

        /// Also save public key to a separate file
        #[arg(short, long)]
        public: bool,
    },

    /// Display information about a key
    Info {
        /// Path to the key file (secret or public)
        key_file: PathBuf,
    },

    /// Export key to JSON format
    Export {
        /// Path to the key file
        key_file: PathBuf,

        /// Output format (json)
        #[arg(short, long, default_value = "json")]
        format: String,
    },

    /// Import key from JSON format
    Import {
        /// Path to the JSON file
        json_file: PathBuf,

        /// Output file for the key
        #[arg(short, long)]
        output: PathBuf,

        /// Import format (json)
        #[arg(short, long, default_value = "json")]
        format: String,
    },

    /// Extract public key from a secret key
    PublicKey {
        /// Path to the secret key file
        secret_key: PathBuf,

        /// Output file for the public key
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Serialize, Deserialize)]
struct KeyExport {
    key_type: String,
    secret_key_hex: Option<String>,
    public_key_hex: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { key_type, output, public } => {
            generate_key(key_type, output, public)?;
        }
        Commands::Info { key_file } => {
            show_info(key_file)?;
        }
        Commands::Export { key_file, format } => {
            export_key(key_file, format)?;
        }
        Commands::Import { json_file, output, format } => {
            import_key(json_file, output, format)?;
        }
        Commands::PublicKey { secret_key, output } => {
            extract_public_key(secret_key, output)?;
        }
    }

    Ok(())
}

fn generate_key(key_type: Option<String>, output: PathBuf, save_public: bool) -> Result<()> {
    let key_type_str = key_type.as_deref().unwrap_or("device");

    eprintln!("Generating {} key...", key_type_str);
    let keypair = Ed25519KeyPair::generate();

    // Save secret key
    let secret_bytes = keypair.secret_bytes();
    fs::write(&output, &secret_bytes)
        .with_context(|| format!("Failed to write secret key to {:?}", output))?;

    eprintln!("✓ Secret key saved to: {:?}", output);

    // Save public key if requested
    if save_public {
        let public_bytes = keypair.public_key().to_bytes();
        let public_path = output.with_extension("pub");
        fs::write(&public_path, &public_bytes)
            .with_context(|| format!("Failed to write public key to {:?}", public_path))?;
        eprintln!("✓ Public key saved to: {:?}", public_path);
    }

    // Display key info
    eprintln!("\nKey Information:");
    eprintln!("  Type: {}", key_type_str);
    eprintln!("  Public key (hex): {}", hex::encode(keypair.public_key().to_bytes()));

    Ok(())
}

fn show_info(key_file: PathBuf) -> Result<()> {
    let bytes = fs::read(&key_file)
        .with_context(|| format!("Failed to read key file {:?}", key_file))?;

    match bytes.len() {
        32 => {
            // Could be either secret or public key
            // Try to load as secret key first
            if let Ok(keypair) = Ed25519KeyPair::from_secret_bytes(&bytes) {
                println!("Key Type: Secret Key (Ed25519)");
                println!("File: {:?}", key_file);
                println!("Size: {} bytes", bytes.len());
                println!("Public key (hex): {}", hex::encode(keypair.public_key().to_bytes()));
            } else if let Ok(pubkey) = Ed25519PublicKey::from_bytes(&bytes) {
                println!("Key Type: Public Key (Ed25519)");
                println!("File: {:?}", key_file);
                println!("Size: {} bytes", bytes.len());
                println!("Public key (hex): {}", hex::encode(pubkey.to_bytes()));
            } else {
                anyhow::bail!("Invalid key file");
            }
        }
        _ => {
            anyhow::bail!("Invalid key size: expected 32 bytes, got {}", bytes.len());
        }
    }

    Ok(())
}

fn export_key(key_file: PathBuf, format: String) -> Result<()> {
    if format != "json" {
        anyhow::bail!("Only 'json' format is supported");
    }

    let bytes = fs::read(&key_file)
        .with_context(|| format!("Failed to read key file {:?}", key_file))?;

    if bytes.len() != 32 {
        anyhow::bail!("Invalid key size: expected 32 bytes, got {}", bytes.len());
    }

    let export = if let Ok(keypair) = Ed25519KeyPair::from_secret_bytes(&bytes) {
        KeyExport {
            key_type: "secret".to_string(),
            secret_key_hex: Some(hex::encode(&bytes)),
            public_key_hex: hex::encode(keypair.public_key().to_bytes()),
        }
    } else if let Ok(pubkey) = Ed25519PublicKey::from_bytes(&bytes) {
        KeyExport {
            key_type: "public".to_string(),
            secret_key_hex: None,
            public_key_hex: hex::encode(pubkey.to_bytes()),
        }
    } else {
        anyhow::bail!("Invalid key file");
    };

    let json = serde_json::to_string_pretty(&export)?;
    println!("{}", json);

    Ok(())
}

fn import_key(json_file: PathBuf, output: PathBuf, format: String) -> Result<()> {
    if format != "json" {
        anyhow::bail!("Only 'json' format is supported");
    }

    let json_str = fs::read_to_string(&json_file)
        .with_context(|| format!("Failed to read JSON file {:?}", json_file))?;

    let export: KeyExport = serde_json::from_str(&json_str)?;

    let bytes = if let Some(secret_hex) = export.secret_key_hex {
        hex::decode(&secret_hex)?
    } else {
        hex::decode(&export.public_key_hex)?
    };

    fs::write(&output, &bytes)
        .with_context(|| format!("Failed to write key to {:?}", output))?;

    eprintln!("✓ Key imported to: {:?}", output);

    Ok(())
}

fn extract_public_key(secret_key: PathBuf, output: Option<PathBuf>) -> Result<()> {
    let secret_bytes = fs::read(&secret_key)
        .with_context(|| format!("Failed to read secret key {:?}", secret_key))?;

    let keypair = Ed25519KeyPair::from_secret_bytes(&secret_bytes)?;
    let public_bytes = keypair.public_key().to_bytes();

    if let Some(output_path) = output {
        fs::write(&output_path, &public_bytes)
            .with_context(|| format!("Failed to write public key to {:?}", output_path))?;
        eprintln!("✓ Public key saved to: {:?}", output_path);
    } else {
        println!("{}", hex::encode(&public_bytes));
    }

    Ok(())
}
