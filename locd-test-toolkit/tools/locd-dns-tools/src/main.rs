//! locd-dns-tools - DNS Record Management for Loc'd Protocol
//!
//! Generate, format, and validate DNS TXT records for the Loc'd Protocol.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use locd_core::types::IdentityDomain;
use locd_crypto::Ed25519PublicKey;
use locd_dns::{IdentityRecord, RevocationRecord};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "locd-dns-tools")]
#[command(about = "Generate and manage DNS records for the Loc'd Protocol")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate an identity record (_locd.<domain>)
    Identity {
        /// Domain name
        #[arg(short, long, value_name = "DOMAIN")]
        domain: String,

        /// Path to master public key
        #[arg(long, value_name = "FILE")]
        master: PathBuf,

        /// Optional expiry timestamp
        #[arg(long, value_name = "TIMESTAMP")]
        expiry: Option<u64>,

        /// Optional revocation endpoint URL
        #[arg(long, value_name = "URL")]
        revocation_url: Option<String>,

        /// Output file for DNS record
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },

    /// Generate a revocation record (_locd-revoke.<domain>)
    Revocation {
        /// Domain name
        #[arg(short, long, value_name = "DOMAIN")]
        domain: String,

        /// Revoked delegation IDs (comma-separated)
        #[arg(long, value_name = "IDS")]
        revoke: String,

        /// Output file for DNS record
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },

    /// Validate a DNS TXT record
    Validate {
        /// TXT record value to validate
        #[arg(value_name = "RECORD")]
        record: String,

        /// Record type (identity, revocation)
        #[arg(short, long, value_name = "TYPE")]
        record_type: String,
    },

    /// Show DNS record names for a domain
    Info {
        /// Domain name
        #[arg(value_name = "DOMAIN")]
        domain: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Identity {
            domain,
            master,
            expiry,
            revocation_url,
            output,
        } => {
            generate_identity_record(domain, master, expiry, revocation_url, output)?;
        }
        Commands::Revocation {
            domain,
            revoke,
            output,
        } => {
            generate_revocation_record(domain, revoke, output)?;
        }
        Commands::Validate {
            record,
            record_type,
        } => {
            validate_record(record, record_type)?;
        }
        Commands::Info { domain } => {
            show_domain_info(domain)?;
        }
    }

    Ok(())
}

fn generate_identity_record(
    domain_str: String,
    master_key_path: PathBuf,
    expiry: Option<u64>,
    revocation_url: Option<String>,
    output: Option<PathBuf>,
) -> Result<()> {
    eprintln!("Generating identity record...");

    // Load master public key
    let master_public = fs::read(&master_key_path)
        .with_context(|| format!("Failed to read master key from {:?}", master_key_path))?;
    let master_pubkey = Ed25519PublicKey::from_bytes(&master_public)?;

    // Get current timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Create identity record
    let mut record = IdentityRecord::new(&master_pubkey.to_bytes(), timestamp);

    if let Some(exp) = expiry {
        record = record.with_expiry(exp);
    }

    if let Some(url) = revocation_url {
        record = record.with_revocation_endpoint(url);
    }

    // Format as TXT record
    let txt_record = record.to_txt_record();

    // Get DNS record name
    let domain = IdentityDomain::new(&domain_str);
    let record_name = IdentityRecord::record_name(&domain);

    eprintln!("\n✓ Identity record generated");
    eprintln!("  Domain: {}", domain_str);
    eprintln!("  Record name: {}", record_name);
    eprintln!("  Timestamp: {}", timestamp);

    // Output
    let output_text = format!(
        "DNS TXT Record:\n\nName: {}\nValue: \"{}\"\n\nFor BIND zone file:\n{} IN TXT \"{}\"\n",
        record_name, txt_record, record_name, txt_record
    );

    if let Some(output_path) = output {
        fs::write(&output_path, &output_text)
            .with_context(|| format!("Failed to write record to {:?}", output_path))?;
        eprintln!("  Output: {:?}", output_path);
    } else {
        println!("{}", output_text);
    }

    Ok(())
}

fn generate_revocation_record(
    domain_str: String,
    revoke_ids: String,
    output: Option<PathBuf>,
) -> Result<()> {
    eprintln!("Generating revocation record...");

    // Parse revoked IDs
    let ids: Vec<String> = revoke_ids
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if ids.is_empty() {
        anyhow::bail!("No revocation IDs provided");
    }

    // Get current timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Create revocation record
    let record = RevocationRecord::new(ids.clone(), timestamp);
    let txt_record = record.to_txt_record();

    // Get DNS record name
    let domain = IdentityDomain::new(&domain_str);
    let record_name = format!("_locd-revoke.{}", domain.as_str());

    eprintln!("\n✓ Revocation record generated");
    eprintln!("  Domain: {}", domain_str);
    eprintln!("  Record name: {}", record_name);
    eprintln!("  Revoked IDs: {}", ids.len());

    // Output
    let output_text = format!(
        "DNS TXT Record:\n\nName: {}\nValue: \"{}\"\n\nFor BIND zone file:\n{} IN TXT \"{}\"\n",
        record_name, txt_record, record_name, txt_record
    );

    if let Some(output_path) = output {
        fs::write(&output_path, &output_text)
            .with_context(|| format!("Failed to write record to {:?}", output_path))?;
        eprintln!("  Output: {:?}", output_path);
    } else {
        println!("{}", output_text);
    }

    Ok(())
}

fn validate_record(record: String, record_type: String) -> Result<()> {
    eprintln!("Validating {} record...", record_type);

    match record_type.as_str() {
        "identity" => match IdentityRecord::from_txt_record(&record) {
            Ok(rec) => {
                eprintln!("\n✓ Valid identity record");
                eprintln!("  Version: {}", rec.version);
                eprintln!("  Algorithm: {}", rec.algorithm);
                eprintln!("  Public key: {}", rec.public_key);
                eprintln!("  Timestamp: {}", rec.timestamp);
                if let Some(exp) = rec.expiry {
                    eprintln!("  Expiry: {}", exp);
                }
                if let Some(rev) = rec.revocation_endpoint {
                    eprintln!("  Revocation URL: {}", rev);
                }
            }
            Err(e) => {
                eprintln!("\n✗ Invalid identity record: {}", e);
                return Err(e.into());
            }
        },
        "revocation" => match RevocationRecord::from_txt_record(&record) {
            Ok(rec) => {
                eprintln!("\n✓ Valid revocation record");
                eprintln!("  Version: {}", rec.version);
                eprintln!("  Revoked IDs: {} entries", rec.revoked_ids.len());
                eprintln!("  Timestamp: {}", rec.timestamp);
                for (i, id) in rec.revoked_ids.iter().enumerate() {
                    eprintln!("    {}: {}", i + 1, id);
                }
            }
            Err(e) => {
                eprintln!("\n✗ Invalid revocation record: {}", e);
                return Err(e.into());
            }
        },
        _ => {
            anyhow::bail!(
                "Unknown record type: {}. Use 'identity' or 'revocation'",
                record_type
            );
        }
    }

    Ok(())
}

fn show_domain_info(domain_str: String) -> Result<()> {
    let domain = IdentityDomain::new(&domain_str);

    println!("DNS Record Information for: {}", domain_str);
    println!("\nRecord Names:");
    println!("  Identity:   {}", IdentityRecord::record_name(&domain));
    println!("  Revocation: _locd-revoke.{}", domain.as_str());
    println!("  Rotation:   _locd-rotate.{}", domain.as_str());

    println!("\nExample DNS Queries:");
    println!("  dig {} TXT", IdentityRecord::record_name(&domain));
    println!("  dig _locd-revoke.{} TXT", domain.as_str());

    Ok(())
}
