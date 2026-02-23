use clap::{Parser, Subcommand};
use anyhow::Result;

#[derive(Parser)]
#[command(name = "locd-mock-dns")]
#[command(about = "Mock DNS server for testing Loc'd Protocol")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the mock DNS server
    Start {
        #[arg(short, long, default_value = "5353")]
        port: u16,
    },
    /// Add a test record
    Add {
        domain: String,
        #[arg(long)]
        identity: Option<String>,
        #[arg(long)]
        revocation: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start { port } => {
            println!("Starting mock DNS server on port {}...", port);
            // TODO: Start server
            println!("Server implementation pending - Phase 5 in progress");
            println!("\nPlanned features:");
            println!("  • Listen on port {} for DNS queries", port);
            println!("  • Respond to TXT record queries for _locd.* domains");
            println!("  • Support identity and revocation records");
            println!("  • Hot-reload configuration without restart");
        }
        Commands::Add { domain, identity, revocation } => {
            println!("Adding record for {}...", domain);
            if let Some(id_key) = identity {
                println!("  Identity key: {}", id_key);
            }
            if let Some(rev_id) = revocation {
                println!("  Revocation ID: {}", rev_id);
            }
            println!("\nRecord management implementation pending - Phase 5 in progress");
        }
    }

    Ok(())
}
