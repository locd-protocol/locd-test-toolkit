use anyhow::Result;
use clap::{Parser, Subcommand};
use locd_crypto::Ed25519KeyPair;
use locd_dns::{IdentityRecord, RevocationRecord};
use locd_mock_dns::MockDnsServer;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "locd-mock-dns")]
#[command(about = "Mock DNS server for testing Loc'd Protocol")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the mock DNS server with sample records
    Start {
        #[arg(short, long, default_value = "5353")]
        port: u16,

        /// Add a sample identity record for testing
        #[arg(long)]
        with_sample: bool,
    },
    /// Show example usage
    Examples,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start { port, with_sample } => {
            println!("🚀 Starting Loc'd Protocol Mock DNS Server");
            println!("════════════════════════════════════════\n");

            let mut server = MockDnsServer::new(port);

            if with_sample {
                println!("📝 Adding sample records for testing...\n");

                // Add sample identity record
                let keypair = Ed25519KeyPair::generate();
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

                let identity_record =
                    IdentityRecord::new(&keypair.public_key().to_bytes(), timestamp);
                server.add_identity_record("example.com", identity_record);
                println!("  ✓ Added identity record for _locd.example.com");

                // Add sample revocation record
                use locd_core::types::DelegationId;
                let rev_id = DelegationId::new();
                let revocation_record = RevocationRecord::new(vec![rev_id.to_string()], timestamp);
                server.add_revocation_record("example.com", revocation_record);
                println!("  ✓ Added revocation record for _locd-revoke.example.com");

                println!(
                    "\n💡 Test with: dig @127.0.0.1 -p {} _locd.example.com TXT\n",
                    port
                );
            }

            server.start().await?;
        }
        Commands::Examples => {
            show_examples();
        }
    }

    Ok(())
}

fn show_examples() {
    println!("🔍 Loc'd Mock DNS Server - Usage Examples");
    println!("═══════════════════════════════════════════\n");

    println!("1️⃣  Start server with sample records:");
    println!("   locd-mock-dns start --with-sample\n");

    println!("2️⃣  Start server on custom port:");
    println!("   locd-mock-dns start --port 5353\n");

    println!("3️⃣  Query identity records:");
    println!("   dig @127.0.0.1 -p 5353 _locd.example.com TXT");
    println!("   OR");
    println!("   nslookup -type=TXT _locd.example.com 127.0.0.1 5353\n");

    println!("4️⃣  Query revocation records:");
    println!("   dig @127.0.0.1 -p 5353 _locd-revoke.example.com TXT\n");

    println!("5️⃣  Using with Rust:");
    println!(
        r#"
   use locd_mock_dns::MockDnsServer;
   use locd_dns::IdentityRecord;

   let mut server = MockDnsServer::new(5353);
   server.add_identity_record("test.com", record);
   server.start().await?;
"#
    );

    println!("\n📚 For more information:");
    println!("   https://github.com/locd-protocol/locd-test-toolkit\n");
}
