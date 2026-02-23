use clap::{Parser, Subcommand};
use locd_audit::{timing, vulns};

#[derive(Parser)]
#[command(name = "locd-audit")]
#[command(about = "Security audit tools for Loc'd Protocol", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run timing analysis on crypto operations
    Timing {
        #[arg(short, long, default_value = "1000")]
        samples: usize,

        #[arg(short, long, default_value = "5.0")]
        threshold: f64,
    },
    /// Scan for known vulnerabilities
    Scan,
    /// Run all security checks
    Full {
        #[arg(short, long, default_value = "1000")]
        samples: usize,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Timing { samples, threshold } => {
            println!("🔍 Running timing analysis with {} samples...\n", samples);
            run_timing_analysis(samples, threshold);
            println!("\n✓ Timing analysis complete");
        }
        Commands::Scan => {
            println!("🔍 Scanning for known vulnerabilities...\n");
            let reports = vulns::check_all_vulnerabilities();

            let mut vulnerable_count = 0;
            let mut mitigated_count = 0;

            for report in &reports {
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("📋 {}", report.name);
                println!("   Status: {}", report.status);
                println!("   Severity: {}", report.severity);
                println!("   {}", report.description);

                match report.status {
                    vulns::Status::Vulnerable => vulnerable_count += 1,
                    vulns::Status::Mitigated => mitigated_count += 1,
                    _ => {}
                }
            }

            println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!(
                "📊 Summary: {} checks, {} mitigated, {} vulnerable",
                reports.len(),
                mitigated_count,
                vulnerable_count
            );

            if vulnerable_count > 0 {
                println!(
                    "\n⚠️  WARNING: {} vulnerable items found!",
                    vulnerable_count
                );
            } else {
                println!("\n✅ No vulnerabilities detected!");
            }
        }
        Commands::Full { samples } => {
            println!("🔍 Running full security audit...\n");

            println!("1️⃣  Scanning for known vulnerabilities...");
            let reports = vulns::check_all_vulnerabilities();
            println!("   ✓ Scanned {} vulnerability checks\n", reports.len());

            println!("2️⃣  Running timing analysis...");
            run_timing_analysis(samples, 5.0);
            println!("   ✓ Timing analysis complete\n");

            println!("✅ Full audit complete!");
        }
    }

    Ok(())
}

fn run_timing_analysis(samples: usize, threshold: f64) {
    // Test 1: Black box operation (baseline)
    println!("  Testing baseline operation...");
    let analysis = timing::detect_timing_leaks(
        || {
            let _ = std::hint::black_box(42);
        },
        samples,
        threshold,
    );

    print_timing_result("Baseline", &analysis);

    // Test 2: Ed25519 key generation
    println!("  Testing Ed25519 key generation...");
    let analysis = timing::detect_timing_leaks(
        || {
            let _ = locd_crypto::Ed25519KeyPair::generate();
        },
        samples.min(100), // Fewer samples for expensive operation
        threshold,
    );

    print_timing_result("Ed25519 KeyGen", &analysis);

    // Test 3: Signature verification
    println!("  Testing Ed25519 signature verification...");
    let keypair = locd_crypto::Ed25519KeyPair::generate();
    let message = b"test message for timing analysis";
    let sig = keypair.sign(message);

    let analysis = timing::detect_timing_leaks(
        || {
            let _ = keypair.public_key().verify(message, &sig);
        },
        samples,
        threshold,
    );

    print_timing_result("Signature Verify", &analysis);
}

fn print_timing_result(name: &str, analysis: &timing::TimingAnalysis) {
    let status = if analysis.suspicious {
        "⚠️ "
    } else {
        "✅"
    };
    println!(
        "    {status} {name}: mean={:.2}µs, variance={:.2}%",
        analysis.mean.as_micros(),
        analysis.max_variance
    );
}
