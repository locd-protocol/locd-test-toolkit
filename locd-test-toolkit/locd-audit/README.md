# locd-audit - Security Audit Tools

Security testing and vulnerability scanning for Loc'd Protocol.

## Features

- **Timing Attack Detection** - Statistical analysis of execution time to detect side-channel vulnerabilities
- **Fuzzing** - Automated input fuzzing with libFuzzer to find parsing bugs and panics
- **Known Vulnerability Checks** - Scan for common cryptographic and protocol security issues

## Installation

```bash
cargo install --path locd-audit
```

## Usage

### Scan for Known Vulnerabilities

```bash
locd-audit scan
```

This checks for:
- Signature malleability
- Timestamp overflow vulnerabilities
- Unbounded delegation chains
- CBOR bomb attacks
- Key reuse issues

### Run Timing Analysis

Test cryptographic operations for timing side-channels:

```bash
# Use 10,000 samples with 5% variance threshold
locd-audit timing --samples 10000 --threshold 5.0
```

Tests performed:
- Baseline operation timing
- Ed25519 key generation
- Ed25519 signature verification

### Run Full Audit

Execute all security checks:

```bash
locd-audit full --samples 1000
```

## Fuzzing

Fuzzing requires `cargo-fuzz`:

```bash
cargo install cargo-fuzz
cd locd-audit
```

### Fuzz Delegation Tokens

```bash
cargo fuzz run fuzz_delegation_token -- -max_total_time=3600
```

### Fuzz DNS Records

```bash
cargo fuzz run fuzz_dns_record -- -max_total_time=3600
```

### Fuzz Verification Messages

```bash
cargo fuzz run fuzz_verification_messages -- -max_total_time=3600
```

## Interpreting Results

### Vulnerability Scan

- ✅ **MITIGATED** - The vulnerability has been addressed
- ⚠️ **VULNERABLE** - Action required to fix
- ℹ️ **N/A** - Requires manual verification

### Timing Analysis

- ✅ Variance below threshold - Likely constant-time
- ⚠️ Variance above threshold - Potential timing leak

Note: Some variance is normal due to system noise. Ed25519 operations may show
variance due to CPU optimizations, but are generally constant-time at the
algorithm level.

## Adding New Checks

### Vulnerability Check

Add to `src/vulns.rs`:

```rust
fn check_my_vulnerability() -> VulnReport {
    VulnReport {
        name: "My Vulnerability".to_string(),
        severity: Severity::High,
        status: Status::Mitigated,
        description: "Description of the check".to_string(),
    }
}
```

Then add to `check_all_vulnerabilities()`.

### Timing Test

Add to `src/main.rs` in `run_timing_analysis()`:

```rust
let analysis = timing::detect_timing_leaks(
    || {
        // Operation to test
    },
    samples,
    threshold,
);
print_timing_result("Operation Name", &analysis);
```

### Fuzz Target

Create `fuzz/fuzz_targets/fuzz_my_target.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parse data, should never panic
});
```

Add to `fuzz/Cargo.toml`:

```toml
[[bin]]
name = "fuzz_my_target"
path = "fuzz_targets/fuzz_my_target.rs"
test = false
doc = false
```

## CI Integration

See `.github/workflows/security.yml` for automated security scanning setup.

## License

MIT OR Apache-2.0
