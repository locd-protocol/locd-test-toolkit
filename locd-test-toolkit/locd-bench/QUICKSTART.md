# Quick Start Guide - locd-bench

## Installation

The benchmark suite is part of the workspace. No separate installation needed.

## Running Benchmarks

### Run All Benchmarks

```bash
cd /path/to/locd-test-toolkit
cargo bench -p locd-bench
```

This will run all 30+ benchmarks across 4 suites and generate HTML reports.

### Run Specific Suite

```bash
# Crypto benchmarks only (~8 benchmarks)
cargo bench -p locd-bench --bench crypto

# Delegation benchmarks only (~7 benchmarks)
cargo bench -p locd-bench --bench delegation

# DNS benchmarks only (~8 benchmarks)
cargo bench -p locd-bench --bench dns

# Verification benchmarks only (~9 benchmarks)
cargo bench -p locd-bench --bench verification
```

### Run Specific Benchmark

```bash
# Run only ed25519_sign benchmark
cargo bench -p locd-bench --bench crypto -- ed25519_sign

# Run only full_verification_flow benchmark
cargo bench -p locd-bench --bench verification -- full_verification_flow
```

### Quick Test Run (Faster)

For development, reduce sample size:

```bash
# Run with fewer samples (faster but less accurate)
cargo bench -p locd-bench -- --sample-size 10
```

## Viewing Results

### Terminal Output

Results appear in terminal immediately:

```
ed25519_sign           time:   [145.23 µs 146.89 µs 148.67 µs]
```

### HTML Reports

Open the HTML report for detailed charts and analysis:

```bash
# Generate and open HTML report
cargo bench -p locd-bench
open target/criterion/report/index.html  # macOS
xdg-open target/criterion/report/index.html  # Linux
```

## Expected Performance Targets

Based on Loc'd Protocol specification:

| Operation | Target | Suite |
|-----------|--------|-------|
| Ed25519 keygen | <1ms | crypto |
| Ed25519 sign | <0.5ms | crypto |
| Ed25519 verify | <1ms | crypto |
| X25519 key agreement | <0.5ms | crypto |
| ChaCha20-Poly1305 encrypt | 1GB/s | crypto |
| Delegation token create | <5ms | delegation |
| Delegation token sign | <1ms | delegation |
| Delegation token verify | <2ms | delegation |
| CBOR encode | <0.5ms | delegation |
| CBOR decode | <0.5ms | delegation |
| TXT record format | <0.1ms | dns |
| TXT record parse | <0.2ms | dns |
| Hello message create | <1ms | verification |
| Challenge create | <0.5ms | verification |
| Response create | <2ms | verification |
| **Full verification flow** | **<10ms** | verification |

## Tips for Accurate Results

1. **Close other applications** - Minimize system noise
2. **Disable CPU throttling** (optional):
   ```bash
   # Linux
   echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
   ```
3. **Run multiple times** - Criterion handles variance automatically
4. **Warm cache** - First run may be slower

## Continuous Integration

Benchmarks run on CI but don't fail builds. Instead:
- Baseline metrics tracked over time
- Performance regressions >10% trigger warnings
- Results archived for historical analysis

## Next Steps

After running benchmarks:

1. Review HTML report for detailed analysis
2. Compare against target metrics above
3. Identify any operations exceeding targets
4. Profile slow operations if needed
5. Re-run after optimizations to measure improvement

## Troubleshooting

### Benchmarks Take Too Long

```bash
# Reduce sample size
cargo bench -p locd-bench -- --sample-size 10
```

### Out of Memory

```bash
# Run one suite at a time
cargo bench -p locd-bench --bench crypto
cargo bench -p locd-bench --bench delegation
# etc.
```

### Unstable Results

- Close background applications
- Wait for system to idle
- Disable CPU power management
- Run multiple times and average

## More Information

See [README.md](README.md) for complete documentation.
