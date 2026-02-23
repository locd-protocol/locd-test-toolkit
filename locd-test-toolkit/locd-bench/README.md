# locd-bench - Performance Benchmarking Suite

Comprehensive performance benchmarks for the Loc'd Protocol Test Toolkit.

## Overview

This crate provides detailed performance benchmarks for all core components of the Loc'd Protocol:

- **Crypto Operations**: Ed25519, X25519, ChaCha20-Poly1305
- **Delegation Operations**: Token creation, signing, verification, CBOR encoding/decoding
- **DNS Operations**: TXT record formatting/parsing, revocation checking
- **Verification Protocol**: Hello messages, challenges, responses, full verification flows

## Running Benchmarks

### Run All Benchmarks

```bash
cargo bench
```

### Run Specific Benchmark Suite

```bash
# Crypto benchmarks only
cargo bench --bench crypto

# Delegation benchmarks only
cargo bench --bench delegation

# DNS benchmarks only
cargo bench --bench dns

# Verification benchmarks only
cargo bench --bench verification
```

### Run Specific Benchmark

```bash
# Run only Ed25519 signing benchmark
cargo bench --bench crypto ed25519_sign
```

## Benchmark Results

Results are saved to `target/criterion/` with:
- HTML reports with charts
- Statistical analysis (mean, median, std dev)
- Comparison with previous runs
- Outlier detection

View HTML reports:
```bash
open target/criterion/report/index.html
```

## Performance Targets

Based on the Loc'd Protocol specification, these are the target performance metrics:

### Crypto Operations
- Ed25519 key generation: **<1ms**
- Ed25519 sign: **<0.5ms**
- Ed25519 verify: **<1ms**
- X25519 key agreement: **<0.5ms**
- ChaCha20-Poly1305 encrypt/decrypt: **1GB/s** (≈1ms for 1MB)

### Delegation Operations
- Token creation: **<5ms**
- Token signing (COSE Sign1): **<1ms**
- Token verification: **<2ms**
- CBOR encode: **<0.5ms**
- CBOR decode: **<0.5ms**

### DNS Operations
- TXT record format: **<0.1ms**
- TXT record parse: **<0.2ms**

### Verification Protocol
- Hello message creation: **<1ms**
- Challenge creation: **<0.5ms**
- Response creation: **<2ms**
- **Full verification flow: <10ms**

## Benchmark Categories

### 1. Crypto Benchmarks (`benches/crypto.rs`)

- Key generation (Ed25519, X25519)
- Digital signatures (sign/verify)
- Key agreement
- Symmetric encryption (ChaCha20-Poly1305)
- Key serialization
- Variable message sizes

### 2. Delegation Benchmarks (`benches/delegation.rs`)

- Delegation token creation
- COSE Sign1 signing/verification
- CBOR encoding/decoding
- Delegation chain verification (multiple depths)
- Multi-service/action constraints

### 3. DNS Benchmarks (`benches/dns.rs`)

- TXT record formatting (identity & revocation)
- TXT record parsing
- Revocation list operations (varying sizes)
- Revocation checking
- Domain validation
- Roundtrip performance

### 4. Verification Benchmarks (`benches/verification.rs`)

- Hello message creation
- Challenge creation
- Response creation
- Full verification flow
- Chain verification (varying depths)
- Message serialization
- Timestamp validation
- Nonce operations

## Interpreting Results

Criterion provides detailed statistical analysis:

```
ed25519_sign           time:   [145.23 µs 146.89 µs 148.67 µs]
                       change: [-2.3421% +0.1234% +2.5678%] (p = 0.87 > 0.05)
                       No change in performance detected.
```

- **time**: Mean execution time with confidence interval
- **change**: Performance change vs. previous run
- **p-value**: Statistical significance (p < 0.05 = significant change)

## Continuous Integration

Benchmarks are run on CI but not as pass/fail tests. Instead:
- Baseline metrics are tracked over time
- Performance regressions >10% trigger warnings
- Results are archived for historical analysis

## Adding New Benchmarks

1. Add benchmark function to appropriate file:

```rust
fn bench_my_operation(c: &mut Criterion) {
    c.bench_function("my_operation", |b| {
        b.iter(|| {
            black_box(my_operation())
        })
    });
}
```

2. Register in `criterion_group!`:

```rust
criterion_group!(
    benches,
    bench_existing,
    bench_my_operation,  // Add here
);
```

3. Run and verify:
```bash
cargo bench --bench <suite_name>
```

## Tips for Accurate Benchmarking

1. **Close other applications** - Reduce system noise
2. **Use release mode** - Benchmarks always run optimized
3. **Warm up** - Criterion automatically handles warm-up iterations
4. **Multiple samples** - Default is 100 samples per benchmark
5. **Disable turbo boost** - For more consistent results (optional)

## Dependencies

- [Criterion.rs](https://github.com/bheisler/criterion.rs) - Statistical benchmarking
- All Loc'd Protocol crates (core, crypto, delegation, dns, verification)

## License

MIT OR Apache-2.0
