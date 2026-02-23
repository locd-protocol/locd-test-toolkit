# Loc'd Protocol Test Toolkit

Comprehensive testing infrastructure for the Loc'd Protocol.

## 🚀 Quick Start

```bash
# Install tools
cargo install --path tools/locd-keygen
cargo install --path tools/locd-compliance
cargo install --path locd-audit

# Generate keys
locd-keygen generate --output master.key --public

# Run compliance tests
locd-compliance enhanced --verbose

# Run security audit
locd-audit full

# Start mock DNS server
locd-mock-dns start --with-sample
```

## 📦 Components

### Core Libraries (Phase 1)
- **locd-core** - Foundation types and protocol version
- **locd-crypto** - Ed25519, X25519, ChaCha20-Poly1305
- **locd-delegation** - CBOR tokens, COSE Sign1
- **locd-dns** - TXT record formats
- **locd-verification** - Challenge-response protocol
- **locd-revocation** - Revocation checking
- **locd-test-vectors** - Golden test data

### CLI Tools (Phase 2)
- **locd-keygen** - Key generation and management
- **locd-delegate** - Token creation and signing
- **locd-verify** - Verification flows
- **locd-dns-tools** - DNS record generation
- **locd-compliance** - Compliance testing and reporting

### Testing Infrastructure (Phase 4)
- **locd-bench** - Performance benchmarks (32 benchmarks)
- **locd-audit** - Security auditing (timing, fuzzing, vulns)
- **locd-mock-dns** - Mock DNS server for testing
- Enhanced compliance (40+ edge case/negative tests)
- HTML reporting with metrics

### CI/CD (Phase 4.5)
- Multi-platform testing (Ubuntu, macOS, Windows)
- Rust stable & beta testing
- Code coverage with tarpaulin
- Weekly security audits
- Automated benchmarking

## 📊 Test Coverage

- **195 tests** across all crates
- **32 benchmarks** for performance tracking
- **40 enhanced compliance tests** (edge cases + negative + compat)
- **3 fuzz targets** for robustness testing
- **8 mock DNS tests** (5 unit + 3 integration)

## 🛠️ Development

```bash
# Run all tests
cargo test --workspace

# Run benchmarks
cargo bench -p locd-bench

# Run compliance suite
cargo run -p locd-compliance -- enhanced

# Security audit
cargo run -p locd-audit -- full

# Generate HTML report
cargo run -p locd-compliance -- report --format html --output report.html

# Start mock DNS server
cargo run -p locd-mock-dns -- start --with-sample
```

## 📖 Documentation

- [Architecture Guide](docs/ARCHITECTURE.md)
- [Protocol Specification](SPEC.md)
- [CLI Tools Guide](tools/README.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Examples](examples/)

## 🔒 Security

- Timing attack detection with statistical analysis
- Fuzzing with libFuzzer (3 targets)
- Dependency vulnerability scanning (cargo-audit)
- Weekly automated security audits

## 🎯 Features

- ✅ Complete protocol implementation
- ✅ Comprehensive test coverage (195 tests)
- ✅ Performance benchmarking
- ✅ Security auditing tools
- ✅ Mock DNS server
- ✅ HTML compliance reports
- ✅ CI/CD with GitHub Actions
- ✅ Cross-platform support

## 📄 License

MIT OR Apache-2.0
