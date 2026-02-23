# Changelog

All notable changes to the Loc'd Protocol Test Toolkit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-02-24

### Added

#### Phase 1: Core Libraries
- `locd-core` - Foundation types and protocol version (22 tests)
- `locd-crypto` - Ed25519, X25519, ChaCha20-Poly1305 cryptographic primitives (18 tests)
- `locd-delegation` - CBOR token encoding with COSE Sign1 signatures (34 tests)
- `locd-dns` - TXT record formats for identity and revocation (16 tests)
- `locd-verification` - Challenge-response protocol implementation (11 tests)
- `locd-revocation` - Revocation list management and checking (12 tests)
- `locd-test-vectors` - Golden test data for protocol compliance (21 tests)

#### Phase 2: CLI Tools
- `locd-keygen` - Key generation and management tool
- `locd-delegate` - Delegation token creation and signing
- `locd-verify` - Verification flow testing tool
- `locd-dns-tools` - DNS record generation utilities
- `locd-compliance` - Comprehensive compliance testing suite

#### Phase 4: Testing Infrastructure
- `locd-bench` - Performance benchmarking with Criterion.rs (32 benchmarks)
- `locd-audit` - Security auditing tools (5 tests)
  - Timing attack detection with statistical analysis
  - Fuzzing targets for robustness testing (3 targets)
  - Vulnerability scanning for code patterns
- Enhanced compliance testing (40 tests)
  - Edge case testing suite (15 tests)
  - Negative testing suite (15 tests)
  - Compatibility testing suite (10 tests)
- HTML report generation with Tera templates
  - Professional styling and metrics
  - JSON export support

#### Phase 4.5: CI/CD Integration
- Multi-platform testing workflow (Ubuntu, macOS, Windows)
- Rust stable & beta testing
- Code coverage with tarpaulin
- Weekly security audit workflow
- Automated benchmark tracking
- Release workflow for tagged versions

#### Phase 5: Mock DNS Server
- `locd-mock-dns` - Local DNS server for testing (8 tests)
  - TXT record query support
  - NXDOMAIN handling
  - Thread-safe record storage
  - CLI tool with sample data

#### Phase 6: Documentation & Release
- Comprehensive README with all components
- Architecture documentation (ARCHITECTURE.md)
- 6 runnable examples demonstrating key features
- Contributing guide (CONTRIBUTING.md)
- This CHANGELOG

### Testing
- 195 total tests across all crates
- All tests passing
- >80% code coverage in core libraries

### Documentation
- Complete API documentation for all public interfaces
- Usage examples in all crates
- Protocol specification reference (SPEC.md)

## [0.1.0] - 2025-02-20

### Added
- Initial development versions of core libraries
- Basic CLI tools
- Foundation for test infrastructure

---

[Unreleased]: https://github.com/locd-protocol/locd-test-toolkit/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/locd-protocol/locd-test-toolkit/releases/tag/v1.0.0
[0.1.0]: https://github.com/locd-protocol/locd-test-toolkit/releases/tag/v0.1.0
