# Architecture Guide

## Overview

The Loc'd Protocol Test Toolkit is organized into three main layers:

1. **Core Libraries** - Protocol implementation
2. **CLI Tools** - User-facing applications
3. **Testing Infrastructure** - Quality assurance

## Crate Structure

```
locd-test-toolkit/
├── crates/                    # Core libraries
│   ├── locd-core/            # Foundation types
│   ├── locd-crypto/          # Cryptographic primitives
│   ├── locd-delegation/      # Token management
│   ├── locd-dns/             # DNS records
│   ├── locd-verification/    # Challenge-response
│   ├── locd-revocation/      # Revocation checking
│   └── locd-test-vectors/    # Test data
├── tools/                     # CLI applications
│   ├── locd-keygen/          # Key generation
│   ├── locd-delegate/        # Token creation
│   ├── locd-verify/          # Verification
│   ├── locd-dns-tools/       # DNS management
│   └── locd-compliance/      # Testing tool
├── locd-bench/               # Benchmarking
├── locd-audit/               # Security auditing
└── locd-mock-dns/            # Mock DNS server
```

## Dependency Graph

```
locd-keygen → locd-crypto → locd-core
locd-delegate → locd-delegation → locd-core
locd-verify → locd-verification → locd-core
locd-dns-tools → locd-dns → locd-core
locd-compliance → all core crates
locd-mock-dns → locd-dns, locd-crypto, locd-core
```

## Core Libraries

### locd-core
Foundation types and constants:
- `IdentityDomain` - Domain name wrapper
- `DelegationId` - Unique delegation identifier
- `ServicePattern` - Service matching patterns
- `ActionPattern` - Action matching patterns
- Protocol version constants

### locd-crypto
Cryptographic primitives:
- Ed25519 signing and verification
- X25519 key agreement
- ChaCha20-Poly1305 AEAD encryption
- HKDF key derivation
- Argon2 password hashing

### locd-delegation
Delegation token management:
- CBOR encoding (RFC 8949)
- COSE Sign1 signatures (RFC 9052)
- Token builder pattern
- Validation logic

### locd-dns
DNS TXT record formatting:
- Identity record format
- Revocation record format
- Record parsing and serialization

### locd-verification
Challenge-response protocol:
- HELLO message creation
- CHALLENGE generation
- RESPONSE validation
- Complete verification flows

### locd-revocation
Revocation checking:
- Revocation list parsing
- Delegation ID validation
- DNS-based revocation checking

## CLI Tools Architecture

### Common Pattern
All CLI tools follow the same pattern:
1. Parse arguments with clap
2. Load necessary keys/data
3. Perform operation
4. Output result (JSON, text, or binary)

### locd-compliance
Special tool with multiple test suites:
- Basic compliance tests
- Edge case tests (`edge_cases.rs`)
- Negative tests (`negative.rs`)
- Compatibility tests (`compat.rs`)
- Report generation (`report.rs`)

## Testing Infrastructure

### locd-bench
Uses Criterion.rs for benchmarking:
- Cryptographic operations
- Token signing/verification
- DNS record parsing
- Serialization/deserialization

### locd-audit
Three-pronged security approach:
1. **Timing Attack Detection** - Statistical analysis of crypto operations
2. **Fuzzing** - libFuzzer targets for robustness
3. **Vulnerability Scanning** - Code pattern analysis

### locd-mock-dns
Local DNS server for testing:
- trust-dns-server based
- UDP transport
- TXT record support
- Thread-safe record storage
- Async with tokio

## Design Decisions

### 1. Workspace Organization
**Decision:** Monorepo with Cargo workspace

**Rationale:**
- Shared dependencies and version management
- Easy cross-crate refactoring
- Single CI/CD pipeline
- Consistent testing

### 2. CBOR + COSE for Tokens
**Decision:** Use CBOR encoding with COSE Sign1

**Rationale:**
- Compact binary format
- Standard signature format (COSE)
- Wide library support
- Suitable for constrained environments

### 3. DNS for Public Key Distribution
**Decision:** Use DNS TXT records for identity

**Rationale:**
- Existing infrastructure
- Global distribution
- No new trust anchors
- TTL-based caching

### 4. Ed25519 for Signatures
**Decision:** Ed25519 over RSA or ECDSA

**Rationale:**
- Fast verification
- Small signatures (64 bytes)
- Constant-time operations
- Widely supported

### 5. Mock DNS Instead of Real DNS
**Decision:** Local mock DNS server for testing

**Rationale:**
- No external dependencies
- Deterministic tests
- Fast execution
- Complete control

### 6. Multi-tier Testing
**Decision:** Unit, integration, and compliance tests

**Rationale:**
- Unit tests for logic
- Integration tests for interactions
- Compliance tests for specification adherence

## Security Considerations

### Cryptographic Safety
- Use audited libraries (ed25519-dalek, x25519-dalek)
- Constant-time operations where possible
- Timing attack detection in test suite
- Fuzzing for input validation

### Memory Safety
- Rust's ownership system prevents memory bugs
- No unsafe code in core libraries
- Careful use of unsafe in crypto wrappers

### Dependency Management
- Minimal dependency tree
- Regular cargo-audit scans
- Weekly security checks in CI/CD

## Performance Characteristics

### Benchmarks (avg on modern hardware)
- Ed25519 signing: ~50 μs
- Ed25519 verification: ~150 μs
- Token creation: ~1 μs (without signing)
- Token serialization: ~5 μs
- DNS record parsing: ~1 μs

### Scalability
- Verification protocol: O(1) per request
- Revocation checking: O(n) where n = revoked tokens
- DNS lookups: Depends on DNS server

## Future Considerations

### Potential Improvements
1. **Batch Verification** - Verify multiple signatures at once
2. **Bloom Filters** - Faster revocation checking
3. **gRPC API** - Alternative to DNS for key distribution
4. **Hardware Security Modules** - HSM support for key storage
5. **WebAssembly** - Browser-based verification

### Extension Points
- Custom storage backends
- Alternative signature algorithms
- Additional transport mechanisms
- Policy engines for delegation rules

---

For implementation details, see source code and inline documentation.
