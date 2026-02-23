# Loc'd Protocol Test Toolkit - Comprehensive Handover

## Project Overview

**Goal**: Build protocol tools and test suite for the Loc'd Protocol - a hardware-bound, user-sovereign digital identity system.

**Location**: `/home/lane/projects/locd/locd-test-toolkit/`

**Technology**: Rust workspace with 7 library crates + 5 CLI tools

## Current Status: Phase 1 (5/7 Complete) ✅

> **NOTE**: This handover is from 2026-01-29. For the latest status (2025-02-23), see **HANDOVER-2025-02-23.md**

```
COMPLETED (as of 2025-02-23):
✅ locd-core:         14 tests passing
✅ locd-crypto:       34 tests passing
✅ locd-delegation:   16 tests passing
✅ locd-dns:          11 tests passing
✅ locd-verification: 23 tests passing  ← COMPLETED 2025-02-23
────────────────────────────────────────
Total:                98/98 tests passing

REMAINING:
⏳ locd-revocation     (Revocation checking)
⏳ locd-test-vectors   (Golden test data)
```

## Project Structure

```
locd-test-toolkit/
├── Cargo.toml                    # Workspace manifest
├── crates/
│   ├── locd-core/               ✅ Core types, errors, constants
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── constants.rs
│   │   │   ├── error.rs
│   │   │   ├── keys.rs
│   │   │   └── types.rs
│   ├── locd-crypto/             ✅ Crypto primitives
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── ed25519.rs       # Ed25519 signatures
│   │   │   ├── x25519.rs        # X25519 key agreement
│   │   │   ├── aead.rs          # ChaCha20-Poly1305
│   │   │   ├── kdf.rs           # HKDF-SHA256
│   │   │   ├── password.rs      # Argon2id
│   │   │   └── encoding.rs      # Base64url/hex
│   ├── locd-delegation/         ✅ Delegation tokens
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── token.rs         # CBOR/COSE tokens
│   │   │   └── validator.rs     # Constraint checking
│   ├── locd-dns/                ✅ DNS records
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── records.rs       # Identity/Revocation/Rotation records
│   │   │   └── resolver.rs      # DNS resolver (placeholder)
│   ├── locd-verification/       ⏳ TODO
│   ├── locd-revocation/         ⏳ TODO
│   └── locd-test-vectors/       ⏳ TODO
├── tools/
│   ├── locd-keygen/             ⏳ TODO (Phase 2)
│   ├── locd-delegate/           ⏳ TODO (Phase 2)
│   ├── locd-verify/             ⏳ TODO (Phase 2)
│   ├── locd-dns-tools/          ⏳ TODO (Phase 2)
│   └── locd-compliance/         ⏳ TODO (Phase 4)
├── test-vectors/                ⏳ TODO (Phase 3)
└── compliance-suite/            ⏳ TODO (Phase 4)
```

## Quick Start Commands

```bash
# Navigate to project
cd /home/lane/projects/locd/locd-test-toolkit

# Build all completed crates
source ~/.cargo/env
cargo build -p locd-core -p locd-crypto -p locd-delegation -p locd-dns

# Run all tests
cargo test --workspace --lib

# Run tests for specific crate
cargo test -p locd-core
cargo test -p locd-crypto
cargo test -p locd-delegation
cargo test -p locd-dns

# Check for warnings
cargo clippy --workspace
```

## Completed Components

### 1. locd-core (Foundation)

**Purpose**: Core types, errors, and constants used across all crates.

**Key exports**:
- `Error`, `Result` - Comprehensive error handling
- `MasterKey`, `DeviceKey`, `SessionKey` - Three-tier key hierarchy
- `DelegationId`, `IdentityDomain`, `ServicePattern`, `ActionPattern` - Protocol types
- Constants: `PROTOCOL_VERSION`, `DELEGATION_TYPE`, `MAX_DELEGATION_DURATION_SECS`, etc.

**Notable features**:
- Pattern matching for service/action wildcards (`*.example.com`, `*`)
- DNS record name generation from IdentityDomain
- Expiry checking for keys

### 2. locd-crypto (Cryptography)

**Purpose**: RFC-compliant cryptographic operations.

**Implementations**:
- **Ed25519**: Sign/verify with RFC 8032 compliance
- **X25519**: Key agreement for Diffie-Hellman
- **ChaCha20-Poly1305**: AEAD encryption with AAD support
- **XChaCha20-Poly1305**: Extended nonce AEAD (for recovery)
- **HKDF-SHA256**: Key derivation
- **Argon2id**: Password hashing
- **Encoding**: Base64url (no padding) and hex

**Key exports**:
- `Ed25519KeyPair`, `Ed25519PublicKey`, `Ed25519Signature`
- `X25519KeyPair`, `X25519PublicKey`
- `ChaCha20Poly1305`, `XChaCha20Poly1305`
- `hkdf_sha256`, `derive_encryption_key`, `derive_mac_key`
- `hash_password`, `verify_password`
- `base64url_encode`, `base64url_decode`

### 3. locd-delegation (Tokens)

**Purpose**: Delegation token creation, signing, validation.

**Key features**:
- CBOR encoding with integer keys (spec §6.2)
- COSE-like signature structure (simplified)
- Builder pattern for token creation
- Constraint validation (services, actions, expiry, max_uses)
- Timestamp tolerance checking

**Key exports**:
- `DelegationToken`, `DelegationTokenBuilder`
- `DelegationValidator`, `ValidationContext`

**Example usage**:
```rust
let token = DelegationToken::builder()
    .delegator(master_key.public_key().to_bytes())
    .delegate(device_key.public_key().to_bytes())
    .expires_in(86400)  // 24 hours
    .service("api.example.com")
    .action("read")
    .build()?;

let signed = token.sign(&master_key)?;
let verified = DelegationToken::verify(&signed, &master_key.public_key())?;
```

### 4. locd-dns (DNS Records)

**Purpose**: DNS TXT record formatting/parsing for Loc'd protocol.

**Record types**:
- **IdentityRecord**: `_locd.<domain>` - Master Key publication
- **RevocationRecord**: `_locd-revoke.<domain>` - Revoked delegation IDs
- **RotationRecord**: `_locd-rotate.<domain>` - Key rotation proofs

**Format examples**:
```
_locd.example.com. 300 IN TXT "v=locd1; k=ed25519; p=<base64url>; t=1234567890"
_locd-revoke.example.com. 60 IN TXT "v=locd-revoke1; ids=uuid1,uuid2; t=1234567890"
_locd-rotate.example.com. 300 IN TXT "v=locd-rotate1; old=<key>; new=<key>; sig=<sig>"
```

**Key exports**:
- `IdentityRecord`, `RevocationRecord`, `RotationRecord`
- `DnsResolver`, `QueryOptions` (placeholder for DNSSEC)

## Architecture Decisions

### CBOR Map Representation
- `ciborium::Value::Map` is `Vec<(Value, Value)>`, not `BTreeMap`
- Use helper functions to iterate and find keys instead of `.get()`

### COSE Signatures (Simplified)
- Used simplified COSE-like structure: `[protected, unprotected, payload, signature]`
- Full `coset` crate integration had serialization complexity
- Current implementation is spec-compliant for the core use case

### DNS Resolver (Placeholder)
- Structure is in place for DNSSEC validation
- Actual DNS querying with `trust-dns-resolver` is TODO
- Allows testing of record formatting/parsing independently

## Remaining Phase 1 Work

### locd-verification (Next Priority)

**Spec reference**: §7 - Verification Layer

**What to implement**:
1. **Protocol messages** (4 messages):
   - `HelloMessage` - Claimant → Verifier
   - `ChallengeMessage` - Verifier → Claimant
   - `ResponseMessage` - Claimant → Verifier
   - `ResultMessage` - Verifier → Claimant

2. **Challenge-response flow**:
   - Nonce generation (32 bytes random)
   - Timestamp checking (60s tolerance)
   - Signature verification
   - Delegation validation integration

3. **Verifier logic**:
   - DNS lookup for Master Key
   - DNSSEC validation
   - Delegation signature check
   - Service/action scope validation
   - Revocation checking

**Key files to create**:
- `crates/locd-verification/src/lib.rs`
- `crates/locd-verification/src/messages.rs`
- `crates/locd-verification/src/verifier.rs`
- `crates/locd-verification/src/claimant.rs`

### locd-revocation (Final Phase 1)

**Spec reference**: §8 - Revocation Layer

**What to implement**:
1. **RevocationChecker**:
   - DNS TXT record lookup (`_locd-revoke.<domain>`)
   - HTTPS supplementary list fetching
   - Revocation cache with TTL

2. **Revocation sources**:
   - Primary: DNS TXT records
   - Supplementary: HTTPS `.well-known/locd/revocations`
   - Cache layer with TTL management

**Key files to create**:
- `crates/locd-revocation/src/lib.rs`
- `crates/locd-revocation/src/checker.rs`
- `crates/locd-revocation/src/cache.rs`

## Dependencies Reference

All workspace dependencies are centralized in root `Cargo.toml`:

```toml
[workspace.dependencies]
# Crypto
ed25519-dalek = { version = "2", features = ["rand_core"] }
x25519-dalek = { version = "2", features = ["static_secrets"] }
chacha20poly1305 = "0.10"
hkdf = "0.12"
argon2 = "0.5"

# Encoding
ciborium = "0.2"
coset = "0.3"
base64ct = { version = "1", features = ["alloc"] }
hex = "0.4"

# DNS
trust-dns-resolver = "0.23"
reqwest = { version = "0.11", features = ["rustls-tls"] }

# Utilities
serde = { version = "1", features = ["derive"] }
serde_json = "1"
uuid = { version = "1", features = ["v4", "serde"] }
clap = { version = "4", features = ["derive"] }
tokio = { version = "1", features = ["full"] }
thiserror = "1"
anyhow = "1"
rand = "0.8"
sha2 = "0.10"
```

## Testing Strategy

All crates have comprehensive unit tests:
- **locd-core**: Type behavior, pattern matching, expiry logic
- **locd-crypto**: RFC test vectors, roundtrip encoding, invalid inputs
- **locd-delegation**: Token creation, signing, validation, constraint checking
- **locd-dns**: Record formatting, parsing roundtrips, field validation

**Run specific test groups**:
```bash
# All crypto tests
cargo test -p locd-crypto

# Specific test
cargo test -p locd-delegation test_sign_verify

# With output
cargo test -p locd-core -- --nocapture
```

## Reference Documentation

- **Spec**: `/home/lane/projects/locd/SPEC.md` (32KB, comprehensive protocol spec)
- **Plan**: This document outlines the full implementation plan
- **Spec sections**:
  - §4: Key Hierarchy
  - §5: Identity Layer (DNS)
  - §6: Delegation Layer (tokens)
  - §7: Verification Layer (challenge-response) ← NEXT
  - §8: Revocation Layer ← AFTER VERIFICATION

## Common Issues & Solutions

### Issue: CBOR map key lookups
**Problem**: `ciborium::Value::Map` is a `Vec<(Value, Value)>`, not a map.
**Solution**: Iterate through vec, match on `Value::Integer(key)`.

### Issue: COSE serialization
**Problem**: `coset::CoseSign1` doesn't implement `Serialize`.
**Solution**: Use simplified array structure `[protected, unprotected, payload, signature]`.

### Issue: Constant imports
**Problem**: `PROTOCOL_VERSION` is in `locd_core` root, not `constants` module.
**Solution**: `use locd_core::{PROTOCOL_VERSION, DELEGATION_TYPE, ...}` (not `constants::*`).

### Issue: Async tests
**Problem**: Tests that use async DNS need tokio runtime.
**Solution**: Use `#[tokio::test]` instead of `#[test]`.

## Next Session Quick Start

```bash
# 1. Navigate and verify
cd /home/lane/projects/locd/locd-test-toolkit
source ~/.cargo/env
cargo test --workspace --lib

# 2. Verify all 75 tests pass
# Expected: 14 + 34 + 16 + 11 = 75 tests passing

# 3. Start locd-verification
cd crates
cargo new --lib locd-verification

# 4. Add to workspace (already done)
# Cargo.toml members list already includes it

# 5. Add dependencies to locd-verification/Cargo.toml
# See "Dependencies Reference" section above
```

## Phase Roadmap

- **Phase 1** (Current): Core Libraries
  - ✅ locd-core, locd-crypto, locd-delegation, locd-dns (4/7)
  - ⏳ locd-verification, locd-revocation, locd-test-vectors (3/7)

- **Phase 2**: CLI Tools (5 tools)
  - locd-keygen, locd-delegate, locd-verify, locd-dns-tools, locd-compliance

- **Phase 3**: Test Vectors
  - JSON test data for cross-implementation validation

- **Phase 4**: Compliance Suite
  - YAML test definitions
  - Automated scoring
  - HTML report generation

- **Phase 5**: Mock DNS Server
  - DNSSEC simulation
  - Configuration files

- **Phase 6**: Documentation & CI/CD
  - README, API docs
  - GitHub Actions
  - Release automation

---

**Status**: Ready to continue with `locd-verification` implementation.
**Location**: `/home/lane/projects/locd/locd-test-toolkit/`
**Tests**: 75/75 passing across 4 completed crates
**Next**: Implement locd-verification (challenge-response protocol, spec §7)
