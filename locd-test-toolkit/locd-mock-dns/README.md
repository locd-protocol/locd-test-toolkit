# locd-mock-dns

Mock DNS server for local testing of the Loc'd Protocol.

## Overview

`locd-mock-dns` provides a lightweight DNS server that responds to TXT record queries for testing Loc'd Protocol implementations without requiring real DNS infrastructure.

## Features

- ✅ Mock DNS server with UDP support
- ✅ TXT record query handling for `_locd.*` domains
- ✅ Identity record storage and retrieval
- ✅ Revocation record storage and retrieval
- ✅ Multiple records per domain support
- ✅ NXDOMAIN responses for unknown domains
- ✅ CLI tool for server management
- ✅ Thread-safe record storage with RwLock
- ✅ Async/await support with tokio
- ✅ Integration tests with real DNS queries

## Status

**Phase 5: COMPLETE ✅**

- DNS server implementation using `trust-dns-server`
- Query handling for `_locd.*` and `_locd-revoke.*` domains
- 5 unit tests + 3 integration tests (all passing)
- Thread-safe record management
- CLI tool with examples and help text

## Usage

### CLI Commands

```bash
# Start server with sample records for testing
locd-mock-dns start --with-sample

# Start server on custom port
locd-mock-dns start --port 5353

# Show usage examples
locd-mock-dns examples
```

### Testing with dig

```bash
# Query identity records
dig @127.0.0.1 -p 5353 _locd.example.com TXT

# Query revocation records
dig @127.0.0.1 -p 5353 _locd-revoke.example.com TXT
```

### Library Usage

```rust
use locd_mock_dns::MockDnsServer;
use locd_dns::IdentityRecord;
use locd_crypto::Ed25519KeyPair;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create server
    let mut server = MockDnsServer::new(5353);

    // Add identity record
    let keypair = Ed25519KeyPair::generate();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    let record = IdentityRecord::new(&keypair.public_key().to_bytes(), timestamp);
    server.add_identity_record("example.com", record);

    // Start server (blocks until stopped)
    server.start().await?;

    Ok(())
}
```

## Testing

```bash
# Run all tests (unit + integration)
cargo test -p locd-mock-dns

# Run with output
cargo test -p locd-mock-dns -- --nocapture

# Run integration tests only
cargo test -p locd-mock-dns --test integration_test
```

## Architecture

The mock DNS server consists of:

### Core Components

1. **MockDnsServer** - Main server struct with:
   - Thread-safe record storage (`Arc<RwLock<HashMap>>`)
   - UDP socket binding
   - Server lifecycle management

2. **MockDnsHandler** - Request handler implementing `RequestHandler`:
   - TXT record query parsing
   - Record lookup and response generation
   - NXDOMAIN for non-existent domains

3. **DnsRecord** - Enum for protocol records:
   - `Identity(IdentityRecord)` - Public key records
   - `Revocation(RevocationRecord)` - Revoked delegation IDs

### Request Flow

```
DNS Query → trust-dns-server → MockDnsHandler
                                       ↓
                                   Parse query
                                       ↓
                                 Normalize FQDN
                                       ↓
                                   Lookup records
                                       ↓
                              Build TXT response
                                       ↓
                              Send to client ✓
```

## Implementation Details

- **FQDN Handling**: Automatically strips trailing dots from queries for consistent lookups
- **Thread Safety**: Uses `Arc<RwLock>` for concurrent access
- **Async Design**: Fully async with tokio runtime
- **TTL**: TXT records have 300-second (5 minute) TTL
- **Port**: Defaults to 5353 (mDNS port) but configurable

## Dependencies

- `trust-dns-server` (0.23) - DNS server implementation
- `trust-dns-client` (0.23) - DNS client for testing
- `locd-core` - Core Loc'd Protocol types
- `locd-dns` - DNS record formatting
- `locd-crypto` - Cryptographic operations
- `tokio` - Async runtime
- `async-trait` - Async trait support

## Test Coverage

### Unit Tests (5)
- `test_mock_dns_creation` - Server initialization
- `test_add_identity_record` - Identity record storage
- `test_add_revocation_record` - Revocation record storage
- `test_clear` - Record clearing
- `test_multiple_records` - Multiple records per domain

### Integration Tests (3)
- `test_dns_server_responds_to_queries` - Real DNS query/response
- `test_dns_server_nxdomain_for_unknown` - NXDOMAIN handling
- `test_dns_server_multiple_records` - Multiple record retrieval

## License

MIT OR Apache-2.0
