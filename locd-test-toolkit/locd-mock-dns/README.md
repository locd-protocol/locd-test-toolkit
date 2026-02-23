# locd-mock-dns

Mock DNS server for local testing of the Loc'd Protocol.

## Overview

`locd-mock-dns` provides a lightweight DNS server that can respond to TXT record queries for testing Loc'd Protocol implementations without requiring real DNS infrastructure.

## Features (Planned)

- ✅ Mock DNS server data structures
- ✅ Identity record storage
- ✅ Revocation record storage
- ✅ CLI tool for server management
- ⏳ DNS server implementation (trust-dns-server)
- ⏳ TXT record query handling
- ⏳ Configuration file support
- ⏳ Hot-reload without restart

## Current Status

**Phase 5: Initial Implementation Complete**

- Library structure implemented
- Basic data structures created
- CLI scaffolding complete
- 4 unit tests passing

**TODO:**
- Implement DNS server loop using `trust-dns-server`
- Add query handling for `_locd.*` and `_locd-revoke.*` domains
- Implement record persistence and loading
- Add integration tests

## Usage

### CLI Commands

```bash
# Start the mock DNS server (implementation pending)
locd-mock-dns start --port 5353

# Add a test identity record (implementation pending)
locd-mock-dns add example.com --identity <public-key-base64>

# Add a test revocation record (implementation pending)
locd-mock-dns add example.com --revocation <delegation-id>
```

### Library Usage

```rust
use locd_mock_dns::{MockDnsServer, DnsRecord};
use locd_dns::IdentityRecord;

// Create a mock server
let mut server = MockDnsServer::new(5353);

// Add identity record
let record = IdentityRecord::new(&public_key, timestamp);
server.add_identity_record("example.com", record);

// Start server (implementation pending)
server.start().await?;
```

## Testing

```bash
# Run tests
cargo test -p locd-mock-dns

# Run with verbose output
cargo test -p locd-mock-dns -- --nocapture
```

## Architecture

The mock DNS server consists of:

1. **MockDnsServer** - Core server structure with record storage
2. **DnsRecord** - Enum for identity and revocation records
3. **CLI Tool** - Command-line interface for server management

Records are stored in memory and keyed by domain name with `_locd` or `_locd-revoke` prefixes.

## Dependencies

- `trust-dns-server` - DNS server implementation
- `trust-dns-client` - DNS client for testing
- `locd-core` - Core Loc'd Protocol types
- `locd-dns` - DNS record formatting
- `tokio` - Async runtime

## License

MIT OR Apache-2.0
