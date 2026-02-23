# Loc'd Protocol CLI Tools

This directory contains command-line tools for working with the Loc'd Protocol.

## Tools

### locd-keygen - Key Generation and Management

Generate, import, export, and inspect Ed25519 keys.

```bash
# Generate a new key pair
locd-keygen generate --output master.key --public

# Display key information
locd-keygen info master.key

# Export to JSON
locd-keygen export master.key --format json

# Extract public key
locd-keygen public-key master.key --output master.pub
```

### locd-delegate - Delegation Token Management

Create, sign, verify, and inspect delegation tokens.

```bash
# Create a delegation token
locd-delegate create \
  --master master.key \
  --device device.pub \
  --service "api.example.com" \
  --action "read" \
  --expires-in 86400 \
  --output token.cbor

# Verify a token
locd-delegate verify token.cbor --master master.pub

# Show token information
locd-delegate info token.cbor --master master.pub
```

### locd-verify - Challenge-Response Verification

Perform identity verification using the challenge-response protocol.

```bash
# Claimant: Create HELLO message
locd-verify claimant \
  --device device.key \
  --domain alice.example.com \
  --output-hello hello.cbor

# Verifier: Create CHALLENGE message
locd-verify verifier \
  --domain service.example.com \
  --hello hello.cbor \
  --output-challenge challenge.cbor

# Claimant: Create RESPONSE
locd-verify respond \
  --device device.key \
  --domain alice.example.com \
  --challenge challenge.cbor \
  --delegation token.cbor \
  --output response.cbor

# Verifier: Verify response
locd-verify verify \
  --domain service.example.com \
  --hello hello.cbor \
  --challenge challenge.cbor \
  --response response.cbor \
  --service "api.example.com" \
  --action "read"
```

### locd-dns-tools - DNS Record Management

Generate and validate DNS TXT records for the Loc'd Protocol.

```bash
# Generate identity record
locd-dns-tools identity \
  --domain example.com \
  --master master.pub \
  --output identity.txt

# Generate revocation record
locd-dns-tools revocation \
  --domain example.com \
  --revoke "uuid1,uuid2,uuid3" \
  --output revocation.txt

# Validate a record
locd-dns-tools validate "v=locd1; k=ed25519; p=..." --record-type identity

# Show DNS record names for a domain
locd-dns-tools info example.com
```

### locd-compliance - Protocol Compliance Testing

Run compliance tests and generate reports.

```bash
# Run all tests
locd-compliance run --suite all --verbose

# Run specific test suite
locd-compliance run --suite crypto

# Verify test vectors
locd-compliance verify test-vectors.json --verbose

# Generate compliance report
locd-compliance report --format html --output report.html

# Show protocol information
locd-compliance info
```

## Building

```bash
# Build all tools
cargo build --bins --release

# Build specific tool
cargo build -p locd-keygen --release

# Tools will be in target/release/
```

## Installation

```bash
# Install all tools to ~/.cargo/bin
cargo install --path tools/locd-keygen
cargo install --path tools/locd-delegate
cargo install --path tools/locd-verify
cargo install --path tools/locd-dns-tools
cargo install --path tools/locd-compliance
```

## Complete Workflow Example

```bash
# 1. Generate keys
locd-keygen generate --output master.key --public
locd-keygen generate --output device.key --public

# 2. Create delegation token
locd-delegate create \
  --master master.key \
  --device device.pub \
  --service "api.example.com" \
  --action "read" \
  --expires-in 86400 \
  --output token.cbor

# 3. Verify token
locd-delegate verify token.cbor --master master.pub

# 4. Generate DNS records
locd-dns-tools identity \
  --domain example.com \
  --master master.pub \
  --output identity.txt

# 5. Run compliance tests
locd-compliance run --suite all
```

## See Also

- [Loc'd Protocol Specification](/SPEC.md)
- [Test Toolkit Documentation](/README.md)
- [Library Crates](/crates/)
