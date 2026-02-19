# Loc'd Protocol Specification

Version: 0.1.0 (Draft)
Status: Draft for Review
Date: February 15, 2026
License: CC BY 4.0
Authors: Lane
Repository: https://github.com/locd-protocol/spec

## Abstract

Loc'd is an open protocol for hardware-bound, user-sovereign digital identity and encrypted connectivity. It enables users to prove their identity cryptographically using keys stored in device hardware (TPM/Secure Enclave), publish their public identity to DNS, establish encrypted peer-to-peer connections without open ports, and delegate scoped authority to devices and agents — all without shared secrets, third-party identity providers, or centralised infrastructure.

This document specifies the protocol's data formats, cryptographic operations, verification procedures, and interaction flows in sufficient detail for independent implementation.

## Table of Contents

1. Introduction
2. Terminology
3. Design Principles
4. Key Hierarchy
5. Identity Layer
6. Delegation Layer
7. Verification Layer
8. Revocation Layer
9. Mesh Connectivity Layer
10. Legacy Bridge Layer
11. Recovery
12. DNS Record Formats
13. Wire Formats
14. Security Considerations
15. IANA Considerations
16. References
17. Appendix A: Example Flows
18. Appendix B: Comparison with Existing Standards

## 1. Introduction

### 1.1 Problem Statement

The internet's prevailing authentication model relies on shared secrets (passwords, API keys, OAuth tokens) mediated by third-party identity providers. This creates three fundamental vulnerabilities:

1. **Borrowed identity.** Users do not control their own identity. An identity provider can revoke access unilaterally, affecting all downstream services.
2. **Discovery-based connectivity.** Services expose public endpoints and filter access after discovery. The existence of the endpoint is itself an attack surface.
3. **Static, unscoped trust.** Credentials grant binary access with no constraints on scope, time, device, or action.

### 1.2 Solution Overview

Loc'd inverts the trust model:

1. The user holds the root of trust (a hardware-bound master key).
2. The user publishes their public identity (via DNS).
3. Services verify against the user's published identity.
4. Connections are encrypted tunnels established only after mutual cryptographic verification.
5. Delegation allows devices and agents to act on the user's behalf with scoped, time-limited, revocable authority.

### 1.3 Scope

This specification defines:

- Key generation, storage, and lifecycle requirements
- DNS-based identity publication format
- Delegation token format and signing
- Challenge-response verification protocol
- Revocation mechanisms
- WireGuard-based mesh establishment after identity verification
- Recovery procedures

This specification does NOT define:

- Client user interface or user experience
- Specific hardware requirements beyond minimum capabilities
- Service-side business logic
- Legacy credential storage formats (implementation-specific)

### 1.4 Relationship to Existing Standards

Loc'd builds on and combines existing standards. It does not replace them.

| Standard | Role in Loc'd |
|----------|--------------|
| FIDO2/WebAuthn (W3C) | Cryptographic identity model, hardware key interaction via CTAP2 |
| WireGuard | Encrypted tunnel establishment for mesh connectivity |
| DNSSEC (RFC 4033-4035) | Integrity protection for published identity records |
| DNS-over-HTTPS (RFC 8484) | Privacy protection for identity lookups |
| CBOR (RFC 8949) | Binary encoding for delegation tokens |
| COSE (RFC 9052) | Signing and encryption of delegation tokens |
| Ed25519 (RFC 8032) | Default signature algorithm |
| X25519 (RFC 7748) | Default key agreement for tunnel establishment |

## 2. Terminology

| Term | Definition |
|------|-----------|
| Master Key | The Tier 1 key pair representing the user's sovereign identity. Generated and stored in a phone's secure enclave. |
| Device Key | A Tier 2 key pair generated in a device's TPM or secure enclave, authorised by the Master Key via a delegation token. |
| Session Key | A Tier 3 ephemeral key pair used for a single connection. Exists only in memory. |
| Delegation Token | A signed data structure granting a Device Key scoped authority to act on behalf of the Master Key. |
| Identity Record | A DNS TXT record publishing a user's public Master Key. |
| Revocation Record | A DNS TXT record or out-of-band publication listing revoked Device Keys or Delegation Tokens. |
| Verifier | Any service that checks a Loc'd identity and delegation before granting access. |
| Claimant | Any device presenting a Loc'd identity and delegation to a Verifier. |
| Mesh | A set of devices connected via WireGuard tunnels, authenticated by Loc'd identities. |
| Legacy Bridge | A client component that manages credentials for services that do not support Loc'd natively. |
| Cooperative Namespace | A shared DNS zone (e.g., id.locd.net) providing subdomains for users without their own domain. |

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 3. Design Principles

1. **User sovereignty.** The user is the root of trust. No third party can revoke, modify, or intercept the user's identity without physical access to their hardware.

2. **Hardware-bound keys.** Private keys MUST be generated in and MUST NOT be extractable from hardware security modules (TPM 2.0, Secure Enclave, or equivalent).

3. **No shared secrets.** The protocol MUST NOT rely on passwords, pre-shared keys, API keys, or any credential that exists in more than one location simultaneously.

4. **Invisible security.** The protocol MUST be implementable such that routine authentication requires no user interaction after initial setup.

5. **Independent layers.** Each protocol layer (Identity, Mesh, Bridge) MUST be usable independently. A service MAY implement only the Identity layer without requiring Mesh connectivity.

6. **Graceful degradation.** If a Verifier cannot reach DNS, or a delegation is near expiry, the protocol MUST define fallback behaviour rather than failing silently.

7. **No vendor dependency.** The protocol MUST NOT require any specific vendor's infrastructure for core functionality. Coordination services, if used, MUST be self-hostable.

## 4. Key Hierarchy

### 4.1 Tier 1: Master Key

- **Algorithm:** Ed25519 (RFC 8032)
- **Generation:** MUST be generated within a hardware secure enclave (iOS Secure Enclave, Android StrongBox / TEE, or equivalent).
- **Storage:** Private key MUST NOT leave the secure enclave. All signing operations are performed within the enclave.
- **Access control:** Signing operations MUST require biometric authentication (fingerprint, face recognition) or device PIN.
- **Purpose:** Signs Delegation Tokens, Revocation statements, and Recovery operations. MUST NOT be used for routine authentication or session establishment.
- **Cardinality:** One Master Key per Loc'd identity.

### 4.2 Tier 2: Device Key

- **Algorithm:** Ed25519 (RFC 8032)
- **Generation:** MUST be generated within the device's TPM 2.0 or secure enclave.
- **Storage:** Private key MUST NOT leave the TPM/secure enclave.
- **Purpose:** Routine authentication, tunnel establishment, service connections.
- **Authorisation:** Each Device Key MUST have a valid Delegation Token signed by the Master Key.
- **Cardinality:** One Device Key per device. A single identity may have multiple authorised devices.

### 4.3 Tier 3: Session Key

- **Algorithm:** X25519 key agreement (RFC 7748), producing a shared secret for symmetric encryption (ChaCha20-Poly1305).
- **Generation:** Generated in memory for each connection.
- **Storage:** MUST NOT be written to persistent storage. MUST be destroyed when the session ends.
- **Purpose:** Encrypts a single session between Claimant and Verifier.
- **Lifetime:** Duration of one session. Maximum lifetime of 24 hours, after which re-establishment is REQUIRED.

### 4.4 Key Lifecycle

```
┌─────────────────────────────────────────────────────┐
│                    MASTER KEY                         │
│              (Phone Secure Enclave)                   │
│                                                       │
│  Signs:  Delegation Tokens                           │
│          Revocation Statements                        │
│          Recovery Operations                          │
│          Device Key Authorisations                    │
│                                                       │
│  Backed up to: USB Recovery Key (encrypted)          │
└──────────────────┬──────────────────────┬────────────┘
                   │ signs delegation     │ signs delegation
                   ▼                      ▼
        ┌──────────────────┐   ┌──────────────────┐
        │   DEVICE KEY A    │   │   DEVICE KEY B    │
        │   (Laptop TPM)    │   │   (Server TPM)    │
        │                   │   │                   │
        │  Scope: all       │   │  Scope: service X │
        │  Expiry: 30 days  │   │  Expiry: 24 hours │
        └────────┬──────────┘   └────────┬──────────┘
                 │ per-connection          │ per-connection
                 ▼                         ▼
        ┌──────────────────┐   ┌──────────────────┐
        │  SESSION KEY      │   │  SESSION KEY      │
        │  (Memory only)    │   │  (Memory only)    │
        │  Lifetime: 1 sess │   │  Lifetime: 1 sess │
        └──────────────────┘   └──────────────────┘
```

## 5. Identity Layer

### 5.1 Identity Creation

1. User installs a Loc'd-compatible client on their primary device (typically a smartphone with secure enclave).
2. The client generates an Ed25519 key pair within the secure enclave.
3. The public key becomes the user's Loc'd Identity.
4. The identity is represented as: `base64url(public_key)` (32 bytes → 43 characters).

### 5.2 Identity Publication

The user's public key is published as a DNS TXT record under their domain (or a cooperative namespace subdomain).

Record location:

```
_locd.<domain>                         # For domain owners
<username>._locd.id.locd.net           # For cooperative namespace users
```

Record format:

```
v=locd1; k=ed25519; p=<base64url-encoded-public-key>; t=<unix-timestamp>; exp=<unix-timestamp>; rev=<revocation-endpoint>
```

Fields:

| Field | Required | Description |
|-------|----------|-------------|
| v | REQUIRED | Protocol version. MUST be `locd1` for this specification. |
| k | REQUIRED | Key algorithm. MUST be `ed25519` for this specification. |
| p | REQUIRED | Base64url-encoded public key (no padding). |
| t | REQUIRED | Unix timestamp of key publication. |
| exp | OPTIONAL | Unix timestamp of key expiry. If absent, key does not expire. |
| rev | OPTIONAL | URL of supplementary revocation list. If absent, revocation is DNS-only. |

Example:

```
_locd.example.com. 300 IN TXT "v=locd1; k=ed25519; p=O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik; t=1739577600; rev=https://example.com/.well-known/locd/revocations"
```

### 5.3 DNSSEC Requirement

Identity records MUST be signed with DNSSEC. A Verifier MUST reject identity lookups that fail DNSSEC validation.

### 5.4 DNS-over-HTTPS (DoH)

Clients SHOULD perform identity lookups via DNS-over-HTTPS (RFC 8484) to prevent network observers from determining which identities a user is verifying.

### 5.5 TTL Recommendations

| Context | Recommended TTL |
|---------|----------------|
| Active identity record | 300 seconds (5 minutes) |
| Cooperative namespace record | 300 seconds (5 minutes) |
| Revoked/expired identity | 60 seconds (1 minute) |

### 5.6 Multiple Identities

A user MAY maintain multiple Loc'd identities (e.g., personal and professional). Each identity is an independent Master Key with its own DNS record, delegation tokens, and revocation scope.

### 5.7 Cooperative Namespace

For users without their own domain, the Loc'd project operates a cooperative namespace at `id.locd.net`. Users register a subdomain (e.g., `lane.id.locd.net`) and publish their identity record there.

The cooperative namespace:

- MUST be operated as a non-profit service.
- MUST allow users to migrate to their own domain at any time.
- MUST NOT impose vendor lock-in through proprietary extensions.
- SHOULD be operatable by multiple independent organisations (federated model).

## 6. Delegation Layer

### 6.1 Purpose

Delegation allows the holder of a Master Key to authorise other keys (Device Keys, agent keys) to act on their behalf with specific constraints.

### 6.2 Delegation Token Format

Delegation Tokens are CBOR-encoded (RFC 8949) and signed using COSE Sign1 (RFC 9052).

Token structure (CBOR map):

```
{
  1: "locd-delegation-v1",     ; type identifier
  2: bytes,                     ; delegator public key (Master Key)
  3: bytes,                     ; delegate public key (Device Key)
  4: uint,                      ; issued-at (Unix timestamp)
  5: uint,                      ; expires-at (Unix timestamp)
  6: text,                      ; delegation ID (UUID v4)
  7: [text],                    ; permitted services (domain patterns)
  8: [text],                    ; permitted actions (action strings)
  9: uint,                      ; max uses (0 = unlimited)
  10: text,                     ; device attestation (optional, TPM quote)
  11: bool                      ; can-sub-delegate (default: false)
}
```

| Key | Name | Required | Description |
|-----|------|----------|-------------|
| 1 | type | REQUIRED | MUST be "locd-delegation-v1" |
| 2 | delegator | REQUIRED | 32-byte Ed25519 public key of the Master Key |
| 3 | delegate | REQUIRED | 32-byte Ed25519 public key of the Device Key |
| 4 | issued_at | REQUIRED | Unix timestamp. Reject tokens with issued_at in the future (60s tolerance). |
| 5 | expires_at | REQUIRED | Unix timestamp. MUST be ≤ 30 days from issued_at. Default: 24 hours. |
| 6 | delegation_id | REQUIRED | UUID v4 string. Used for revocation. |
| 7 | services | OPTIONAL | Array of domain patterns. Empty/absent = all services. |
| 8 | actions | OPTIONAL | Array of action strings. Empty/absent = all actions. |
| 9 | max_uses | OPTIONAL | Maximum number of uses. 0/absent = unlimited. |
| 10 | attestation | OPTIONAL | TPM 2.0 attestation quote. |
| 11 | can_sub_delegate | OPTIONAL | Whether delegate can create further delegations. Default: false. |

### 6.3 Signing

The Delegation Token is wrapped in a COSE Sign1 structure:

```
COSE_Sign1 = [
  protected:   { 1: -8 },          ; alg: EdDSA
  unprotected: {},
  payload:     CBOR-encoded token,
  signature:   Ed25519 signature by Master Key
]
```

### 6.4 Constraints

- `expires_at` MUST NOT exceed 30 days from `issued_at`. Default SHOULD be 24 hours.
- Auto-renewal: Clients SHOULD automatically request renewed tokens before expiry when the Master Key device is reachable.
- If Master Key device is unreachable at renewal time, the delegation expires.

### 6.5 Sub-Delegation

If `can_sub_delegate` is true, the delegate MAY issue further delegation tokens. Sub-delegated tokens:

- MUST include a chain: original + sub-delegation token.
- MUST NOT expand scope beyond the parent delegation.
- MUST NOT exceed the parent delegation's `expires_at`.
- Chain depth MUST NOT exceed 3.

## 7. Verification Layer

### 7.1 Challenge-Response Protocol

```
Claimant                                    Verifier
   │                                           │
   │──── 1. HELLO (identity domain) ──────────▶│
   │                                           │
   │                          2. DNS lookup: _locd.<domain>
   │                             Verify DNSSEC chain
   │                             Extract public key
   │                                           │
   │◀─── 3. CHALLENGE (nonce, timestamp) ──────│
   │                                           │
   │     4. Sign challenge with Device Key     │
   │        Attach Delegation Token            │
   │                                           │
   │──── 5. RESPONSE (signature, delegation) ─▶│
   │                                           │
   │                          6. Verify delegation:
   │                             - Signed by published Master Key?
   │                             - Delegation not expired?
   │                             - Delegation not revoked?
   │                             - Service within scope?
   │                             - Action within scope?
   │                          7. Verify response signature:
   │                             - Signed by delegated Device Key?
   │                             - Nonce matches?
   │                             - Timestamp within tolerance?
   │                                           │
   │◀─── 8. VERIFIED / REJECTED ──────────────│
   │                                           │
   │──── 9. (If verified) Establish tunnel ───▶│
   │                                           │
```

### 7.2 Message Formats

All protocol messages are CBOR-encoded.

**HELLO:**
```
{
  1: "locd-hello-v1",
  2: "example.com",            ; identity domain
  3: bytes                     ; Claimant's Device Key public key
}
```

**CHALLENGE:**
```
{
  1: "locd-challenge-v1",
  2: bytes,                    ; 32-byte random nonce
  3: uint,                     ; Unix timestamp
  4: text                      ; Verifier's identity domain (for mutual auth)
}
```

**RESPONSE:**
```
{
  1: "locd-response-v1",
  2: bytes,                    ; Ed25519 signature over (nonce || timestamp || verifier_domain)
  3: bytes,                    ; COSE Sign1 Delegation Token
  4: [bytes]                   ; Sub-delegation chain (if any), ordered root-first
}
```

**RESULT:**
```
{
  1: "locd-result-v1",
  2: bool,                     ; verified (true/false)
  3: text,                     ; reason code
  4: bytes                     ; (If verified) Verifier's WireGuard public key
}
```

### 7.3 Mutual Authentication

Loc'd supports mutual authentication. After the Claimant is verified, the Verifier MAY prove its identity using the same protocol in reverse. RECOMMENDED for Mesh connections, OPTIONAL for service connections.

### 7.4 Reason Codes

| Code | Meaning |
|------|---------|
| ok | Verification succeeded |
| dns_lookup_failed | Could not resolve identity record |
| dnssec_invalid | DNSSEC validation failed |
| identity_not_found | No Loc'd identity record at domain |
| identity_expired | Identity record past exp timestamp |
| delegation_invalid | Delegation signature doesn't match published Master Key |
| delegation_expired | Delegation past expires_at |
| delegation_revoked | Delegation ID on revocation list |
| scope_violation | Service or action not permitted by delegation |
| nonce_mismatch | Response signature doesn't match challenge |
| timestamp_skew | Timestamps outside 60-second tolerance |
| chain_too_deep | Sub-delegation chain exceeds max depth |
| attestation_failed | TPM attestation did not validate |

### 7.5 Caching

Verifiers MAY cache a Claimant's public key for the DNS TTL duration. Verifiers MUST re-query when TTL expires. Verifiers MUST NOT cache past a Delegation Token's `expires_at`.

## 8. Revocation Layer

### 8.1 Revocation Mechanisms

**Layer 1: Short-Lived Delegations (Primary)**
- Default expiry of 24 hours.
- Compromised device loses authority within 24 hours even without active revocation.

**Layer 2: DNS Revocation Record (Authoritative)**
- DNS TXT record at `_locd-revoke.<domain>`
- Format: `v=locd-revoke1; ids=<comma-separated-delegation-UUIDs>; t=<timestamp>`
- Verifiers MUST check during verification.

**Layer 3: Supplementary Revocation List (Fast)**
- Published at URL in `rev` field of identity record.
- Signed JSON document:

```json
{
  "v": "locd-revoke-list-v1",
  "identity": "example.com",
  "revocations": [
    {
      "delegation_id": "550e8400-e29b-41d4-a716-446655440000",
      "revoked_at": 1739577600,
      "reason": "device_lost"
    }
  ],
  "published_at": 1739577660,
  "signature": "<base64url-encoded-Ed25519-signature>"
}
```

### 8.2 Revocation Reasons

| Reason | Description |
|--------|-------------|
| device_lost | Physical device lost or stolen |
| device_compromised | Device suspected or confirmed compromised |
| key_rotation | Routine key rotation |
| scope_change | Delegation scope reduced |
| user_initiated | User explicitly revoked |

### 8.3 Master Key Rotation

If the Master Key is compromised:

1. User recovers via USB Recovery Key (§11).
2. New Master Key generated in new device's secure enclave.
3. Key rotation record published to DNS:

```
_locd-rotate.<domain> TXT "v=locd-rotate1; old=<old-pubkey>; new=<new-pubkey>; t=<timestamp>; sig=<signature-by-old-key>"
```

4. All existing Delegation Tokens become invalid.
5. Devices must re-pair with new Master Key.
6. Transition period: recommended 7 days.

## 9. Mesh Connectivity Layer

### 9.1 Overview

The Mesh layer provides encrypted, peer-to-peer connectivity between devices authenticated by the Identity and Delegation layers. Uses WireGuard as the tunnel protocol.

### 9.2 Tunnel Establishment

After successful identity verification (§7.1):

1. Verification completes. Both parties confirmed.
2. RESULT message includes Verifier's WireGuard public key.
3. Claimant responds with its WireGuard public key.
4. Both configure a WireGuard peer entry.
5. WireGuard tunnel established.

### 9.3 Coordination

**Self-Hosted Coordination (RECOMMENDED):**
- Lightweight service compatible with Headscale API.
- Stores current IP addresses and port mappings.
- Authenticated via Loc'd identity.
- No traffic passes through coordinator.

**Peer-to-Peer Discovery (OPTIONAL):**
- Address info exchanged directly via WireGuard mesh.
- Requires one initial connection to bootstrap.
- Suitable for small meshes (2-5 devices).

### 9.4 No Open Ports

Mesh devices MUST NOT listen on publicly accessible ports. Connections via:

- WireGuard UDP hole-punching.
- STUN/TURN relay as fallback (relay sees only encrypted WireGuard traffic).
- Coordination service facilitating initial rendezvous.

### 9.5 Device-to-Device Sync

Devices within a mesh synchronise:

- Current delegation token set.
- Revocation lists.
- Legacy bridge credentials (encrypted to each device's TPM key).

Sync performed over WireGuard mesh. No external service involved.

## 10. Legacy Bridge Layer

### 10.1 Purpose

Manages credentials (passwords, API keys, OAuth tokens) for non-Loc'd services, encrypted to the device's hardware.

### 10.2 Credential Storage

- Encrypted using key derived from device's TPM-bound Device Key.
- Encryption: XChaCha20-Poly1305 with key via HKDF-SHA256 from Device Key.
- Stored on local filesystem.
- NEVER in plaintext, NEVER transmitted to a server, NEVER decryptable without TPM.

### 10.3 Credential Injection

1. Client decrypts credential within TPM trust boundary.
2. Credential injected into connection at moment of use.
3. Plaintext exists in memory only during injection.
4. Service receives a normal authenticated request.

### 10.4 Cross-Device Credential Sync

1. Source encrypts using shared secret from DH exchange between Device Keys.
2. Encrypted payload transmitted over WireGuard mesh.
3. Receiver re-encrypts to its own TPM-bound key.
4. Shared secret discarded after sync.

### 10.5 Dashboard Indicators

- **Green:** Native Loc'd authentication. No shared secrets.
- **Yellow:** Legacy Bridge. Credentials managed locally.
- **Red:** Known security issue or credential problem.

## 11. Recovery

### 11.1 USB Recovery Key

Primary recovery: physical USB security key (e.g., YubiKey 5 series).

**Backup creation:**
1. Master Key exported from secure enclave in encrypted form.
2. Encrypted with user passphrase using Argon2id (64MB memory, 3 iterations, 4 parallelism) + XChaCha20-Poly1305.
3. Written to USB key's FIDO2 resident credential storage.
4. Decryption requires passphrase AND physical presence (button press).

**Recovery process:**
1. Install Loc'd client on new device.
2. Insert USB recovery key.
3. Enter passphrase.
4. USB key decrypts internally.
5. Master Key transferred to new device's secure enclave via CTAP2.
6. USB key can be removed.
7. Re-pair devices or verify existing delegations.

### 11.2 Multiple Recovery Keys

Users SHOULD create multiple USB recovery keys stored in different physical locations.

### 11.3 Shamir's Secret Sharing (Optional)

- Split Master Key backup into N shares (recommended: 5 shares, threshold of 3).
- Distribute to trusted parties.
- Shares individually encrypted to each recipient.
- Recovery: collect threshold shares, reconstruct, decrypt, transfer to new device.

### 11.4 Recovery Without Backup

- Identity is irrecoverable. This is by design.
- Legacy Bridge services recoverable through individual service recovery.
- User creates new identity and re-registers.
- Trade-off of self-sovereignty: no "forgot password" backdoor.

## 12. DNS Record Formats

| Record | Location | Purpose |
|--------|----------|---------|
| Identity | `_locd.<domain>` | Publishes user's public Master Key |
| Revocation | `_locd-revoke.<domain>` | Lists revoked Delegation IDs |
| Key Rotation | `_locd-rotate.<domain>` | Announces Master Key rotation |
| Service Endpoint | `_locd-svc.<service-domain>` | Announces Loc'd-native service capability |

### 12.2 Service Discovery Record

```
_locd-svc.api.example.com TXT "v=locd-svc1; port=<coordination-port>; actions=read,write,admin; min-delegation-ttl=3600"
```

## 13. Wire Formats

### 13.1 Transport

Transport-agnostic. Options:
- Raw TCP (default port: TBD)
- WebSocket (browser clients)
- HTTP/2 or HTTP/3 (web services)

Length-prefixed frames:

```
┌────────────────┬──────────────────────┐
│ Length (4 bytes)│ CBOR payload         │
│ big-endian u32 │ (variable length)    │
└────────────────┴──────────────────────┘
```

### 13.2 Protocol Negotiation

HELLO includes protocol version. Verifier responds with `version_unsupported` and supported versions list if incompatible.

## 14. Security Considerations

### 14.1 Threat Model

| Threat | Mitigation |
|--------|-----------|
| DNS spoofing | DNSSEC required. Reject records failing validation. |
| Network eavesdropping | DoH for lookups. WireGuard for transport. |
| Stolen device | 24hr delegation default. Instant revocation. Biometric gating. |
| Compromised TPM | Single device only. Revoke device. Master Key on separate device. |
| Rogue coordination server | Only sees encrypted WireGuard traffic. Self-hostable. |
| Replay attack | Timestamp + random nonce. Reject replayed nonces. |
| Master Key compromise | USB recovery enables rotation. Old delegations invalidated. |
| DNS DoS | Cache for TTL. Accept cached if DNS unreachable (degraded). |

### 14.2 What Loc'd Does NOT Defend Against

- Nation-state with physical access and coercion.
- Secure enclave hardware compromise (side-channel attacks).
- User social engineering (bad delegation decisions).
- Availability (auth + encryption only, not uptime).

### 14.3 Cryptographic Agility

Protocol version field enables future algorithm adoption. Migration: publish new record with new version, maintain old during transition, remove after update.

## 15. IANA Considerations

Future versions will request:
- TCP/UDP port registration.
- `_locd`, `_locd-revoke`, `_locd-rotate`, `_locd-svc` DNS label registration (RFC 8552).
- `locd-delegation-v1` CBOR tag registration.

## 16. References

### Normative

- [RFC 2119] Requirement level key words
- [RFC 4033] DNS Security Introduction
- [RFC 7748] Elliptic Curves for Security (X25519)
- [RFC 8032] EdDSA (Ed25519)
- [RFC 8484] DNS-over-HTTPS
- [RFC 8949] CBOR
- [RFC 9052] COSE

### Informative

- [FIDO2] CTAP v2.1
- [WebAuthn] W3C Level 2
- [WireGuard] Donenfeld, NDSS 2017
- [Argon2] Biryukov et al., 2015
- [TPM 2.0] TCG Library Specification, Family 2.0

## Appendix A: Example Flows

### A.1 Complete Authentication Flow

```
1. User "lane" has Master Key published at:
   _locd.lane.id.locd.net TXT "v=locd1; k=ed25519; p=O2onvM62pC1io6jQ...; t=1739577600"

2. Lane's laptop has Device Key DK-laptop, with delegation token:
   {
     delegator: <Master Key pubkey>,
     delegate: <DK-laptop pubkey>,
     expires_at: 1739664000,        // 24 hours from issuance
     services: ["api.example.com"],
     actions: ["read", "write"]
   }
   Signed by Master Key.

3. Laptop connects to api.example.com:

   Laptop -> Service:  HELLO { domain: "lane.id.locd.net", device_key: <DK-laptop> }

   Service: DNS lookup _locd.lane.id.locd.net -> gets Master Key pubkey
            Verifies DNSSEC chain

   Service -> Laptop:  CHALLENGE { nonce: <random>, timestamp: <now>, verifier: "api.example.com" }

   Laptop: Signs (nonce || timestamp || "api.example.com") with DK-laptop private key (in TPM)

   Laptop -> Service:  RESPONSE { signature: <sig>, delegation: <COSE Sign1 token> }

   Service: Verifies delegation:
            - Delegation signed by Master Key from DNS? YES
            - Delegation not expired? YES (24hr window)
            - Delegation not revoked? YES (checked DNS + rev endpoint)
            - "api.example.com" in permitted services? YES
            - Actions within scope? YES
            Verifies response:
            - Signature matches challenge nonce? YES
            - Signed by the delegated Device Key? YES

   Service -> Laptop:  RESULT { verified: true, wireguard_key: <service WG pubkey> }

   WireGuard tunnel established.
```

### A.2 Revocation Flow

```
1. Lane loses his laptop.

2. Lane opens Loc'd app on phone.
   App shows: "DK-laptop - authorized 2026-02-14, expires 2026-02-15"
   Lane swipes to revoke.

3. Phone (Master Key) signs a revocation statement for DK-laptop's delegation ID.

4. Revocation is published:
   a. DNS: _locd-revoke.lane.id.locd.net updated with delegation ID
   b. HTTPS: https://lane.id.locd.net/.well-known/locd/revocations updated

5. Next time anyone tries to verify DK-laptop's delegation:
   - DNS revocation check finds the delegation ID -> REJECTED
   - Even if DNS hasn't propagated, HTTPS revocation list -> REJECTED

6. DK-laptop's delegation expires naturally within 24 hours regardless.
```

## Appendix B: Comparison with Existing Standards

| Feature | Loc'd | Passkeys | OAuth 2.0 | mTLS | Tailscale |
|---------|-------|----------|-----------|------|-----------|
| User owns identity | Yes | No (vendor-synced) | No (provider-owned) | Partial | No |
| Hardware-bound keys | Yes (required) | Optional | No | Optional | No |
| No shared secrets | Yes | Yes | No (tokens) | Yes | Yes |
| Scoped delegation | Yes | No | Partial | No | No |
| Time-limited auth | Yes (24hr) | No | Yes | Yes | No |
| User-controlled revocation | Yes (instant) | No | No | Partial | No |
| No vendor dependency | Yes | No | No | Yes | No |
| Encrypted connectivity | Yes (WireGuard) | No | No | Yes | Yes |
| Works without server | Yes | No | No | No | No |
| Legacy service support | Yes (bridge) | No | N/A | No | No |

---

*This specification is licensed under Creative Commons Attribution 4.0 International (CC BY 4.0).*
