# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in the RCPT Protocol, SDKs, or related tooling, please report it responsibly.

**Email:** security@rcptprotocol.com

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for a fix within 7 days.

**Do not** open a public GitHub issue for security vulnerabilities.

## Cryptographic Design

### Signature Scheme
- **Algorithm:** Ed25519 (RFC 8032)
- **Key size:** 256-bit (128-bit security level)
- **Implementation:** Python stdlib `cryptography` library / Node.js `crypto` module
- **Deterministic:** Ed25519 signatures are deterministic; same message + key = same signature

### Hashing
- **Algorithm:** SHA-256
- **Canonicalization:** JCS (RFC 8785) before hashing ensures deterministic byte representation
- **Format:** `sha256:{64 hex chars}`

### Identity
- **Standard:** W3C DID `did:key` method
- **Encoding:** Multicodec 0xed01 (Ed25519 public key) + base58btc
- **Self-certifying:** The DID embeds the public key; no external registry needed

### What RCPT Does NOT Protect Against

- **Key compromise:** If an agent's private key is leaked, the attacker can sign receipts as that agent. Mitigation: key rotation, revocation receipts.
- **Timestamp forgery:** Without on-chain anchoring, timestamps are self-reported. Anchored receipts provide a trustless upper bound.
- **Output verification:** RCPT proves *that* an output was produced and *who* produced it. It does not prove the output is *correct* or *truthful*.
- **Replay attacks:** Verifiers should check for duplicate receipt IDs. ULIDs are unique but the protocol does not enforce deduplication at the store level.

### Dependencies

**Python SDK:** Uses only the Python standard library (`hashlib`, `json`, `base64`, `dataclasses`). The `cryptography` package is used for Ed25519 but can be replaced with `pynacl` or any Ed25519 implementation.

**TypeScript SDK:** Uses only Node.js built-in `crypto` module. Zero external dependencies.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Current |

## Security Audits

The RCPT Protocol has not yet undergone a formal third-party security audit. We welcome and encourage independent review of the cryptographic implementation.
