# Changelog

All notable changes to the RCPT Protocol are documented here.

## [Unreleased]

### Fixed — cross-SDK verification (Python ↔ TypeScript)

Receipts carrying custom metadata or certain values verified in the SDK that
signed them but **failed** in the other SDK. All four causes are fixed:

- **TypeScript dropped custom metadata keys** in `Receipt.toDict()`, so any
  Python receipt with `Metadata.extra` (e.g. `{"confidence": 0.95}`) failed TS
  verification. The 0.1.1 note that `extra` was preserved "in both SDKs" was
  only true for Python.
- **Python JCS omitted `null` values**; RFC 8785 and the TS SDK keep them.
- **Python JCS used `repr()` for floats** (`1.0`, `1e-07`, `1e+16`) instead of
  the ECMAScript form RFC 8785 requires (`1`, `1e-7`, `10000000000000000`).
- **Python dropped empty `tags` / `compliance` lists**, so TS receipts with
  `tags: []` failed Python verification.
- Python JCS now sorts keys by UTF-16 code units (RFC 8785 §3.2.3), and both
  SDKs reject NaN/Infinity instead of emitting invalid JSON.

**Compatibility:** receipts signed by the Python SDK whose metadata contains
integral floats (`1.0`), exponent-form floats or `null` values were signed over
non-standard bytes and will no longer verify. Receipts without such values are
unaffected.

### Tests
- `tests/test_jcs.py` — RFC 8785 number and key-ordering vectors (runs without Node).
- 3 new cross-language regression tests in `tests/test_interop.py`.
- CI: new `cross-sdk-interop` job builds the TS SDK and fails if the interop
  suite is skipped. Previously the interop tests were always skipped in CI
  because the TS SDK was never built in the Python job.
- Totals: 209 Python, 64 TypeScript, 19 MCP — 292 tests, 0 failures, 0 skipped.

## [0.1.1] — 2026-03-28

### Breaking Changes

**Signing algorithm corrected (cross-SDK interop fix)**

Previous releases of the Python and TypeScript SDKs incorrectly pre-hashed the
JCS canonical bytes with SHA-256 before passing them to Ed25519. RFC 8032
specifies that Ed25519 operates on the raw message bytes directly — the
algorithm internally applies its own hashing. The Go SDK (`rcpt-go`) was
already correct.

- **Before:** `signature = Ed25519.sign(SHA256(JCS(receipt_body)))`
- **After:** `signature = Ed25519.sign(JCS(receipt_body))`

**Impact:** Receipts signed with Python/TypeScript SDK v0.1.0 will **not**
verify under v0.1.1, and will **not** verify against the Go SDK. This is
intentional — the old behavior was wrong. Re-sign any receipts that must
remain verifiable.

**`delegation.scope` type changed from string to array**

The `delegation.scope` field now uses `["read:x", "write:y"]` (JSON array)
instead of `"read:x,write:y"` (comma-separated string). This aligns with the
Go SDK and standard OAuth 2.0 scope conventions.

- **Before:** `"scope": "read:crm,write:reports"`
- **After:** `"scope": ["read:crm", "write:reports"]`

Backward compatibility: `Receipt.from_dict()` / `Receipt.fromDict()` in both
Python and TypeScript SDKs will automatically normalize legacy string scopes
to arrays on deserialization.

### Added
- `rcpt chain` CLI command now fully implemented (was registered but unhandled)
- `ReceiptStore.store_many()` uses a single SQLite transaction (was N commits)
- `ReceiptStore.export_json()` exports all receipts without silent 100-receipt truncation
- `Metadata.extra` field now preserved through `attest()`, `from_dict()`, and JSON roundtrip in both Python and TypeScript SDKs
- Go SDK (`rcpt-go`) — new third SDK; full spec compliance; Builder pattern; chain/trust/verify/jcs packages
- Conduid integration — RCPT receipt generation on every tracked MCP event; per-server DIDs; 7 new API endpoints

### Fixed
- Python `crypto.py`: removed `hashlib` import (no longer used after signing fix)
- TypeScript `crypto.ts`: removed unused `createHash` import
- `Delegation.scope` type corrected in Python `models.py`, TypeScript `models.ts`, JSON schema, and spec
- All spec examples updated (§3.3, Appendix A.2) to use array scope format
- Spec §4.2 and §4.3 updated to describe correct RFC 8032 signing (no pre-hash)

### Tests
- 198 Python tests (was 190 in this archive; 8 restored from previous sessions)
- 64 TypeScript tests (unchanged)
- 19 MCP tests (unchanged)
- **Total: 281 tests, 0 failures**
- Cross-language interop: all 5 interop tests pass (Python ↔ TypeScript signing confirmed compatible)

---

## [0.1.0] — 2026-02-22

### Protocol
- RCPT v0.1 specification (7 required fields, 8 optional field groups)
- JSON Schema for receipt validation
- Ed25519 signatures with JCS canonicalization (RFC 8785)
- W3C DID `did:key` agent identity
- ULID receipt identifiers
- Receipt chaining via `parent_receipt_id`
- Merkle tree batching with proof generation/verification

### Python SDK
- `RCPTClient` — attest, verify, chain, export
- `ReceiptStore` — SQLite persistence with query, Merkle batching, export
- `ReputationEngine` — v0.1 scoring algorithm (volume, consistency, age, verification, dispute)
- `ComplianceDashboard` — EU AI Act gap analysis (Articles 12, 19, 26)
- `rcpt` CLI — keygen, attest, verify, inspect, hash, merkle, compliance, reputation
- Zero external dependencies (stdlib only)
- 165 tests passing

### TypeScript SDK
- Full feature parity with Python SDK
- `RCPTClient`, `Receipt`, `ReputationEngine`, `ComplianceDashboard`
- Private key import/export with `deriveFromPrivateKey()`
- Zero external dependencies (Node.js crypto only)
- 64 tests passing

### Integrations
- **LangChain** — `RCPTCallbackHandler` for automatic receipt generation
- **CrewAI** — `RCPTCrewPlugin` for multi-agent receipt chaining
- **OpenAI SDK** — `ReceiptedOpenAI` drop-in wrapper
- **Anthropic SDK** — `ReceiptedAnthropic` drop-in wrapper
- **FastAPI** — `RCPTMiddleware` with receipt headers and introspection API
- **MCP Server** — 8 tools over JSON-RPC 2.0 / stdio (19 tests)

### Infrastructure
- Solana anchor program for Merkle root anchoring
- Receipt explorer web UI
- Landing page (rcptprotocol.com)
- Documentation site (rcpt.dev)
- GitHub Actions CI (Python 3.9-3.13, Node 18/20/22)
- NIST NCCoE comment letter

### Examples
- Multi-agent enterprise workflow
- `@receipted` function decorator
- Public verification service
