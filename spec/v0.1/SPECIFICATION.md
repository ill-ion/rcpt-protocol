# RCPT Protocol Specification v0.1

**Receipt Chain Protocol for Trust — Cryptographic Proof-of-Action for AI Agents**

Status: DRAFT
Version: 0.1
Date: February 2026
License: Apache 2.0

---

## Abstract

RCPT (Receipt Chain Protocol for Trust) defines an open protocol for generating, signing, chaining, and verifying cryptographic attestations of AI agent actions. Each attestation ("receipt") binds an action to an agent identity, timestamp, and content hashes via Ed25519 digital signatures. Receipts may be chained into directed acyclic graphs representing multi-step workflows, and optionally anchored on a blockchain via Merkle tree roots for trustless timestamp verification.

The protocol is designed to be minimal, privacy-preserving, framework-agnostic, and composable — enabling agent identity, audit trails, regulatory compliance, and reputation to emerge from a single cryptographic primitive.

## 1. Terminology

| Term | Definition |
|------|-----------|
| **Receipt** | A signed JSON document attesting that an AI agent performed a specific action at a specific time. |
| **Agent** | Any software entity that uses an AI model to perform actions autonomously or semi-autonomously. |
| **Attestation** | The act of generating and signing a receipt. |
| **Chain** | A sequence of receipts linked by parent references, representing a multi-step workflow. |
| **Anchor** | The act of publishing a Merkle root of a batch of receipts to a blockchain. |
| **DID** | Decentralized Identifier — a self-sovereign identity standard (W3C DID Core). |
| **JCS** | JSON Canonicalization Scheme (RFC 8785) — deterministic JSON serialization. |
| **ULID** | Universally Unique Lexicographically Sortable Identifier. |

## 2. Receipt Structure

### 2.1 Required Fields

Every RCPT receipt MUST contain the following fields:

| Field | Type | Format | Description |
|-------|------|--------|-------------|
| `rcpt_version` | string | Semver | Protocol version. MUST be `"0.1"` for this specification. |
| `receipt_id` | string | ULID | Unique identifier. MUST be a valid ULID (26 characters, Crockford Base32). |
| `timestamp` | string | ISO 8601 | Time of attestation. MUST include milliseconds. MUST be UTC (Z suffix). |
| `agent_id` | string | DID | Identity of the attesting agent. MUST be a valid DID. |
| `action_type` | string | enum | One of: `inference`, `tool_call`, `transaction`, `delegation`, `observation`, `custom`. |
| `output_hash` | string | `sha256:{hex}` | SHA-256 hash of the action output. MUST be lowercase hex, 64 characters. |
| `signature` | string | `ed25519:{b64url}` | Ed25519 signature of the canonical receipt body. |

### 2.2 Optional Fields

See the [JSON Schema](receipt-schema.json) for the complete optional field definitions, including:

- `input_hash` — SHA-256 hash of the action input
- `parameters_hash` — SHA-256 hash of model configuration
- `model` — Model provider, ID, and version
- `framework` — Agent framework name and version
- `chain` — Parent receipt ID(s), workflow ID, sequence number
- `delegation` — Delegator ID, scope, expiry
- `anchor` — Blockchain, transaction hash, Merkle root and proof
- `metadata` — Description, tags, TTL, compliance references

### 2.3 Action Types

| Type | Use When |
|------|----------|
| `inference` | Agent calls an LLM for text, image, code, or embedding generation. |
| `tool_call` | Agent invokes an external tool, API, database query, or MCP tool. |
| `transaction` | Agent executes a financial transaction, blockchain transaction, or state-changing operation. |
| `delegation` | Agent delegates authority or a task to another agent. |
| `observation` | Agent reads or observes data without modifying external state. |
| `custom` | Any action not covered above. SHOULD include `metadata.description`. |

## 3. Identity

### 3.1 Agent Identity

Agent identity is based on W3C Decentralized Identifiers (DIDs). The RECOMMENDED method for agent identity is `did:key`, which encodes the agent's public key directly:

```
did:key:z6Mkf5rGMoatrSj1f4QLP1RGvMwb5bPCG2gkKvEBSjQdkCas
```

The `did:key` method requires no registry or resolution infrastructure. The agent's identity IS its public key.

For enterprise environments where organizational anchoring is needed, `did:web` is RECOMMENDED:

```
did:web:company.com:agents:sales-bot-v2
```

Implementations MAY support additional DID methods (e.g., `did:ion`, `did:sol`) as needed.

### 3.2 Key Management

- Each agent instance MUST have a unique Ed25519 keypair.
- Private keys SHOULD be stored in a secure enclave, HSM, or encrypted keystore.
- Key rotation SHOULD generate a new DID and a `delegation` receipt linking the old and new identities.
- Compromised keys SHOULD be revoked by publishing a revocation receipt with `action_type: "custom"` and `metadata.description: "key-revocation"`.

### 3.3 Human Identity Binding

When an agent acts on behalf of a human, the `delegation` field MUST be present:

```json
{
  "delegation": {
    "delegator_id": "did:web:company.com:users:jane",
    "scope": ["read:documents", "write:email"],
    "expires": "2026-02-20T16:30:00.000Z"
  }
}
```

This creates a cryptographic binding between the human authorization and the agent's actions.

## 4. Signing and Verification

### 4.1 Canonical Serialization

To produce a deterministic signature, the receipt body MUST be serialized using JSON Canonicalization Scheme (JCS, RFC 8785):

1. Remove the `signature` field from the receipt object.
2. Remove the `anchor` field if present (anchoring is post-hoc).
3. Serialize using JCS: sorted keys, no whitespace, UTF-8 encoding.
4. The result is the **canonical bytes**.

### 4.2 Signing

1. Sign the canonical bytes directly with the agent's Ed25519 private key → 64-byte signature (per RFC 8032 — no pre-hashing).
2. Encode the signature as base64url (no padding).
3. Set `signature` to `"ed25519:{base64url_signature}"`.

### 4.3 Verification

1. Extract and remove the `signature` field from the receipt.
2. Remove the `anchor` field if present.
3. Serialize the remaining object using JCS.
4. Decode the base64url signature from the `signature` field.
5. Resolve the agent's public key from `agent_id` (for `did:key`, the key is embedded in the DID).
6. Verify the Ed25519 signature against the canonical bytes and public key (per RFC 8032 — no pre-hashing).

A receipt is **valid** if and only if the signature verification succeeds.

## 5. Receipt Chaining

### 5.1 Chain Model

Receipts form directed acyclic graphs (DAGs) via the `chain.parent_receipt_id` field. This enables:

- **Linear chains:** A → B → C → D (sequential workflow)
- **Fan-out:** A → {B, C, D} (parallel tasks from one parent)
- **Fan-in:** {B, C, D} → E (aggregation from multiple parents)

### 5.2 Single Parent

```json
{
  "chain": {
    "parent_receipt_id": "01JMBN6A2WKXYZ...",
    "workflow_id": "01JMBN5P9RABC...",
    "sequence": 2
  }
}
```

### 5.3 Multiple Parents (Fan-In)

```json
{
  "chain": {
    "parent_receipt_id": [
      "01JMBN6A2WKXYZ...",
      "01JMBN7B3XLMNO...",
      "01JMBN8C4YPQRS..."
    ],
    "workflow_id": "01JMBN5P9RABC...",
    "sequence": 5
  }
}
```

### 5.4 Workflow Isolation

All receipts in the same workflow SHOULD share the same `workflow_id`. This enables efficient querying of complete workflows without traversing the full chain graph.

### 5.5 Cross-Agent Chains

When Agent B chains off Agent A's receipt, Agent B's receipt references Agent A's receipt ID. This creates a verifiable chain of custody across agent boundaries. The verifier can confirm that Agent A's receipt is valid before trusting Agent B's chain.

## 6. On-Chain Anchoring

### 6.1 Purpose

Anchoring provides trustless timestamp verification — proof that a receipt existed at a specific time, without trusting the receipt creator or any centralized authority.

### 6.2 Process

1. **Batch:** Collect receipts over a configurable time window (RECOMMENDED: 60 seconds or 1,000 receipts, whichever comes first).
2. **Hash:** Compute the SHA-256 hash of each receipt's canonical bytes.
3. **Merkle tree:** Build a binary Merkle tree from the receipt hashes (leaf sorting: lexicographic by hash).
4. **Anchor:** Publish the Merkle root to the target blockchain.
5. **Backfill:** Update each receipt's `anchor` field with:
   - `chain`: blockchain identifier
   - `tx_hash`: transaction hash
   - `merkle_root`: root hash
   - `merkle_proof`: proof path from receipt hash to root
   - `anchored_at`: blockchain-confirmed timestamp

### 6.3 Verification

Given a receipt and its `anchor` field:

1. Compute SHA-256 of the receipt's canonical bytes.
2. Walk the `merkle_proof` array, hashing pairs at each level.
3. Confirm the computed root matches `anchor.merkle_root`.
4. Look up `anchor.tx_hash` on the blockchain and confirm it contains `anchor.merkle_root`.
5. The blockchain's timestamp for that transaction is the trustless anchor time.

### 6.4 Chain Support

The primary anchor chain is **Solana** (fast finality, low cost). The protocol is chain-agnostic — implementations MAY support additional chains (Ethereum L2s, Bitcoin via OP_RETURN, etc.).

### 6.5 Self-Anchoring

Any party MAY anchor their own receipts. The RCPT protocol does not require a centralized anchoring service. Hosted anchoring is a convenience, not a dependency.

## 7. Privacy

### 7.1 Hash-Only Default

Receipts store SHA-256 hashes of inputs and outputs, never raw data. The hash is one-way — it can verify that a known input matches but cannot reverse-engineer the input.

### 7.2 Selective Disclosure

Agents control which optional fields to include. A minimal receipt (7 required fields) reveals only that an agent of a given identity performed an action of a given type at a given time, with a given output hash. No content is disclosed.

### 7.3 GDPR Compliance (Crypto-Shredding)

For data subject deletion requests (GDPR Article 17):

1. Store the mapping of `output_hash → encrypted(output_data)` separately from the receipt.
2. Encrypt using a per-record or per-subject key.
3. To "delete" data: destroy the encryption key.
4. The receipt persists (maintaining audit trail integrity) but the referenced data is irrecoverable.

### 7.4 On-Chain Privacy

Only Merkle roots are published on-chain. Individual receipt contents are never on-chain. Receipt data is only visible to parties who have been given access to the off-chain store.

## 8. Compliance Mapping

### 8.1 EU AI Act (Regulation (EU) 2024/1689)

| Article | Requirement | RCPT Mapping |
|---------|-------------|--------------|
| 12(1) | Automatic recording of events over system lifetime | SDK auto-generates receipts for every agent action |
| 12(2a) | Identify situations presenting risk | Receipt chain analysis detects anomalous patterns |
| 12(2b) | Facilitate post-market monitoring | Receipt export API and dashboard |
| 19 | Providers keep automatically generated logs (6+ months) | Configurable TTL; anchored receipts are permanent |
| 26(5) | Deployers monitor operation of high-risk AI | Real-time receipt stream monitoring |
| 26(6) | Deployers keep logs (6+ months) | Receipt store with retention policies |

### 8.2 NIST SP 800-207 (Zero Trust Architecture)

| Principle | RCPT Mapping |
|-----------|-------------|
| Verify explicitly | Every action cryptographically signed and verifiable |
| Least privilege access | Delegation receipts encode scope and expiry |
| Assume breach | Immutable receipt chains enable full forensic reconstruction |

## 9. Reputation (Informational)

This section is informational and not normative. Implementations MAY compute reputation scores from receipt data.

### 9.1 Algorithm (v0.1)

```
reputation = weighted_sum(
    volume_score      * 0.20,
    consistency_score * 0.25,
    age_score         * 0.15,
    verification_rate * 0.20,
    dispute_rate      * 0.20
)
```

- **volume_score:** `min(1.0, log10(total_receipts) / 4)` — logarithmic, caps at 10,000
- **consistency_score:** fraction of actions with complete receipt chains
- **age_score:** `min(1.0, days_since_first_receipt / 365)`
- **verification_rate:** fraction of receipts verified by third parties
- **dispute_rate:** `1.0 - (disputed_receipts / total_receipts)`

Score range: 0–100.

### 9.2 Trust Levels

| Score | Level | Description |
|-------|-------|-------------|
| 0–20 | Unverified | New or untested agent |
| 21–40 | Emerging | Some history, limited verification |
| 41–60 | Established | Consistent history, some third-party verification |
| 61–80 | Trusted | Strong history, low disputes, regularly verified |
| 81–100 | Authority | Extensive history, zero disputes, widely verified |

## 10. Security Considerations

### 10.1 Key Compromise

If an agent's private key is compromised, all future receipts from that key are suspect. Mitigations:
- Publish a key-revocation receipt immediately.
- Rotate to a new keypair and DID.
- Receipts signed before compromise remain valid (the key was legitimate at the time).

### 10.2 Replay Attacks

Each receipt has a unique `receipt_id` (ULID) and `timestamp`. Verifiers SHOULD reject duplicate receipt IDs.

### 10.3 Timestamp Manipulation

Without anchoring, timestamps are self-reported and untrusted. On-chain anchoring provides a trustless upper bound on when the receipt existed. Verifiers requiring trusted timestamps SHOULD require anchored receipts.

### 10.4 Receipt Forgery

Receipts cannot be forged without the agent's private key. Ed25519 provides 128-bit security against forgery.

### 10.5 Merkle Proof Manipulation

Merkle proofs are verifiable against on-chain roots. A manipulated proof will not match the published root.

## 11. IANA Considerations

This specification defines no IANA registries. The `rcpt_version` field provides protocol versioning. Future versions MAY register media types or URI schemes as needed.

## 12. References

- [RFC 8785] Rundgren, A., "JSON Canonicalization Scheme (JCS)", RFC 8785, June 2020.
- [W3C DID Core] Sporny, M., et al., "Decentralized Identifiers (DIDs) v1.0", W3C Recommendation, July 2022.
- [Ed25519] Bernstein, D.J., et al., "High-speed high-security signatures", Journal of Cryptographic Engineering, 2012.
- [ULID] Fregly, A., "Universally Unique Lexicographically Sortable Identifier", 2016.
- [EU AI Act] Regulation (EU) 2024/1689 of the European Parliament and of the Council, June 2024.
- [NIST SP 800-207] Rose, S., et al., "Zero Trust Architecture", NIST Special Publication 800-207, August 2020.

## Appendix A: Example Receipts

### A.1 Minimal Receipt

```json
{
  "rcpt_version": "0.1",
  "receipt_id": "01JMBN7K8X3YZ4A5B6C7D8E9F0",
  "timestamp": "2026-02-20T15:30:00.123Z",
  "agent_id": "did:key:z6Mkf5rGMoatrSj1f4QLP1RGvMwb5bPCG2gkKvEBSjQdkCas",
  "action_type": "inference",
  "output_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "signature": "ed25519:3K4lRtBXkFqZ8mN2pY7vW9xA1cD5eH6gJ0kL3nP8rS4tU"
}
```

### A.2 Full Receipt with Chaining and Delegation

```json
{
  "rcpt_version": "0.1",
  "receipt_id": "01JMBN8M9Y4ZA5B6C7D8E9F0G1",
  "timestamp": "2026-02-20T15:30:45.789Z",
  "agent_id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "action_type": "tool_call",
  "output_hash": "sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
  "input_hash": "sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
  "parameters_hash": "sha256:f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e1",
  "model": {
    "provider": "anthropic",
    "model_id": "claude-sonnet-4-5-20250929",
    "version": "2025-09-29"
  },
  "framework": {
    "name": "crewai",
    "version": "0.80.0"
  },
  "chain": {
    "parent_receipt_id": "01JMBN7K8X3YZ4A5B6C7D8E9F0",
    "workflow_id": "01JMBN5P9RABC4D5E6F7G8H9J0",
    "sequence": 2,
    "depth": 1
  },
  "delegation": {
    "delegator_id": "did:web:acme.com:users:jane-smith",
    "scope": ["read:crm", "write:reports"],
    "expires": "2026-02-20T17:30:00.000Z"
  },
  "metadata": {
    "description": "Retrieved Q4 sales data from CRM for quarterly report generation",
    "tags": ["finance", "reporting", "crm"],
    "compliance": ["eu-ai-act"]
  },
  "signature": "ed25519:7H8jK9lM0nP1qR2sT3uV4wX5yZ6aB7cD8eF9gH0jK1lM2n"
}
```

### A.3 Anchored Receipt

```json
{
  "rcpt_version": "0.1",
  "receipt_id": "01JMBN7K8X3YZ4A5B6C7D8E9F0",
  "timestamp": "2026-02-20T15:30:00.123Z",
  "agent_id": "did:key:z6Mkf5rGMoatrSj1f4QLP1RGvMwb5bPCG2gkKvEBSjQdkCas",
  "action_type": "inference",
  "output_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "signature": "ed25519:3K4lRtBXkFqZ8mN2pY7vW9xA1cD5eH6gJ0kL3nP8rS4tU",
  "anchor": {
    "chain": "solana",
    "tx_hash": "5K4lRtBXkFqZ8mN2pY7vW9xA1cD5eH6gJ0kL3nP8rS4tU6vW7xY8zA9bC0dE",
    "merkle_root": "sha256:b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8",
    "merkle_proof": [
      "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    ],
    "anchored_at": "2026-02-20T15:31:00.456Z"
  }
}
```
