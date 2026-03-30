# Public Comment: RCPT Protocol — Receipt Chain Protocol for Trust for Agent Identity and Auditing

**To:** AI-Identity@nist.gov
**Re:** Accelerating the Adoption of Software and AI Agent Identity and Authorization — Concept Paper
**Date:** March 2026
**From:** [Name], RCPT Protocol

---

## Executive Summary

We submit this comment in response to the NCCoE concept paper on Software and AI Agent Identity and Authorization. We introduce **RCPT (Receipt Chain Protocol for Trust)**, an open protocol that provides cryptographic proof-of-action for AI agents through signed, chained, and verifiable attestation receipts.

RCPT addresses a critical gap in the current standards landscape: while OAuth 2.0, OIDC, and SPIFFE handle agent authentication and authorization, **no existing standard provides non-repudiation, tamper-evident audit trails, and emergent agent identity from a single, composable primitive.** RCPT is designed to complement — not replace — the identity standards under consideration by the NCCoE.

The protocol is fully open (Apache 2.0), framework-agnostic, and available as SDKs for Python, TypeScript, and as a Model Context Protocol (MCP) server. A working implementation, specification, and JSON Schema are publicly available at [github.com/rcpt-protocol/rcpt-protocol](https://github.com/rcpt-protocol/rcpt-protocol).

---

## Response to Concept Paper Questions

### Section 5: Auditing and Non-Repudiation

**Q: "How can we ensure that agents log their actions and intent in a tamper-proof and verifiable manner?"**

This is RCPT's core value proposition. The protocol generates a signed JSON attestation ("receipt") for every agent action. Each receipt contains:

- **Agent identity** (W3C Decentralized Identifier encoding the agent's Ed25519 public key)
- **Action type** (inference, tool call, transaction, delegation, observation)
- **Output hash** (SHA-256 hash of the action output — content itself is never stored)
- **Timestamp** (ISO 8601, UTC, millisecond precision)
- **Ed25519 signature** (computed over JCS-canonicalized receipt body per RFC 8785)

Tamper evidence is provided at two levels:

1. **Cryptographic signing:** Each receipt is signed with the agent's Ed25519 private key. Any modification to the receipt body invalidates the signature. Verification requires only the agent's public key (embedded in the DID).

2. **On-chain anchoring (optional):** Receipts are batched into Merkle trees with roots published to a blockchain (Solana). This provides trustless timestamp proof — any party can verify a receipt existed at a specific time without trusting the receipt creator.

Integration requires minimal developer effort:

```python
from rcpt import RCPTClient, ActionType

client = RCPTClient(private_key="...")
receipt = client.attest(
    action_type=ActionType.TOOL_CALL,
    output=api_response,
    input_data=tool_parameters
)
# Receipt is signed, stored, and queued for anchoring
```

**Q: "How do we ensure non-repudiation for agent actions and binding back to human authorization?"**

RCPT receipts support a **delegation** field that cryptographically binds agent actions to human authorization:

```json
{
  "delegation": {
    "delegator_id": "did:web:company.com:users:jane-smith",
    "scope": ["read:documents", "write:reports"],
    "expires": "2026-02-20T17:30:00.000Z"
  }
}
```

Combined with receipt chaining, this creates a verifiable chain from human authorization through every subsequent agent action. An auditor can:

1. Verify the delegation receipt was signed by the human's identity
2. Verify each agent receipt chains to the delegation receipt
3. Verify each agent receipt's scope falls within the delegated authority
4. Verify the delegation had not expired at the time of each action

Non-repudiation is achieved because the agent cannot produce a valid receipt without possession of its private key, and the delegation chain proves the authorization path back to a human identity.

### Section 2: Identification

**Q: "How might agents be identified in an enterprise architecture? What metadata is essential for an AI agent's identity?"**

RCPT uses W3C Decentralized Identifiers (DIDs) for agent identity. The recommended method is `did:key`, which encodes the agent's Ed25519 public key directly:

```
did:key:z6Mkf5rGMoatrSj1f4QLP1RGvMwb5bPCG2gkKvEBSjQdkCas
```

This approach has several advantages for agent architectures:

- **No registry dependency:** The agent's identity IS its public key. No centralized registry is needed for identity resolution.
- **Ephemeral or persistent:** New agents can generate identities instantly. Long-lived agents maintain their identity through key continuity.
- **Enterprise anchoring:** For organizational contexts, `did:web` provides domain-anchored identity: `did:web:company.com:agents:sales-bot-v2`
- **Interoperable:** W3C DIDs are interoperable with OIDC claims (the DID can be included as a claim in OIDC tokens) and with SPIFFE IDs.

RCPT introduces a unique contribution to agent identification: **emergent identity through receipt history.** An agent's receipt chain serves as a verifiable track record — analogous to a credit history for financial identity. The protocol defines a reputation algorithm computed from receipt metrics (volume, consistency, verification rate, dispute rate), enabling trust decisions without centralized attestation.

**Q: "Should agent identity metadata be ephemeral or fixed?"**

Both, depending on the use case. RCPT supports:

- **Ephemeral agents:** Generate a new `did:key` per task. Receipts are chained to the task's workflow ID. Identity exists only for the duration of the task.
- **Persistent agents:** Maintain a `did:key` across sessions. Receipt history accumulates into a reputation score.
- **Key rotation:** A delegation receipt links old and new DIDs, maintaining identity continuity while updating cryptographic material.

### Section 4: Authorization

**Q: "What are the mechanisms for an agent to prove its authority to perform a specific action?"**

RCPT delegation receipts encode authority as verifiable attestations:

1. A human (or authorizing agent) generates a delegation receipt specifying scope, expiry, and the delegatee agent's DID.
2. The delegatee references this delegation receipt in subsequent action receipts.
3. Any verifier can check: (a) the delegation receipt's signature is valid, (b) the scope covers the action taken, (c) the delegation had not expired.

This mechanism is complementary to OAuth 2.0 — OAuth tokens authorize access at the protocol level, while RCPT delegation receipts provide a non-repudiable attestation of the authorization decision.

**Q: "How might an agent convey the intent of its actions?"**

RCPT receipts capture intent through:

- **input_hash:** SHA-256 hash of the original instruction/prompt
- **parameters_hash:** SHA-256 hash of model configuration
- **metadata.description:** Human-readable action description
- **chain.parent_receipt_id:** Links to the receipt that triggered this action

An auditor can compare the input hash against a known instruction to verify the agent was given a specific directive. The chain of parent receipts traces the full decision path from intent to execution.

### Section 1: General Questions

**Q: "What support are you seeing for new protocols such as Model Context Protocol (MCP)?"**

RCPT ships as an MCP Server, making it a native tool for any MCP-compatible agent. This means:

- Any agent using MCP can generate RCPT receipts without SDK changes
- Receipt generation can be configured as automatic for every MCP tool call
- Receipt verification is available as an MCP tool (agents can verify other agents' receipts before transacting)

MCP provides the **connectivity** layer (how agents access tools and data). RCPT provides the **trust** layer (proof that an agent performed a specific action). Together, they create a complete framework for trusted agent operations.

**Q: "What standards exist, or are emerging, to support identity and access management of agents?"**

Based on our landscape analysis, the following approaches exist but each addresses only a subset of the challenge:

| Standard/Project | Covers | Gap |
|---|---|---|
| OAuth 2.0/OIDC | Authorization, authentication | No non-repudiation or audit trail |
| SPIFFE/SPIRE | Workload identity | No action-level attestation |
| SCIM | Identity lifecycle management | No cryptographic proof of actions |
| C2PA | Content provenance for media | Not applicable to agent actions |
| SCITT (IETF) | Supply chain transparency logs | Pre-AI; no agent identity model |

RCPT is designed to operate alongside these standards, adding the missing non-repudiation and audit layer.

---

## Alignment with NCCoE Standards Under Consideration

| NCCoE Standard | RCPT Alignment |
|---|---|
| **MCP** | RCPT available as MCP Server; native integration for any MCP-compatible agent |
| **OAuth 2.0/2.1** | Complementary — OAuth authorizes; RCPT attests. Delegation receipts can reference OAuth token IDs |
| **OIDC** | Agent DIDs interoperable with OIDC claims; can be included in ID tokens |
| **SPIFFE/SPIRE** | `did:key` maps to SPIFFE IDs; receipt generation can be gated by SPIRE attestation |
| **SCIM** | Agent lifecycle events can generate RCPT receipts, creating auditable identity lifecycle |
| **NGAC** | Authorization policy decisions can be attested via receipts; receipts encode the policy context |
| **SP 800-207** | Every action verified (explicit verification); delegation scopes (least privilege); immutable chains (assume breach) |
| **SP 800-63-4** | RCPT extends digital identity to non-human entities with equivalent cryptographic strength |

---

## Proposed Demonstration

We propose a demonstration scenario aligned with the NCCoE's enterprise AI agent use case (Use Case #1):

**Scenario: Enterprise Multi-Agent Workflow with Full Receipt Provenance**

1. A human user authorizes an AI agent team via OAuth + RCPT delegation receipt
2. **Research Agent** retrieves data from internal systems via MCP (each tool call generates an RCPT receipt)
3. **Analysis Agent** processes the data and generates recommendations (inference receipts chained to research receipts)
4. **Action Agent** executes approved recommendations — sends emails, updates CRM (transaction receipts chained to analysis)
5. An auditor queries the receipt chain and reconstructs: who authorized what, which agent did what, when, and whether each action fell within delegated scope

This demonstrates: identification (DID), authentication (Ed25519 signatures), authorization (delegation receipts with scope), access delegation (human-to-agent binding), logging and transparency (complete receipt chain), and data flow tracking (input/output hashes).

We are prepared to implement this demonstration using commercially available technology in collaboration with the NCCoE.

---

## Open Source Commitment

RCPT is fully open:

- **Specification:** Apache 2.0 licensed, publicly available
- **JSON Schema:** Machine-readable receipt validation
- **SDKs:** Python and TypeScript, zero external dependencies, 194+ tests passing
- **MCP Server:** 8 tools for receipt generation, verification, chaining, and Merkle anchoring
- **Framework integrations:** LangChain callback handler, CrewAI plugin
- **Solana anchor program:** On-chain Merkle root anchoring with proof verification
- **EU AI Act compliance dashboard:** Automated gap analysis against Articles 12, 19, and 26
- **Reputation engine:** Agent scoring algorithm per spec Section 9
- **No vendor lock-in:** Any party can implement the spec independently
- **Governance:** Designed for community governance; potential future contribution to the Agentic AI Foundation (AAIF) alongside MCP

---

## Contact

[Name]
RCPT Protocol
[Email]
GitHub: github.com/rcpt-protocol/rcpt-protocol
Specification: github.com/rcpt-protocol/rcpt-protocol/tree/main/spec/v0.1
