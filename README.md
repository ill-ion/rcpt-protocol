# RCPT — Receipt Chain Protocol for Trust

[![CI](https://github.com/rcpt-protocol/rcpt-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/rcpt-protocol/rcpt-protocol/actions) [![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE) [![Python 3.9+](https://img.shields.io/badge/python-3.9+-green.svg)](https://pypi.org/project/rcpt/) [![Node 18+](https://img.shields.io/badge/node-18+-green.svg)](https://www.npmjs.com/package/rcpt) [![Tests](https://img.shields.io/badge/tests-281-brightgreen.svg)](#)

**Cryptographic proof-of-action for AI agents.**

RCPT is an open protocol that generates a signed, verifiable receipt every time an AI agent takes an action. Receipts are chained into workflows, anchored on-chain for trustless verification, and composable into agent identity, audit trails, and reputation scores.

Think of it as **SSL certificates for AI agents** — a universal trust layer that works across any model, any framework, and any chain.

---

## Why RCPT Exists

AI agents are entering production at scale. By 2028, 33% of enterprise software will include agentic AI (Gartner). Yet there is no universal way to verify:

- **What** an AI agent did
- **When** it did it
- **Who** authorized it
- **Whether** the output matches the intent

The EU AI Act (enforceable August 2, 2026) requires tamper-resistant audit logging for high-risk AI systems. NIST is actively seeking solutions for agent identity and authorization. Only 22% of organizations treat AI agents as independent identities.

**RCPT fills the gap between what's required and what exists.**

## How It Works

```
Agent Action → RCPT Receipt (signed) → Receipt Store → Merkle Root → Solana
```

Every action generates a lightweight JSON receipt containing:
- Agent identity (DID-based)
- Action type and output hash
- Timestamp and Ed25519 signature
- Optional: input hash, model info, parent receipt (for chaining)

Receipts are stored off-chain (private, fast, cheap) with Merkle roots anchored on Solana (trustless, permanent, verifiable).

## Quick Start

### Python
```bash
pip install rcpt
```

```python
from rcpt import RCPTClient, ActionType

client = RCPTClient(private_key="base64url:...")

receipt = client.attest(
    action_type=ActionType.INFERENCE,
    output=response_text,
    model="claude-sonnet-4-5"
)

assert client.verify(receipt)
```

### TypeScript
```bash
npm install rcpt
```

```typescript
import { RCPTClient, ActionType } from 'rcpt';

const client = new RCPTClient({ privateKey: '...' });

const receipt = await client.attest({
  actionType: ActionType.TOOL_CALL,
  output: apiResponse,
});

const { valid } = await client.verify(receipt);
```

## What RCPT Solves

| Problem | Solution |
|---------|----------|
| **Agent Identity** | An agent's receipt chain IS its identity. No centralized registry needed. |
| **Output Verification** | Cryptographic binding of output to agent, model, and timestamp. |
| **Audit Trails** | Receipt chains reconstruct the full history of any workflow. |
| **Intent Verification** | Input hash + output hash = auditable comparison of intent vs. result. |
| **EU AI Act Compliance** | Direct mapping to Articles 12, 19, and 26 logging requirements. |
| **Agent Reputation** | Computed from receipt history — volume, consistency, dispute rate. |

## Design Principles

1. **Minimal** — 7 required fields. Everything else is optional.
2. **Private** — Hashes of data, never raw data. GDPR crypto-shredding compatible.
3. **Universal** — Framework-agnostic, model-agnostic, chain-agnostic.
4. **Fast** — Receipt generation <1ms. Anchoring is async and batched.
5. **Open** — Apache 2.0 licensed. No vendor lock-in. Anyone can implement.

## Integrations

- **LangChain / LangGraph** — Callback handler for automatic receipt generation
- **CrewAI** — Plugin for multi-agent receipt chaining
- **OpenAI SDK** — Drop-in `ReceiptedOpenAI` wrapper
- **Anthropic SDK** — Drop-in `ReceiptedAnthropic` wrapper
- **FastAPI** — Middleware with receipt headers and introspection API
- **MCP** — Server with 8 tools for any MCP-compatible agent

## CLI

```bash
pip install rcpt

rcpt keygen                          # Generate Ed25519 keypair
rcpt attest "Hello" --model gpt-4o   # Sign a receipt
rcpt verify receipt.json             # Verify signature
rcpt validate receipt.json           # Full spec validation
rcpt inspect receipt.json            # Pretty-print with verification
rcpt compliance receipts.json        # EU AI Act gap analysis
rcpt reputation receipts.json        # Compute agent reputation scores
rcpt merkle receipts.json            # Build Merkle tree, print root
rcpt hash "content"                  # SHA-256 hash
```
- **MCP** — RCPT as an MCP Server (native tool for any MCP-compatible agent)

## Specification

The full protocol specification is at [`spec/v0.1/`](spec/v0.1/).

- [Receipt Schema](spec/v0.1/receipt-schema.json) — JSON Schema for receipt validation
- [Protocol Specification](spec/v0.1/SPECIFICATION.md) — Complete technical specification
- [Examples](spec/v0.1/examples/) — Sample receipts and receipt chains

## Project Structure

```
rcpt-protocol/
├── spec/v0.1/           # Protocol specification and JSON Schema
├── sdk/python/          # Python SDK + CLI
├── sdk/typescript/      # TypeScript SDK
├── anchor/              # Solana anchor program
├── explorer/            # Receipt explorer web UI
├── integrations/
│   ├── langchain/       # LangChain callback handler
│   ├── crewai/          # CrewAI plugin
│   ├── mcp/             # MCP Server
│   ├── openai/          # OpenAI SDK wrapper
│   ├── anthropic/       # Anthropic SDK wrapper
│   └── fastapi/         # FastAPI middleware
├── cli/                 # CLI source (also packaged in SDK)
├── site/                # Landing page (rcptprotocol.com)
├── nist-submission/     # NIST NCCoE comment letter
└── .github/workflows/   # CI pipeline
```

## Roadmap

- [x] Protocol specification v0.1
- [x] JSON Schema for receipt validation
- [x] Python SDK (core: generate, sign, verify)
- [x] TypeScript SDK
- [x] LangChain integration
- [x] CrewAI integration
- [x] MCP Server
- [x] Solana anchor program
- [x] Receipt explorer
- [x] Compliance dashboard
- [x] Reputation algorithm implementation

## Contributing

RCPT is an open standard. We welcome contributions of all kinds — spec improvements, SDK ports, framework integrations, documentation, and feedback.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Links

- Website: [rcptprotocol.com](https://rcptprotocol.com)
- GitHub: [github.com/rcpt-protocol](https://github.com/rcpt-protocol)
- Specification: [spec/v0.1/SPECIFICATION.md](spec/v0.1/SPECIFICATION.md)
