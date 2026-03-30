# RCPT MCP Server

RCPT as a Model Context Protocol (MCP) server. Any MCP-compatible agent can generate, verify, and query cryptographic receipts.

## Install

```bash
pip install rcpt
```

## Configure

Add to your MCP client configuration (e.g., `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "rcpt": {
      "command": "python",
      "args": ["-m", "rcpt_mcp"]
    }
  }
}
```

## Tools

| Tool | Description |
|---|---|
| `rcpt_attest` | Generate a signed receipt for any action |
| `rcpt_verify` | Verify a receipt's cryptographic signature |
| `rcpt_get_receipt` | Retrieve a receipt by ID |
| `rcpt_get_chain` | Get the full receipt chain for an action |
| `rcpt_hash` | Compute SHA-256 hash of content |
| `rcpt_merkle_anchor` | Build a Merkle tree from receipts for on-chain anchoring |
| `rcpt_export` | Export receipts (JSON or EU AI Act format) |
| `rcpt_agent_info` | Get agent identity (DID, public key) |

## Example

Once configured, an MCP-compatible agent can use RCPT tools directly:

```
Agent: I'll generate a receipt for this API call.
→ rcpt_attest(action_type="tool_call", output="API response data...", model="claude-sonnet-4-5")

Agent: Let me verify that receipt from the other agent.
→ rcpt_verify(receipt_json='{"rcpt_version":"0.1",...}')

Agent: I need to see the full audit trail.
→ rcpt_get_chain(receipt_id="01KHZ08YF0S8EN8F5WB8QQ5FMK")
```

## Programmatic Usage

```python
from rcpt import RCPTClient
from rcpt_mcp import RCPTMCPServer

client = RCPTClient()
server = RCPTMCPServer(client)

# Simulate a tool call
response = server.handle_request({
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "rcpt_attest",
        "arguments": {
            "action_type": "inference",
            "output": "The capital of France is Paris.",
            "model": "claude-sonnet-4-5"
        }
    }
})
print(response)
```

## License

Apache 2.0
