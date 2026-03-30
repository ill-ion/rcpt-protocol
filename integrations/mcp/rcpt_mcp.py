"""
RCPT MCP Server

Exposes RCPT receipt generation and verification as MCP (Model Context Protocol) tools.
Any MCP-compatible agent can generate, verify, chain, and query RCPT receipts.

Usage:
    # Run as MCP server (stdio transport)
    python -m rcpt_mcp

    # Or programmatically
    from rcpt_mcp import serve
    serve()

MCP Configuration (claude_desktop_config.json):
    {
      "mcpServers": {
        "rcpt": {
          "command": "python",
          "args": ["-m", "rcpt_mcp"]
        }
      }
    }
"""

from __future__ import annotations

import json
import sys
import hashlib
from typing import Any, Dict, List, Optional

from rcpt import RCPTClient, ActionType, Receipt
from rcpt.hashing import (
    hash_content,
    hash_receipt_canonical,
    build_merkle_tree,
    get_merkle_proof,
    verify_merkle_proof,
)


# ── MCP Protocol Implementation (stdio) ────────────────────────────────────
# Implements JSON-RPC 2.0 over stdio per MCP specification.

class RCPTMCPServer:
    """RCPT MCP Server exposing receipt operations as tools."""

    SERVER_INFO = {
        "name": "rcpt",
        "version": "0.1.0",
    }

    CAPABILITIES = {
        "tools": {},
    }

    TOOLS = [
        {
            "name": "rcpt_attest",
            "description": (
                "Generate a signed RCPT receipt for an agent action. "
                "Creates a cryptographic proof-of-action with Ed25519 signature, "
                "SHA-256 output hash, and DID-based agent identity. "
                "Use this to create an auditable, tamper-evident record of any action."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action_type": {
                        "type": "string",
                        "enum": ["inference", "tool_call", "transaction", "delegation", "observation", "custom"],
                        "description": "Category of the action being attested.",
                    },
                    "output": {
                        "type": "string",
                        "description": "The action output (will be hashed, not stored in the receipt).",
                    },
                    "input_data": {
                        "type": "string",
                        "description": "Optional input/prompt that triggered this action (will be hashed).",
                    },
                    "model": {
                        "type": "string",
                        "description": "Model identifier, e.g. 'claude-sonnet-4-5' or 'openai/gpt-4o'.",
                    },
                    "parent_receipt_id": {
                        "type": "string",
                        "description": "Receipt ID of the parent action for chaining.",
                    },
                    "workflow_id": {
                        "type": "string",
                        "description": "Workflow ID to group related receipts.",
                    },
                    "description": {
                        "type": "string",
                        "description": "Human-readable description of the action.",
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Tags for categorizing this receipt.",
                    },
                },
                "required": ["action_type", "output"],
            },
        },
        {
            "name": "rcpt_verify",
            "description": (
                "Verify the cryptographic signature of an RCPT receipt. "
                "Returns whether the receipt is authentic and untampered. "
                "Use this before trusting another agent's receipt."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "receipt_json": {
                        "type": "string",
                        "description": "The receipt as a JSON string.",
                    },
                },
                "required": ["receipt_json"],
            },
        },
        {
            "name": "rcpt_get_receipt",
            "description": (
                "Retrieve a previously generated receipt by its ID."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "receipt_id": {
                        "type": "string",
                        "description": "The ULID of the receipt to retrieve.",
                    },
                },
                "required": ["receipt_id"],
            },
        },
        {
            "name": "rcpt_get_chain",
            "description": (
                "Get the full receipt chain leading to a given receipt. "
                "Walks parent references backward to the root, reconstructing "
                "the complete audit trail for a workflow."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "receipt_id": {
                        "type": "string",
                        "description": "The receipt ID to trace back from.",
                    },
                },
                "required": ["receipt_id"],
            },
        },
        {
            "name": "rcpt_hash",
            "description": (
                "Compute the SHA-256 hash of content using RCPT's hashing scheme. "
                "Useful for verifying that an output matches a receipt's output_hash."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "The content to hash.",
                    },
                },
                "required": ["content"],
            },
        },
        {
            "name": "rcpt_merkle_anchor",
            "description": (
                "Build a Merkle tree from a batch of receipts and return the root hash. "
                "The root can be anchored on-chain for trustless verification."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "receipt_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of receipt IDs to include in the Merkle tree.",
                    },
                },
                "required": ["receipt_ids"],
            },
        },
        {
            "name": "rcpt_export",
            "description": (
                "Export all receipts for compliance or analysis. "
                "Supports JSON and EU AI Act compliance format."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "format": {
                        "type": "string",
                        "enum": ["json", "eu-ai-act"],
                        "description": "Export format.",
                        "default": "json",
                    },
                },
            },
        },
        {
            "name": "rcpt_agent_info",
            "description": (
                "Get the current agent's identity information (DID and public key)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {},
            },
        },
    ]

    def __init__(self, client: Optional[RCPTClient] = None):
        self.client = client or RCPTClient(store="memory")

    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a JSON-RPC 2.0 request."""
        method = request.get("method", "")
        params = request.get("params", {})
        req_id = request.get("id")

        try:
            if method == "initialize":
                result = self._handle_initialize(params)
            elif method == "tools/list":
                result = self._handle_tools_list()
            elif method == "tools/call":
                result = self._handle_tool_call(params)
            elif method == "notifications/initialized":
                return None  # No response for notifications
            elif method == "ping":
                result = {}
            else:
                return self._error_response(req_id, -32601, f"Method not found: {method}")

            if result is None and req_id is None:
                return None  # Notification, no response needed

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result,
            }

        except Exception as e:
            return self._error_response(req_id, -32603, str(e))

    def _handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": self.CAPABILITIES,
            "serverInfo": self.SERVER_INFO,
        }

    def _handle_tools_list(self) -> Dict[str, Any]:
        return {"tools": self.TOOLS}

    def _handle_tool_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        handler_map = {
            "rcpt_attest": self._tool_attest,
            "rcpt_verify": self._tool_verify,
            "rcpt_get_receipt": self._tool_get_receipt,
            "rcpt_get_chain": self._tool_get_chain,
            "rcpt_hash": self._tool_hash,
            "rcpt_merkle_anchor": self._tool_merkle_anchor,
            "rcpt_export": self._tool_export,
            "rcpt_agent_info": self._tool_agent_info,
        }

        handler = handler_map.get(tool_name)
        if not handler:
            return {
                "content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}],
                "isError": True,
            }

        try:
            result = handler(arguments)
            return {
                "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
            }
        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Error: {str(e)}"}],
                "isError": True,
            }

    # ── Tool Implementations ────────────────────────────────────────────────

    def _tool_attest(self, args: Dict[str, Any]) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {
            "action_type": args["action_type"],
            "output": args["output"],
        }

        if "input_data" in args:
            kwargs["input_data"] = args["input_data"]
        if "model" in args:
            kwargs["model"] = args["model"]
        if "parent_receipt_id" in args:
            kwargs["parent"] = args["parent_receipt_id"]
        if "workflow_id" in args:
            kwargs["workflow_id"] = args["workflow_id"]

        metadata = {}
        if "description" in args:
            metadata["description"] = args["description"]
        if "tags" in args:
            metadata["tags"] = args["tags"]
        if metadata:
            kwargs["metadata"] = metadata

        receipt = self.client.attest(**kwargs)

        return {
            "receipt": receipt.to_dict(),
            "receipt_id": receipt.receipt_id,
            "verified": self.client.verify(receipt),
        }

    def _tool_verify(self, args: Dict[str, Any]) -> Dict[str, Any]:
        receipt_json = args["receipt_json"]
        try:
            receipt = Receipt.from_json(receipt_json)
            valid = self.client.verify(receipt)
            result = {
                "valid": valid,
                "receipt_id": receipt.receipt_id,
                "agent_id": receipt.agent_id,
                "action_type": receipt.action_type,
                "timestamp": receipt.timestamp,
            }
            if not valid:
                result["reason"] = "Signature verification failed — receipt may have been tampered with."
            return result
        except Exception as e:
            return {"valid": False, "reason": f"Invalid receipt format: {str(e)}"}

    def _tool_get_receipt(self, args: Dict[str, Any]) -> Dict[str, Any]:
        receipt = self.client.get_receipt(args["receipt_id"])
        if receipt is None:
            return {"found": False, "receipt_id": args["receipt_id"]}
        return {"found": True, "receipt": receipt.to_dict()}

    def _tool_get_chain(self, args: Dict[str, Any]) -> Dict[str, Any]:
        chain = self.client.get_chain(args["receipt_id"])
        return {
            "chain_length": len(chain),
            "receipts": [r.to_dict() for r in chain],
        }

    def _tool_hash(self, args: Dict[str, Any]) -> Dict[str, Any]:
        h = hash_content(args["content"])
        return {"hash": h, "algorithm": "sha256", "content_length": len(args["content"])}

    def _tool_merkle_anchor(self, args: Dict[str, Any]) -> Dict[str, Any]:
        receipt_ids = args["receipt_ids"]
        hashes = []
        for rid in receipt_ids:
            receipt = self.client.get_receipt(rid)
            if receipt is None:
                return {"error": f"Receipt not found: {rid}"}
            hashes.append(hash_receipt_canonical(receipt.to_dict()))

        root, levels = build_merkle_tree(hashes)

        # Generate proofs for each receipt
        proofs = {}
        for i, rid in enumerate(receipt_ids):
            proof = get_merkle_proof(hashes, hashes[i] if i < len(hashes) else hashes[0])
            proofs[rid] = proof

        return {
            "merkle_root": root,
            "receipt_count": len(receipt_ids),
            "tree_depth": len(levels),
            "proofs": proofs,
        }

    def _tool_export(self, args: Dict[str, Any]) -> Dict[str, Any]:
        fmt = args.get("format", "json")
        exported = self.client.export(format=fmt)
        return json.loads(exported) if fmt == "json" else json.loads(exported)

    def _tool_agent_info(self, args: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "agent_id": self.client.agent_id,
            "public_key": self.client.public_key,
            "receipt_count": len(self.client._memory_store),
        }

    # ── Helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _error_response(req_id: Any, code: int, message: str) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        }


# ── stdio Transport ─────────────────────────────────────────────────────────

def serve(client: Optional[RCPTClient] = None) -> None:
    """
    Run the RCPT MCP server over stdio.

    Reads JSON-RPC messages from stdin, processes them, and writes responses to stdout.
    Each message is delimited by Content-Length headers per the LSP/MCP protocol.
    """
    server = RCPTMCPServer(client)

    while True:
        try:
            # Read Content-Length header
            header = ""
            while True:
                line = sys.stdin.readline()
                if not line:
                    return  # EOF
                header += line
                if line.strip() == "":
                    break

            # Parse content length
            content_length = 0
            for h_line in header.split("\n"):
                if h_line.lower().startswith("content-length:"):
                    content_length = int(h_line.split(":")[1].strip())

            if content_length == 0:
                continue

            # Read body
            body = sys.stdin.read(content_length)
            request = json.loads(body)

            # Handle
            response = server.handle_request(request)

            if response is not None:
                response_bytes = json.dumps(response).encode("utf-8")
                sys.stdout.write(f"Content-Length: {len(response_bytes)}\r\n\r\n")
                sys.stdout.write(response_bytes.decode("utf-8"))
                sys.stdout.flush()

        except json.JSONDecodeError:
            continue
        except KeyboardInterrupt:
            break
        except Exception:
            continue


if __name__ == "__main__":
    serve()
