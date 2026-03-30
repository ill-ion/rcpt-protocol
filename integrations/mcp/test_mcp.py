"""
RCPT MCP Server — Test Suite

Tests the MCP server's JSON-RPC handling and tool implementations directly.
No network required — tests the server object programmatically.
"""

import json
import sys
import os
import unittest

# Add parent to path so we can import
sys.path.insert(0, os.path.dirname(__file__))
# Add the SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python"))

from rcpt import RCPTClient, ActionType
from rcpt_mcp import RCPTMCPServer


class TestMCPInitialize(unittest.TestCase):
    def test_initialize(self):
        server = RCPTMCPServer()
        resp = server.handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "test", "version": "1.0"},
            },
        })
        self.assertEqual(resp["id"], 1)
        result = resp["result"]
        self.assertEqual(result["protocolVersion"], "2024-11-05")
        self.assertIn("tools", result["capabilities"])
        self.assertEqual(result["serverInfo"]["name"], "rcpt")

    def test_tools_list(self):
        server = RCPTMCPServer()
        resp = server.handle_request({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        })
        tools = resp["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        self.assertIn("rcpt_attest", tool_names)
        self.assertIn("rcpt_verify", tool_names)
        self.assertIn("rcpt_get_receipt", tool_names)
        self.assertIn("rcpt_get_chain", tool_names)
        self.assertIn("rcpt_hash", tool_names)
        self.assertIn("rcpt_merkle_anchor", tool_names)
        self.assertIn("rcpt_export", tool_names)
        self.assertIn("rcpt_agent_info", tool_names)

    def test_notification_returns_none(self):
        server = RCPTMCPServer()
        resp = server.handle_request({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        })
        self.assertIsNone(resp)

    def test_unknown_method(self):
        server = RCPTMCPServer()
        resp = server.handle_request({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "nonexistent/method",
            "params": {},
        })
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32601)


class TestMCPAttest(unittest.TestCase):
    def setUp(self):
        self.server = RCPTMCPServer()

    def _call_tool(self, name, arguments):
        resp = self.server.handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        })
        content = resp["result"]["content"][0]["text"]
        return json.loads(content)

    def test_basic_attest(self):
        result = self._call_tool("rcpt_attest", {
            "action_type": "inference",
            "output": "Hello world",
        })
        self.assertIn("receipt", result)
        self.assertIn("receipt_id", result)
        self.assertTrue(result["verified"])
        receipt = result["receipt"]
        self.assertEqual(receipt["action_type"], "inference")
        self.assertEqual(receipt["rcpt_version"], "0.1")

    def test_attest_with_model(self):
        result = self._call_tool("rcpt_attest", {
            "action_type": "inference",
            "output": "Paris is the capital of France.",
            "model": "claude-sonnet-4-5",
        })
        receipt = result["receipt"]
        self.assertEqual(receipt["model"]["provider"], "anthropic")
        self.assertEqual(receipt["model"]["model_id"], "claude-sonnet-4-5")

    def test_attest_with_chaining(self):
        r1 = self._call_tool("rcpt_attest", {
            "action_type": "inference",
            "output": "Step 1",
        })
        r2 = self._call_tool("rcpt_attest", {
            "action_type": "tool_call",
            "output": "Step 2",
            "parent_receipt_id": r1["receipt_id"],
        })
        self.assertIn("chain", r2["receipt"])
        self.assertEqual(r2["receipt"]["chain"]["parent_receipt_id"], r1["receipt_id"])

    def test_attest_with_metadata(self):
        result = self._call_tool("rcpt_attest", {
            "action_type": "tool_call",
            "output": "API response",
            "description": "Called weather API",
            "tags": ["weather", "api"],
        })
        receipt = result["receipt"]
        self.assertIn("metadata", receipt)
        self.assertEqual(receipt["metadata"]["tags"], ["weather", "api"])

    def test_attest_all_action_types(self):
        for at in ["inference", "tool_call", "transaction", "delegation", "observation", "custom"]:
            result = self._call_tool("rcpt_attest", {
                "action_type": at,
                "output": f"Output for {at}",
            })
            self.assertEqual(result["receipt"]["action_type"], at)
            self.assertTrue(result["verified"])


class TestMCPVerify(unittest.TestCase):
    def setUp(self):
        self.server = RCPTMCPServer()

    def _call_tool(self, name, arguments):
        resp = self.server.handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        })
        content = resp["result"]["content"][0]["text"]
        return json.loads(content)

    def test_verify_valid(self):
        attest_result = self._call_tool("rcpt_attest", {
            "action_type": "inference",
            "output": "Hello",
        })
        receipt_json = json.dumps(attest_result["receipt"])
        verify_result = self._call_tool("rcpt_verify", {"receipt_json": receipt_json})
        self.assertTrue(verify_result["valid"])

    def test_verify_tampered(self):
        attest_result = self._call_tool("rcpt_attest", {
            "action_type": "inference",
            "output": "Hello",
        })
        receipt = attest_result["receipt"]
        receipt["output_hash"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        verify_result = self._call_tool("rcpt_verify", {"receipt_json": json.dumps(receipt)})
        self.assertFalse(verify_result["valid"])

    def test_verify_invalid_json(self):
        verify_result = self._call_tool("rcpt_verify", {"receipt_json": "not json"})
        self.assertFalse(verify_result["valid"])


class TestMCPReceiptOps(unittest.TestCase):
    def setUp(self):
        self.server = RCPTMCPServer()

    def _call_tool(self, name, arguments):
        resp = self.server.handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        })
        content = resp["result"]["content"][0]["text"]
        return json.loads(content)

    def test_get_receipt(self):
        attest = self._call_tool("rcpt_attest", {"action_type": "inference", "output": "test"})
        get = self._call_tool("rcpt_get_receipt", {"receipt_id": attest["receipt_id"]})
        self.assertTrue(get["found"])
        self.assertEqual(get["receipt"]["receipt_id"], attest["receipt_id"])

    def test_get_receipt_not_found(self):
        get = self._call_tool("rcpt_get_receipt", {"receipt_id": "nonexistent"})
        self.assertFalse(get["found"])

    def test_get_chain(self):
        r1 = self._call_tool("rcpt_attest", {"action_type": "inference", "output": "Step 1"})
        r2 = self._call_tool("rcpt_attest", {
            "action_type": "tool_call",
            "output": "Step 2",
            "parent_receipt_id": r1["receipt_id"],
        })
        r3 = self._call_tool("rcpt_attest", {
            "action_type": "inference",
            "output": "Step 3",
            "parent_receipt_id": r2["receipt_id"],
        })
        chain = self._call_tool("rcpt_get_chain", {"receipt_id": r3["receipt_id"]})
        self.assertEqual(chain["chain_length"], 3)

    def test_hash(self):
        result = self._call_tool("rcpt_hash", {"content": "Hello world"})
        self.assertTrue(result["hash"].startswith("sha256:"))
        self.assertEqual(result["algorithm"], "sha256")

    def test_agent_info(self):
        info = self._call_tool("rcpt_agent_info", {})
        self.assertTrue(info["agent_id"].startswith("did:key:z"))
        self.assertIsInstance(info["public_key"], str)

    def test_export_json(self):
        self._call_tool("rcpt_attest", {"action_type": "inference", "output": "test1"})
        self._call_tool("rcpt_attest", {"action_type": "tool_call", "output": "test2"})
        exported = self._call_tool("rcpt_export", {"format": "json"})
        self.assertIsInstance(exported, list)
        self.assertEqual(len(exported), 2)

    def test_merkle_anchor(self):
        ids = []
        for i in range(4):
            r = self._call_tool("rcpt_attest", {"action_type": "inference", "output": f"item-{i}"})
            ids.append(r["receipt_id"])
        result = self._call_tool("rcpt_merkle_anchor", {"receipt_ids": ids})
        self.assertTrue(result["merkle_root"].startswith("sha256:"))
        self.assertEqual(result["receipt_count"], 4)
        self.assertIn("proofs", result)


if __name__ == "__main__":
    unittest.main()
