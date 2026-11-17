"""
RCPT Cross-Language Interop Test

Proves that receipts signed by the Python SDK can be verified by the TypeScript SDK,
and vice versa. This is the most important test in the repo — it validates that
RCPT is a real interoperable protocol, not just two implementations that happen
to share a name.

Requires: Node.js 18+ available on PATH

Run:
    cd sdk/python && python tests/test_interop.py
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

# Ensure we can import rcpt from the local SDK
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rcpt import RCPTClient, ActionType, Receipt
from rcpt.hashing import hash_content, canonical_serialize


TS_SDK_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "typescript")
TS_DIST = os.path.join(TS_SDK_DIR, "dist")


def node_available() -> bool:
    try:
        r = subprocess.run(["node", "--version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def ts_dist_available() -> bool:
    return os.path.isfile(os.path.join(TS_DIST, "index.js"))


@unittest.skipUnless(node_available(), "Node.js not available")
@unittest.skipUnless(ts_dist_available(), "TypeScript SDK not built (run tsc first)")
class TestCrossLanguageInterop(unittest.TestCase):
    """Cross-language receipt verification."""

    def _run_node(self, script: str) -> str:
        """Run a Node.js script and return stdout."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mjs", delete=False) as f:
            f.write(script)
            f.flush()
            try:
                result = subprocess.run(
                    ["node", f.name],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode != 0:
                    self.fail(f"Node.js script failed:\n{result.stderr}")
                return result.stdout.strip()
            finally:
                os.unlink(f.name)

    def test_python_sign_typescript_verify(self):
        """Python generates a receipt → TypeScript verifies it."""
        client = RCPTClient()
        receipt = client.attest(
            action_type=ActionType.INFERENCE,
            output="Hello from Python",
            model="claude-sonnet-4-5",
        )

        # Sanity check: Python can verify its own receipt
        self.assertTrue(client.verify(receipt))

        receipt_json = receipt.to_json()

        script = f"""
import {{ verifyReceipt, Receipt }} from "{TS_DIST}/index.js";
const receipt = Receipt.fromJSON({json.dumps(receipt_json)});
const valid = verifyReceipt(receipt);
console.log(JSON.stringify({{ valid, receipt_id: receipt.receipt_id }}));
"""
        output = self._run_node(script)
        result = json.loads(output)
        self.assertTrue(result["valid"], "TypeScript failed to verify Python-signed receipt")
        self.assertEqual(result["receipt_id"], receipt.receipt_id)

    def test_typescript_sign_python_verify(self):
        """TypeScript generates a receipt → Python verifies it."""
        script = f"""
import {{ RCPTClient, ActionType }} from "{TS_DIST}/index.js";
const client = new RCPTClient();
const receipt = client.attest({{
  actionType: ActionType.INFERENCE,
  output: "Hello from TypeScript",
  model: "claude-sonnet-4-5",
}});
console.log(receipt.toJSON());
"""
        output = self._run_node(script)
        receipt = Receipt.from_json(output)

        # Python verifies TypeScript-signed receipt
        client = RCPTClient()  # Different client, doesn't matter — verification uses the DID
        self.assertTrue(client.verify(receipt), "Python failed to verify TypeScript-signed receipt")

    def test_hash_interop(self):
        """Same input produces same hash in both languages."""
        test_string = "The quick brown fox jumps over the lazy dog"
        python_hash = hash_content(test_string)

        script = f"""
import {{ hashContent }} from "{TS_DIST}/index.js";
console.log(hashContent("{test_string}"));
"""
        ts_hash = self._run_node(script)
        self.assertEqual(python_hash, ts_hash, "Hash mismatch between Python and TypeScript")

    def test_jcs_interop(self):
        """Same object produces same canonical bytes in both languages."""
        test_obj = {"z_last": 1, "a_first": "hello", "m_middle": True}
        python_canonical = canonical_serialize(test_obj).decode("utf-8")

        script = f"""
import {{ canonicalSerialize }} from "{TS_DIST}/index.js";
const obj = {json.dumps(test_obj)};
const buf = canonicalSerialize(obj);
console.log(buf.toString("utf-8"));
"""
        ts_canonical = self._run_node(script)
        self.assertEqual(python_canonical, ts_canonical, "JCS canonical form mismatch")

    def test_chained_receipt_cross_verify(self):
        """Python creates a chain → TypeScript verifies each receipt in the chain."""
        client = RCPTClient()
        r1 = client.attest(action_type=ActionType.INFERENCE, output="Step 1")
        r2 = client.attest(action_type=ActionType.TOOL_CALL, output="Step 2", parent=r1.receipt_id)
        r3 = client.attest(action_type=ActionType.INFERENCE, output="Step 3", parent=r2.receipt_id)

        for receipt in [r1, r2, r3]:
            receipt_json = receipt.to_json()
            script = f"""
import {{ verifyReceipt, Receipt }} from "{TS_DIST}/index.js";
const r = Receipt.fromJSON({json.dumps(receipt_json)});
console.log(JSON.stringify({{ valid: verifyReceipt(r), id: r.receipt_id }}));
"""
            output = self._run_node(script)
            result = json.loads(output)
            self.assertTrue(
                result["valid"],
                f"TypeScript failed to verify chained receipt {receipt.receipt_id}"
            )

    # ── Regression tests: canonical-form edge cases (found 2026-11-17) ──────

    def _ts_verify(self, receipt_json: str) -> bool:
        script = f"""
import {{ verifyReceipt, Receipt }} from "{TS_DIST}/index.js";
console.log(JSON.stringify(verifyReceipt(Receipt.fromJSON({json.dumps(receipt_json)}))));
"""
        return json.loads(self._run_node(script))

    def test_python_metadata_extra_typescript_verify(self):
        """Custom metadata keys (numbers, floats, nulls, nesting) survive TS verification."""
        cases = {
            "fractional float": {"confidence": 0.95},
            "integral float": {"score": 1.0},
            "small float": {"latency_s": 2.5e-07},
            "large float": {"tokens": 1e16},
            "null value": {"note": None},
            "nested": {"ctx": {"b": [1, 2.0, None], "a": True}},
        }
        client = RCPTClient()
        for name, extra in cases.items():
            with self.subTest(name):
                r = client.attest(
                    action_type=ActionType.INFERENCE, output="x",
                    metadata={"description": "t", **extra},
                )
                self.assertTrue(client.verify(r))
                self.assertTrue(self._ts_verify(r.to_json()), f"TS rejected Python receipt ({name})")

    def test_typescript_metadata_python_verify(self):
        """TS receipts with empty lists and custom metadata verify in Python."""
        script = f"""
import {{ RCPTClient, ActionType }} from "{TS_DIST}/index.js";
const c = new RCPTClient();
const r = c.attest({{ actionType: ActionType.INFERENCE, output: "x",
  metadata: {{ description: "t", tags: [], compliance: [], score: 1, note: null, ratio: 0.5 }} }});
console.log(r.toJSON());
"""
        receipt = Receipt.from_json(self._run_node(script))
        self.assertTrue(RCPTClient().verify(receipt), "Python rejected TS receipt with empty lists/extra metadata")

    def test_jcs_number_and_null_interop(self):
        """Python and TS produce byte-identical JCS for numbers, nulls and non-ASCII keys."""
        obj = {"f1": 1.0, "f2": 0.95, "f3": 1e-7, "f4": 1e16, "f5": 1e21, "f6": -0.0,
               "f7": 123.456, "n": None, "é": 1, "\U0001F600": 2, "ﬁ": 3}
        python_canonical = canonical_serialize(obj).decode("utf-8")
        script = f"""
import {{ canonicalSerialize }} from "{TS_DIST}/index.js";
console.log(canonicalSerialize(JSON.parse({json.dumps(json.dumps(obj))})).toString("utf-8"));
"""
        self.assertEqual(python_canonical, self._run_node(script))


if __name__ == "__main__":
    unittest.main()
