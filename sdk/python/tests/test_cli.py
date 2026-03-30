"""
RCPT CLI — Test Suite

Tests all CLI commands via subprocess to simulate real usage.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

SDK_DIR = os.path.join(os.path.dirname(__file__), "..")
CLI_ENV = {**os.environ, "PYTHONPATH": SDK_DIR}


def run_cli(*args, stdin_data=None):
    """Run the RCPT CLI and return (returncode, stdout, stderr)."""
    cmd = [sys.executable, "-m", "rcpt.cli"] + list(args)
    result = subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=SDK_DIR, env=CLI_ENV,
        input=stdin_data, timeout=10,
    )
    return result.returncode, result.stdout, result.stderr


class TestCLIKeygen(unittest.TestCase):
    def test_keygen_json(self):
        rc, out, _ = run_cli("keygen", "--json")
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertIn("agent_id", data)
        self.assertIn("public_key", data)
        self.assertIn("private_key", data)
        self.assertTrue(data["agent_id"].startswith("did:key:z"))

    def test_keygen_text(self):
        rc, out, _ = run_cli("keygen")
        self.assertEqual(rc, 0)
        self.assertIn("Agent ID:", out)
        self.assertIn("did:key:z", out)


class TestCLIHash(unittest.TestCase):
    def test_hash_text(self):
        rc, out, _ = run_cli("hash", "Hello world")
        self.assertEqual(rc, 0)
        self.assertTrue(out.strip().startswith("sha256:"))
        self.assertEqual(len(out.strip()), 71)

    def test_hash_deterministic(self):
        _, out1, _ = run_cli("hash", "test")
        _, out2, _ = run_cli("hash", "test")
        self.assertEqual(out1, out2)

    def test_hash_stdin(self):
        rc, out, _ = run_cli("hash", "-", stdin_data="Hello world")
        self.assertEqual(rc, 0)
        self.assertTrue(out.strip().startswith("sha256:"))


class TestCLIAttest(unittest.TestCase):
    def test_attest_basic(self):
        rc, out, _ = run_cli("attest", "Hello world")
        self.assertEqual(rc, 0)
        receipt = json.loads(out)
        self.assertEqual(receipt["rcpt_version"], "0.1")
        self.assertEqual(receipt["action_type"], "inference")
        self.assertTrue(receipt["signature"].startswith("ed25519:"))

    def test_attest_with_model(self):
        rc, out, _ = run_cli("attest", "Response text", "--model", "claude-sonnet-4-5")
        self.assertEqual(rc, 0)
        receipt = json.loads(out)
        self.assertEqual(receipt["model"]["provider"], "anthropic")

    def test_attest_with_type(self):
        rc, out, _ = run_cli("attest", "API response", "--type", "tool_call")
        self.assertEqual(rc, 0)
        receipt = json.loads(out)
        self.assertEqual(receipt["action_type"], "tool_call")

    def test_attest_with_key(self):
        # Generate a key, then use it
        _, keygen_out, _ = run_cli("keygen", "--json")
        key_data = json.loads(keygen_out)

        _, out, _ = run_cli("attest", "Signed with specific key", "--key", key_data["private_key"])
        receipt = json.loads(out)
        self.assertEqual(receipt["agent_id"], key_data["agent_id"])


class TestCLIVerify(unittest.TestCase):
    def _make_receipt_file(self):
        _, out, _ = run_cli("attest", "test output")
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        f.write(out)
        f.close()
        return f.name

    def test_verify_valid(self):
        path = self._make_receipt_file()
        try:
            rc, out, _ = run_cli("verify", path)
            self.assertEqual(rc, 0)
            self.assertIn("valid", out.lower())
        finally:
            os.unlink(path)

    def test_verify_tampered(self):
        _, out, _ = run_cli("attest", "original")
        receipt = json.loads(out)
        receipt["output_hash"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(receipt, f)
        f.close()
        try:
            rc, out, _ = run_cli("verify", f.name)
            self.assertEqual(rc, 1)
            self.assertIn("INVALID", out.upper())
        finally:
            os.unlink(f.name)

    def test_verify_array(self):
        receipts = []
        for i in range(3):
            _, out, _ = run_cli("attest", f"msg-{i}")
            receipts.append(json.loads(out))

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(receipts, f)
        f.close()
        try:
            rc, out, _ = run_cli("verify", f.name)
            self.assertEqual(rc, 0)
            self.assertIn("3/3", out)
        finally:
            os.unlink(f.name)


class TestCLIInspect(unittest.TestCase):
    def test_inspect(self):
        _, attest_out, _ = run_cli("attest", "inspect me", "--model", "gpt-4o")
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        f.write(attest_out)
        f.close()
        try:
            rc, out, _ = run_cli("inspect", f.name)
            self.assertEqual(rc, 0)
            self.assertIn("VERIFIED", out)
            self.assertIn("inference", out)
            self.assertIn("openai/gpt-4o", out)
        finally:
            os.unlink(f.name)


class TestCLIMerkle(unittest.TestCase):
    def test_merkle(self):
        receipts = []
        for i in range(4):
            _, out, _ = run_cli("attest", f"item-{i}")
            receipts.append(json.loads(out))

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(receipts, f)
        f.close()
        try:
            rc, out, _ = run_cli("merkle", f.name)
            self.assertEqual(rc, 0)
            self.assertIn("sha256:", out)
            self.assertIn("4 receipts", out)
        finally:
            os.unlink(f.name)


class TestCLICompliance(unittest.TestCase):
    def test_compliance_json(self):
        receipts = []
        for i in range(3):
            _, out, _ = run_cli("attest", f"msg-{i}", "--model", "claude-sonnet-4-5")
            receipts.append(json.loads(out))

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(receipts, f)
        f.close()
        try:
            rc, out, _ = run_cli("compliance", f.name, "--json")
            self.assertEqual(rc, 0)
            report = json.loads(out)
            self.assertIn("overall_score", report)
            self.assertIn("Article 12", report["article_scores"])
        finally:
            os.unlink(f.name)

    def test_compliance_pretty(self):
        receipts = []
        _, out, _ = run_cli("attest", "test")
        receipts.append(json.loads(out))

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(receipts, f)
        f.close()
        try:
            rc, out, _ = run_cli("compliance", f.name)
            self.assertEqual(rc, 0)
            self.assertIn("Article 12", out)
        finally:
            os.unlink(f.name)


class TestCLIReputation(unittest.TestCase):
    def test_reputation_json(self):
        receipts = []
        for i in range(5):
            _, out, _ = run_cli("attest", f"msg-{i}")
            receipts.append(json.loads(out))

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(receipts, f)
        f.close()
        try:
            rc, out, _ = run_cli("reputation", f.name, "--json")
            self.assertEqual(rc, 0)
            data = json.loads(out)
            self.assertIsInstance(data, list)
            self.assertGreater(len(data), 0)
            self.assertIn("score", data[0])
        finally:
            os.unlink(f.name)


class TestCLIChain(unittest.TestCase):
    def test_chain_multiple_receipts(self):
        """chain command accepts a file of receipts and shows chain info."""
        _, r1_out, _ = run_cli("attest", "step-one")
        r1 = json.loads(r1_out)
        _, r2_out, _ = run_cli("attest", "step-two", "--parent", r1["receipt_id"])
        r2 = json.loads(r2_out)
        _, r3_out, _ = run_cli("attest", "step-three", "--parent", r2["receipt_id"])
        r3 = json.loads(r3_out)

        receipts = [r1, r2, r3]
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(receipts, f)
        f.close()
        try:
            rc, out, err = run_cli("chain", f.name)
            self.assertEqual(rc, 0)
            self.assertIn("Receipt Chain", out)
            self.assertIn("3 receipts", out)
        finally:
            os.unlink(f.name)

    def test_chain_single_receipt(self):
        """chain on a single-receipt file does not crash."""
        _, r_out, _ = run_cli("attest", "standalone")
        r = json.loads(r_out)

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump([r], f)
        f.close()
        try:
            rc, out, err = run_cli("chain", f.name)
            # Command is registered and accepts a file arg — must not crash with usage error
            self.assertNotIn("error: unrecognized arguments", err)
        finally:
            os.unlink(f.name)


class TestCLIValidate(unittest.TestCase):
    def test_validate_valid_receipt(self):
        """validate passes on a freshly-signed receipt."""
        _, r_out, _ = run_cli("attest", "valid-output")
        r = json.loads(r_out)

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump([r], f)
        f.close()
        try:
            rc, out, _ = run_cli("validate", f.name)
            self.assertEqual(rc, 0)
            self.assertIn("valid", out.lower())
        finally:
            os.unlink(f.name)

    def test_validate_tampered_receipt(self):
        """validate exits non-zero on a tampered receipt."""
        _, r_out, _ = run_cli("attest", "legit-output")
        r = json.loads(r_out)
        r["output_hash"] = "sha256:" + "0" * 64  # tamper

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump([r], f)
        f.close()
        try:
            rc, out, _ = run_cli("validate", f.name)
            self.assertNotEqual(rc, 0)
        finally:
            os.unlink(f.name)

    def test_validate_json_output(self):
        """validate --json returns structured report."""
        _, r_out, _ = run_cli("attest", "json-test")
        r = json.loads(r_out)

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump([r], f)
        f.close()
        try:
            rc, out, _ = run_cli("validate", f.name, "--json")
            self.assertEqual(rc, 0)
            data = json.loads(out)
            self.assertIn("valid", data)
            self.assertTrue(data["valid"])
        finally:
            os.unlink(f.name)

    def test_validate_no_sig(self):
        """validate --no-sig skips signature verification."""
        _, r_out, _ = run_cli("attest", "no-sig-test")
        r = json.loads(r_out)
        r["signature"] = "ed25519:" + "A" * 86  # structurally valid format, wrong sig

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump([r], f)
        f.close()
        try:
            rc, out, _ = run_cli("validate", f.name, "--no-sig")
            self.assertEqual(rc, 0)
        finally:
            os.unlink(f.name)


if __name__ == "__main__":
    unittest.main()
