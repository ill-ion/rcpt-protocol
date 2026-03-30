"""
RCPT Validator — Test Suite

Tests structural validation, format checking, and cross-receipt integrity.
"""

import unittest

from rcpt import RCPTClient, ActionType
from rcpt.validator import validate_receipt, ReceiptValidator, ValidationError


class TestStructuralValidation(unittest.TestCase):
    """Tests for individual receipt structural checks."""

    def setUp(self):
        self.client = RCPTClient()

    def test_valid_receipt(self):
        r = self.client.attest(action_type=ActionType.INFERENCE, output="hello")
        errors = validate_receipt(r.to_dict())
        error_list = [e for e in errors if e.severity == "error"]
        self.assertEqual(len(error_list), 0)

    def test_missing_required_field(self):
        r = self.client.attest(action_type=ActionType.INFERENCE, output="test")
        d = r.to_dict()
        del d["agent_id"]
        errors = validate_receipt(d, verify_signature=False)
        fields = [e.field for e in errors]
        self.assertIn("agent_id", fields)

    def test_missing_all_required(self):
        errors = validate_receipt({}, verify_signature=False)
        self.assertEqual(len(errors), 7)  # 7 required fields

    def test_invalid_receipt_id(self):
        r = self.client.attest(action_type=ActionType.INFERENCE, output="test")
        d = r.to_dict()
        d["receipt_id"] = "not-a-ulid"
        errors = validate_receipt(d, verify_signature=False)
        fields = [e.field for e in errors]
        self.assertIn("receipt_id", fields)

    def test_invalid_timestamp(self):
        r = self.client.attest(action_type=ActionType.INFERENCE, output="test")
        d = r.to_dict()
        d["timestamp"] = "2026-02-21"
        errors = validate_receipt(d, verify_signature=False)
        fields = [e.field for e in errors]
        self.assertIn("timestamp", fields)

    def test_invalid_agent_id(self):
        r = self.client.attest(action_type=ActionType.INFERENCE, output="test")
        d = r.to_dict()
        d["agent_id"] = "not-a-did"
        errors = validate_receipt(d, verify_signature=False)
        fields = [e.field for e in errors]
        self.assertIn("agent_id", fields)

    def test_invalid_action_type(self):
        r = self.client.attest(action_type=ActionType.INFERENCE, output="test")
        d = r.to_dict()
        d["action_type"] = "unknown_type"
        errors = validate_receipt(d, verify_signature=False)
        fields = [e.field for e in errors]
        self.assertIn("action_type", fields)

    def test_invalid_output_hash(self):
        r = self.client.attest(action_type=ActionType.INFERENCE, output="test")
        d = r.to_dict()
        d["output_hash"] = "md5:abc"
        errors = validate_receipt(d, verify_signature=False)
        fields = [e.field for e in errors]
        self.assertIn("output_hash", fields)

    def test_invalid_signature_format(self):
        r = self.client.attest(action_type=ActionType.INFERENCE, output="test")
        d = r.to_dict()
        d["signature"] = "rsa:xxxxx"
        errors = validate_receipt(d, verify_signature=False)
        fields = [e.field for e in errors]
        self.assertIn("signature", fields)

    def test_invalid_version(self):
        r = self.client.attest(action_type=ActionType.INFERENCE, output="test")
        d = r.to_dict()
        d["rcpt_version"] = "99.0"
        errors = validate_receipt(d, verify_signature=False)
        fields = [e.field for e in errors]
        self.assertIn("rcpt_version", fields)

    def test_valid_action_types(self):
        for at in ["inference", "tool_call", "transaction", "delegation", "observation", "custom"]:
            r = self.client.attest(action_type=at, output="test")
            d = r.to_dict()
            errors = [e for e in validate_receipt(d, verify_signature=False) if e.severity == "error"]
            self.assertEqual(len(errors), 0, f"Action type '{at}' should be valid")


class TestSignatureValidation(unittest.TestCase):

    def test_valid_signature(self):
        client = RCPTClient()
        r = client.attest(action_type=ActionType.INFERENCE, output="hello")
        errors = validate_receipt(r.to_dict(), verify_signature=True)
        error_list = [e for e in errors if e.severity == "error"]
        self.assertEqual(len(error_list), 0)

    def test_tampered_receipt(self):
        client = RCPTClient()
        r = client.attest(action_type=ActionType.INFERENCE, output="hello")
        d = r.to_dict()
        d["output_hash"] = "sha256:" + "0" * 64
        errors = validate_receipt(d, verify_signature=True)
        sig_errors = [e for e in errors if e.field == "signature" and e.severity == "error"]
        self.assertGreater(len(sig_errors), 0)


class TestOptionalFieldValidation(unittest.TestCase):

    def setUp(self):
        self.client = RCPTClient()

    def test_invalid_input_hash(self):
        r = self.client.attest(action_type=ActionType.INFERENCE, output="test")
        d = r.to_dict()
        d["input_hash"] = "bad-hash"
        errors = validate_receipt(d, verify_signature=False)
        fields = [e.field for e in errors]
        self.assertIn("input_hash", fields)

    def test_valid_model(self):
        r = self.client.attest(action_type=ActionType.INFERENCE, output="test", model="claude-sonnet-4-5")
        errors = [e for e in validate_receipt(r.to_dict(), verify_signature=False) if e.severity == "error"]
        self.assertEqual(len(errors), 0)


class TestMultiReceiptValidator(unittest.TestCase):

    def test_validate_all_valid(self):
        client = RCPTClient()
        v = ReceiptValidator()
        for i in range(5):
            r = client.attest(action_type=ActionType.INFERENCE, output=f"msg-{i}")
            v.add_receipt(r.to_dict())
        report = v.validate_all()
        self.assertTrue(report.is_valid)
        self.assertEqual(report.valid_receipts, 5)

    def test_chain_parent_missing(self):
        client = RCPTClient()
        r1 = client.attest(action_type=ActionType.INFERENCE, output="start")
        r2 = client.attest(action_type=ActionType.TOOL_CALL, output="step", parent=r1.receipt_id)

        v = ReceiptValidator()
        v.add_receipt(r2.to_dict())  # Only add child, not parent
        report = v.validate_all()
        # Should warn about missing parent
        parent_warnings = [w for w in report.warnings if "parent" in w.field.lower()]
        self.assertGreater(len(parent_warnings), 0)

    def test_chain_complete(self):
        client = RCPTClient()
        r1 = client.attest(action_type=ActionType.INFERENCE, output="start")
        r2 = client.attest(action_type=ActionType.TOOL_CALL, output="step", parent=r1.receipt_id)

        v = ReceiptValidator()
        v.add_receipt(r1.to_dict())
        v.add_receipt(r2.to_dict())
        report = v.validate_all()
        parent_warnings = [w for w in report.warnings if "parent" in w.field.lower()]
        self.assertEqual(len(parent_warnings), 0)

    def test_report_to_dict(self):
        client = RCPTClient()
        v = ReceiptValidator()
        r = client.attest(action_type=ActionType.INFERENCE, output="test")
        v.add_receipt(r.to_dict())
        report = v.validate_all()
        d = report.to_dict()
        self.assertIn("valid", d)
        self.assertIn("total_receipts", d)
        self.assertTrue(d["valid"])

    def test_mixed_valid_invalid(self):
        client = RCPTClient()
        v = ReceiptValidator()

        # Valid receipt
        r = client.attest(action_type=ActionType.INFERENCE, output="good")
        v.add_receipt(r.to_dict())

        # Invalid receipt (tampered)
        r2 = client.attest(action_type=ActionType.INFERENCE, output="bad")
        d = r2.to_dict()
        d["output_hash"] = "sha256:" + "0" * 64
        v.add_receipt(d)

        report = v.validate_all()
        self.assertFalse(report.is_valid)
        self.assertEqual(report.valid_receipts, 1)
        self.assertEqual(report.total_receipts, 2)


if __name__ == "__main__":
    unittest.main()
