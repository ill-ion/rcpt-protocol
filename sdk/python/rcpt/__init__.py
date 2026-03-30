"""
RCPT — Receipt Chain Protocol for Trust Protocol

Cryptographic proof-of-action for AI agents.

Usage:
    from rcpt import RCPTClient, ActionType

    client = RCPTClient(private_key="base64url:...")
    receipt = client.attest(action_type=ActionType.INFERENCE, output="Hello world")
    assert client.verify(receipt)
"""

from rcpt.client import RCPTClient
from rcpt.models import Receipt, ActionType, Model, Framework, Chain, Delegation, Anchor, Metadata
from rcpt.crypto import generate_keypair, sign_receipt, verify_receipt
from rcpt.hashing import hash_content, hash_receipt_canonical
from rcpt.reputation import ReputationEngine, ReputationScore
from rcpt.compliance import ComplianceDashboard, ComplianceReport, ComplianceFinding
from rcpt.store import ReceiptStore
from rcpt.validator import ReceiptValidator, validate_receipt, ValidationError, ValidationReport

__version__ = "0.1.1"
__all__ = [
    "RCPTClient",
    "Receipt",
    "ActionType",
    "Model",
    "Framework",
    "Chain",
    "Delegation",
    "Anchor",
    "Metadata",
    "generate_keypair",
    "sign_receipt",
    "verify_receipt",
    "hash_content",
    "hash_receipt_canonical",
    "ReputationEngine",
    "ReputationScore",
    "ComplianceDashboard",
    "ComplianceReport",
    "ComplianceFinding",
    "ReceiptStore",
    "ReceiptValidator",
    "validate_receipt",
    "ValidationError",
    "ValidationReport",
]
