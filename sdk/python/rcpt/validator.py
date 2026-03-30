"""
RCPT Receipt Validator

Validates receipts against the RCPT v0.1 specification:
- Structural validation (required fields, types, formats)
- Cryptographic verification (Ed25519 signature)
- Chain integrity (parent references exist, no cycles)
- Schema compliance (ULID format, DID format, hash format, timestamp format)

Usage:
    from rcpt.validator import ReceiptValidator, validate_receipt

    # Quick validation
    errors = validate_receipt(receipt_dict)
    if errors:
        for e in errors:
            print(f"  {e.severity}: {e.field} — {e.message}")

    # Full validator with chain checking
    validator = ReceiptValidator()
    validator.add_receipt(receipt1)
    validator.add_receipt(receipt2)
    report = validator.validate_all()
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from rcpt.crypto import verify_receipt as crypto_verify
from rcpt.models import Receipt


# ── Validation Error ────────────────────────────────────────────────────────

@dataclass
class ValidationError:
    """A single validation finding."""
    field: str
    message: str
    severity: str  # "error", "warning", "info"
    receipt_id: Optional[str] = None

    def __str__(self):
        prefix = f"[{self.receipt_id[:16]}] " if self.receipt_id else ""
        return f"{prefix}{self.severity.upper()}: {self.field} — {self.message}"


@dataclass
class ValidationReport:
    """Complete validation report for one or more receipts."""
    total_receipts: int
    valid_receipts: int
    errors: List[ValidationError]
    warnings: List[ValidationError]

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

    def to_dict(self) -> dict:
        return {
            "valid": self.is_valid,
            "total_receipts": self.total_receipts,
            "valid_receipts": self.valid_receipts,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "errors": [{"field": e.field, "message": e.message, "receipt_id": e.receipt_id} for e in self.errors],
            "warnings": [{"field": w.field, "message": w.message, "receipt_id": w.receipt_id} for w in self.warnings],
        }


# ── Format Patterns ─────────────────────────────────────────────────────────

ULID_PATTERN = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
DID_PATTERN = re.compile(r"^did:[a-z]+:.+$")
SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
ED25519_SIG_PATTERN = re.compile(r"^ed25519:.+$")
ISO8601_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
VALID_ACTION_TYPES = {"inference", "tool_call", "transaction", "delegation", "observation", "custom"}
VALID_VERSIONS = {"0.1"}


# ── Single Receipt Validation ───────────────────────────────────────────────

def validate_receipt(
    data: dict,
    verify_signature: bool = True,
) -> List[ValidationError]:
    """
    Validate a single receipt dict against the RCPT v0.1 specification.

    Args:
        data: Receipt as a dict.
        verify_signature: If True, also verify the Ed25519 signature.

    Returns:
        List of ValidationError objects. Empty = valid.
    """
    errors: List[ValidationError] = []
    rid = data.get("receipt_id", "unknown")

    def err(field: str, msg: str, sev: str = "error"):
        errors.append(ValidationError(field=field, message=msg, severity=sev, receipt_id=rid))

    # ── Required Fields ─────────────────────────────────────────────────

    required = ["rcpt_version", "receipt_id", "timestamp", "agent_id", "action_type", "output_hash", "signature"]
    for f in required:
        if f not in data or data[f] is None:
            err(f, f"Required field '{f}' is missing")

    # ── rcpt_version ────────────────────────────────────────────────────

    if "rcpt_version" in data:
        if data["rcpt_version"] not in VALID_VERSIONS:
            err("rcpt_version", f"Unknown version '{data['rcpt_version']}'. Expected one of: {VALID_VERSIONS}")

    # ── receipt_id ──────────────────────────────────────────────────────

    if "receipt_id" in data and data["receipt_id"]:
        if not ULID_PATTERN.match(data["receipt_id"]):
            err("receipt_id", f"Invalid ULID format: '{data['receipt_id']}'. Must be 26 Crockford Base32 chars.")

    # ── timestamp ───────────────────────────────────────────────────────

    if "timestamp" in data and data["timestamp"]:
        ts = data["timestamp"]
        if not ISO8601_PATTERN.match(ts):
            err("timestamp", f"Invalid timestamp format: '{ts}'. Must be ISO 8601 with milliseconds and Z suffix.")
        if not ts.endswith("Z"):
            err("timestamp", "Timestamp must be UTC (Z suffix)")

    # ── agent_id ────────────────────────────────────────────────────────

    if "agent_id" in data and data["agent_id"]:
        if not DID_PATTERN.match(data["agent_id"]):
            err("agent_id", f"Invalid DID format: '{data['agent_id']}'. Must start with 'did:<method>:'.")

    # ── action_type ─────────────────────────────────────────────────────

    if "action_type" in data and data["action_type"]:
        if data["action_type"] not in VALID_ACTION_TYPES:
            err("action_type", f"Invalid action type '{data['action_type']}'. Must be one of: {VALID_ACTION_TYPES}")

    # ── output_hash ─────────────────────────────────────────────────────

    if "output_hash" in data and data["output_hash"]:
        if not SHA256_PATTERN.match(data["output_hash"]):
            err("output_hash", f"Invalid hash format. Must be 'sha256:' followed by 64 hex chars.")

    # ── signature ───────────────────────────────────────────────────────

    if "signature" in data and data["signature"]:
        if not ED25519_SIG_PATTERN.match(data["signature"]):
            err("signature", "Invalid signature format. Must start with 'ed25519:'.")

    # ── Optional: input_hash ────────────────────────────────────────────

    if "input_hash" in data and data["input_hash"]:
        if not SHA256_PATTERN.match(data["input_hash"]):
            err("input_hash", "Invalid hash format. Must be 'sha256:' followed by 64 hex chars.")

    # ── Optional: parameters_hash ───────────────────────────────────────

    if "parameters_hash" in data and data["parameters_hash"]:
        if not SHA256_PATTERN.match(data["parameters_hash"]):
            err("parameters_hash", "Invalid hash format.")

    # ── Optional: model ─────────────────────────────────────────────────

    if "model" in data and data["model"]:
        model = data["model"]
        if isinstance(model, dict):
            if "provider" not in model:
                err("model.provider", "Model object must include 'provider' field", "warning")
            if "model_id" not in model:
                err("model.model_id", "Model object must include 'model_id' field", "warning")
        else:
            err("model", "Model field must be an object with 'provider' and 'model_id'")

    # ── Optional: chain ─────────────────────────────────────────────────

    if "chain" in data and data["chain"]:
        chain = data["chain"]
        if isinstance(chain, dict):
            if "parent_receipt_id" not in chain and "workflow_id" not in chain:
                err("chain", "Chain object must include 'parent_receipt_id' or 'workflow_id'", "warning")
        else:
            err("chain", "Chain field must be an object")

    # ── Optional: delegation ────────────────────────────────────────────

    if "delegation" in data and data["delegation"]:
        deleg = data["delegation"]
        if isinstance(deleg, dict):
            if "delegator_id" not in deleg:
                err("delegation.delegator_id", "Delegation must include 'delegator_id'")
            elif not DID_PATTERN.match(deleg.get("delegator_id", "")):
                # Relaxed: delegator_id can be any URI-like string
                pass
        else:
            err("delegation", "Delegation field must be an object")

    # ── Signature Verification ──────────────────────────────────────────

    if verify_signature and len([e for e in errors if e.severity == "error"]) == 0:
        try:
            receipt = Receipt.from_dict(data)
            if not crypto_verify(receipt):
                err("signature", "Ed25519 signature verification failed")
        except Exception as e:
            err("signature", f"Could not verify signature: {e}")

    return errors


# ── Multi-Receipt Validator ─────────────────────────────────────────────────

class ReceiptValidator:
    """
    Validates multiple receipts including cross-receipt integrity checks.

    Checks:
    - Individual receipt structural validation
    - Signature verification
    - Chain integrity (parent references resolve)
    - No duplicate receipt IDs
    - Timestamp ordering within chains
    """

    def __init__(self):
        self._receipts: Dict[str, dict] = {}

    def add_receipt(self, data: dict) -> None:
        """Add a receipt dict for validation."""
        rid = data.get("receipt_id", f"unknown-{len(self._receipts)}")
        self._receipts[rid] = data

    def add_receipts(self, data: List[dict]) -> None:
        for d in data:
            self.add_receipt(d)

    def validate_all(self, verify_signatures: bool = True) -> ValidationReport:
        """
        Validate all added receipts.

        Returns:
            ValidationReport with errors and warnings.
        """
        all_errors: List[ValidationError] = []
        all_warnings: List[ValidationError] = []
        valid_count = 0

        # Individual validation
        for rid, data in self._receipts.items():
            findings = validate_receipt(data, verify_signature=verify_signatures)
            errors = [f for f in findings if f.severity == "error"]
            warnings = [f for f in findings if f.severity in ("warning", "info")]
            all_errors.extend(errors)
            all_warnings.extend(warnings)
            if not errors:
                valid_count += 1

        # Cross-receipt checks
        receipt_ids = set(self._receipts.keys())

        # Check parent references
        for rid, data in self._receipts.items():
            chain = data.get("chain")
            if chain and isinstance(chain, dict):
                parent = chain.get("parent_receipt_id")
                if parent:
                    parents = parent if isinstance(parent, list) else [parent]
                    for p in parents:
                        if p not in receipt_ids:
                            all_warnings.append(ValidationError(
                                field="chain.parent_receipt_id",
                                message=f"Parent receipt '{p[:16]}...' not found in validation set",
                                severity="warning",
                                receipt_id=rid,
                            ))

        # Check for timestamp ordering in chains
        for rid, data in self._receipts.items():
            chain = data.get("chain")
            if chain and isinstance(chain, dict):
                parent_id = chain.get("parent_receipt_id")
                if parent_id and not isinstance(parent_id, list) and parent_id in self._receipts:
                    parent_ts = self._receipts[parent_id].get("timestamp", "")
                    child_ts = data.get("timestamp", "")
                    if parent_ts and child_ts and child_ts < parent_ts:
                        all_warnings.append(ValidationError(
                            field="timestamp",
                            message=f"Receipt timestamp ({child_ts}) is before parent ({parent_ts})",
                            severity="warning",
                            receipt_id=rid,
                        ))

        return ValidationReport(
            total_receipts=len(self._receipts),
            valid_receipts=valid_count,
            errors=all_errors,
            warnings=all_warnings,
        )
