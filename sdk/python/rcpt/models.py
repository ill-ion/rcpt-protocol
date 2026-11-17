"""
RCPT Receipt data models.

Defines the Receipt structure and all supporting types per the RCPT v0.1 specification.
"""

from __future__ import annotations

import json
import time
import os
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Union, List, Dict, Any
from datetime import datetime, timezone


class ActionType(str, Enum):
    """Categories of agent actions that can be attested."""
    INFERENCE = "inference"
    TOOL_CALL = "tool_call"
    TRANSACTION = "transaction"
    DELEGATION = "delegation"
    OBSERVATION = "observation"
    CUSTOM = "custom"


@dataclass
class Model:
    """Model identification."""
    provider: str
    model_id: str
    version: Optional[str] = None

    def to_dict(self) -> dict:
        d = {"provider": self.provider, "model_id": self.model_id}
        if self.version:
            d["version"] = self.version
        return d


@dataclass
class Framework:
    """Agent framework identification."""
    name: str
    version: Optional[str] = None

    def to_dict(self) -> dict:
        d = {"name": self.name}
        if self.version:
            d["version"] = self.version
        return d


@dataclass
class Chain:
    """Receipt chaining for multi-step workflows."""
    parent_receipt_id: Optional[Union[str, List[str]]] = None
    workflow_id: Optional[str] = None
    sequence: Optional[int] = None
    depth: Optional[int] = None

    def to_dict(self) -> dict:
        d = {}
        if self.parent_receipt_id is not None:
            d["parent_receipt_id"] = self.parent_receipt_id
        if self.workflow_id:
            d["workflow_id"] = self.workflow_id
        if self.sequence is not None:
            d["sequence"] = self.sequence
        if self.depth is not None:
            d["depth"] = self.depth
        return d


@dataclass
class Delegation:
    """Delegation metadata when agent acts on behalf of another entity."""
    delegator_id: str
    scope: List[str]
    expires: Optional[str] = None
    authorization_ref: Optional[str] = None

    def to_dict(self) -> dict:
        d = {"delegator_id": self.delegator_id, "scope": self.scope}
        if self.expires:
            d["expires"] = self.expires
        if self.authorization_ref:
            d["authorization_ref"] = self.authorization_ref
        return d


@dataclass
class Anchor:
    """On-chain anchoring proof."""
    chain: str
    tx_hash: str
    merkle_root: str
    merkle_proof: Optional[List[str]] = None
    anchored_at: Optional[str] = None

    def to_dict(self) -> dict:
        d = {
            "chain": self.chain,
            "tx_hash": self.tx_hash,
            "merkle_root": self.merkle_root,
        }
        if self.merkle_proof:
            d["merkle_proof"] = self.merkle_proof
        if self.anchored_at:
            d["anchored_at"] = self.anchored_at
        return d


@dataclass
class Metadata:
    """Free-form context and annotations."""
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    ttl: Optional[int] = None
    compliance: Optional[List[str]] = None
    extra: Optional[Dict[str, Any]] = None

    def to_dict(self) -> dict:
        d = {}
        if self.description:
            d["description"] = self.description
        # Lists are kept even when empty, matching the TypeScript SDK (where [] is
        # truthy). Dropping them would change the signed bytes on a round-trip.
        if self.tags is not None:
            d["tags"] = self.tags
        if self.ttl is not None:
            d["ttl"] = self.ttl
        if self.compliance is not None:
            d["compliance"] = self.compliance
        if self.extra:
            d.update(self.extra)
        return d


@dataclass
class Receipt:
    """
    RCPT Receipt — cryptographic proof-of-action for an AI agent.

    Required fields: rcpt_version, receipt_id, timestamp, agent_id,
    action_type, output_hash, signature.
    """
    # Required
    rcpt_version: str = "0.1"
    receipt_id: str = ""
    timestamp: str = ""
    agent_id: str = ""
    action_type: str = ""
    output_hash: str = ""
    signature: str = ""

    # Optional
    input_hash: Optional[str] = None
    parameters_hash: Optional[str] = None
    model: Optional[Model] = None
    framework: Optional[Framework] = None
    chain: Optional[Chain] = None
    delegation: Optional[Delegation] = None
    anchor: Optional[Anchor] = None
    metadata: Optional[Metadata] = None

    def to_dict(self) -> dict:
        """Convert receipt to dictionary, excluding None optional fields."""
        d = {
            "rcpt_version": self.rcpt_version,
            "receipt_id": self.receipt_id,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "action_type": self.action_type if isinstance(self.action_type, str) else self.action_type.value,
            "output_hash": self.output_hash,
            "signature": self.signature,
        }

        if self.input_hash:
            d["input_hash"] = self.input_hash
        if self.parameters_hash:
            d["parameters_hash"] = self.parameters_hash
        if self.model:
            d["model"] = self.model.to_dict()
        if self.framework:
            d["framework"] = self.framework.to_dict()
        if self.chain:
            chain_dict = self.chain.to_dict()
            if chain_dict:
                d["chain"] = chain_dict
        if self.delegation:
            d["delegation"] = self.delegation.to_dict()
        if self.anchor:
            d["anchor"] = self.anchor.to_dict()
        if self.metadata:
            meta_dict = self.metadata.to_dict()
            if meta_dict:
                d["metadata"] = meta_dict

        return d

    def to_json(self, indent: int = 2) -> str:
        """Serialize receipt to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def signable_dict(self) -> dict:
        """
        Return the receipt dict for signing — excludes 'signature' and 'anchor' fields.
        This is what gets canonicalized and signed.
        """
        d = self.to_dict()
        d.pop("signature", None)
        d.pop("anchor", None)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Receipt":
        """Deserialize a receipt from a dictionary."""
        receipt = cls(
            rcpt_version=data.get("rcpt_version", "0.1"),
            receipt_id=data["receipt_id"],
            timestamp=data["timestamp"],
            agent_id=data["agent_id"],
            action_type=data["action_type"],
            output_hash=data["output_hash"],
            signature=data.get("signature", ""),
        )

        if "input_hash" in data:
            receipt.input_hash = data["input_hash"]
        if "parameters_hash" in data:
            receipt.parameters_hash = data["parameters_hash"]
        if "model" in data:
            receipt.model = Model(**data["model"])
        if "framework" in data:
            receipt.framework = Framework(**data["framework"])
        if "chain" in data:
            receipt.chain = Chain(**data["chain"])
        if "delegation" in data:
            deleg_data = dict(data["delegation"])
            # Normalize scope: accept both legacy str ("read:x,write:y") and list (["read:x","write:y"])
            raw_scope = deleg_data.get("scope", [])
            if isinstance(raw_scope, str):
                deleg_data["scope"] = [s.strip() for s in raw_scope.split(",") if s.strip()]
            elif not isinstance(raw_scope, list):
                deleg_data["scope"] = []
            receipt.delegation = Delegation(**deleg_data)
        if "anchor" in data:
            receipt.anchor = Anchor(**data["anchor"])
        if "metadata" in data:
            known_keys = {"description", "tags", "ttl", "compliance"}
            meta_data = data["metadata"]
            extra = {k: v for k, v in meta_data.items() if k not in known_keys} or None
            receipt.metadata = Metadata(
                description=meta_data.get("description"),
                tags=meta_data.get("tags"),
                ttl=meta_data.get("ttl"),
                compliance=meta_data.get("compliance"),
                extra=extra,
            )

        return receipt

    @classmethod
    def from_json(cls, json_str: str) -> "Receipt":
        """Deserialize a receipt from a JSON string."""
        return cls.from_dict(json.loads(json_str))


def generate_ulid() -> str:
    """
    Generate a ULID (Universally Unique Lexicographically Sortable Identifier).
    26 characters, Crockford Base32.
    """
    CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    now_ms = int(time.time() * 1000)

    # Timestamp: 10 characters (48 bits)
    ts_chars = []
    for _ in range(10):
        ts_chars.append(CROCKFORD[now_ms & 0x1F])
        now_ms >>= 5
    ts_part = "".join(reversed(ts_chars))

    # Randomness: 16 characters (80 bits)
    rand_bytes = os.urandom(10)
    rand_val = int.from_bytes(rand_bytes, "big")
    rand_chars = []
    for _ in range(16):
        rand_chars.append(CROCKFORD[rand_val & 0x1F])
        rand_val >>= 5
    rand_part = "".join(reversed(rand_chars))

    return ts_part + rand_part


def now_iso8601() -> str:
    """Generate current UTC timestamp in ISO 8601 format with milliseconds."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
           f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"
