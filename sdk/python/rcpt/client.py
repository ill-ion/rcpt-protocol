"""
RCPT Client — the primary interface for generating and verifying receipts.

Usage:
    from rcpt import RCPTClient, ActionType

    client = RCPTClient(private_key="base64url:...")
    receipt = client.attest(action_type=ActionType.INFERENCE, output="Hello")
    assert client.verify(receipt)
"""

from __future__ import annotations

import json
import sqlite3
import os
from typing import Optional, Union, List, Dict, Any
from pathlib import Path

from rcpt.models import (
    Receipt, ActionType, Model, Framework, Chain,
    Delegation, Anchor, Metadata, generate_ulid, now_iso8601,
)
from rcpt.hashing import hash_content, hash_receipt_canonical
from rcpt.crypto import sign_receipt, verify_receipt, generate_keypair, _b64url_encode, _public_key_to_did


class RCPTClient:
    """
    RCPT Client for generating and verifying Receipt Chain Protocol for Trusts.

    Args:
        private_key: Ed25519 private key as base64url string.
                     If not provided, a new keypair is generated.
        agent_id: DID of the agent. If not provided, derived from the private key.
        store: Receipt storage backend.
               - "memory" (default): in-memory only
               - "sqlite:///path.db": SQLite database
               - None: no storage (receipts returned but not persisted)
    """

    def __init__(
        self,
        private_key: Optional[str] = None,
        agent_id: Optional[str] = None,
        store: str = "memory",
    ):
        if private_key is None:
            self._private_key, self._public_key, self._agent_id = generate_keypair()
        else:
            self._private_key = private_key
            # Derive public key and DID from private key
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                from cryptography.hazmat.primitives import serialization
                from rcpt.crypto import _b64url_decode
                sk = Ed25519PrivateKey.from_private_bytes(_b64url_decode(private_key))
                pk_bytes = sk.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
                self._public_key = _b64url_encode(pk_bytes)
                self._agent_id = _public_key_to_did(pk_bytes)
            except ImportError:
                try:
                    from nacl.signing import SigningKey
                    from rcpt.crypto import _b64url_decode
                    sk = SigningKey(_b64url_decode(private_key))
                    pk_bytes = bytes(sk.verify_key)
                    self._public_key = _b64url_encode(pk_bytes)
                    self._agent_id = _public_key_to_did(pk_bytes)
                except ImportError:
                    raise ImportError("RCPT requires 'cryptography' or 'pynacl'.")

        if agent_id:
            self._agent_id = agent_id

        # Initialize storage
        self._store_type = store
        self._memory_store: List[Receipt] = []
        self._db: Optional[sqlite3.Connection] = None

        if store and store.startswith("sqlite:///"):
            db_path = store[len("sqlite:///"):]
            self._db = sqlite3.connect(db_path)
            self._init_db()

    def _init_db(self):
        """Initialize SQLite schema."""
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                receipt_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                output_hash TEXT NOT NULL,
                workflow_id TEXT,
                parent_receipt_id TEXT,
                receipt_json TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_receipts_agent
            ON receipts(agent_id)
        """)
        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_receipts_workflow
            ON receipts(workflow_id)
        """)
        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_receipts_timestamp
            ON receipts(timestamp)
        """)
        self._db.commit()

    @property
    def agent_id(self) -> str:
        """The agent's DID."""
        return self._agent_id

    @property
    def public_key(self) -> str:
        """The agent's public key as base64url."""
        return self._public_key

    def attest(
        self,
        action_type: Union[ActionType, str],
        output: Union[str, bytes, dict, list, Any],
        input_data: Optional[Union[str, bytes, dict, list]] = None,
        parameters: Optional[dict] = None,
        model: Optional[Union[str, Model]] = None,
        framework: Optional[Union[str, Framework]] = None,
        parent: Optional[Union[str, List[str]]] = None,
        workflow_id: Optional[str] = None,
        sequence: Optional[int] = None,
        delegation: Optional[Delegation] = None,
        metadata: Optional[Union[Metadata, dict]] = None,
    ) -> Receipt:
        """
        Generate a signed RCPT receipt for an agent action.

        Args:
            action_type: Category of action (ActionType enum or string)
            output: The action output (will be hashed, not stored)
            input_data: Optional input/prompt (will be hashed)
            parameters: Optional model configuration dict (will be hashed)
            model: Model identifier (string like "claude-sonnet-4-5" or Model object)
            framework: Framework name (string like "langchain" or Framework object)
            parent: Parent receipt ID(s) for chaining
            workflow_id: Workflow grouping ID
            sequence: Position in workflow chain
            delegation: Delegation metadata
            metadata: Additional context

        Returns:
            Signed Receipt object
        """
        # Normalize action_type
        if isinstance(action_type, ActionType):
            action_type_str = action_type.value
        else:
            action_type_str = str(action_type)

        # Build receipt
        receipt = Receipt(
            rcpt_version="0.1",
            receipt_id=generate_ulid(),
            timestamp=now_iso8601(),
            agent_id=self._agent_id,
            action_type=action_type_str,
            output_hash=hash_content(output),
        )

        # Optional: input hash
        if input_data is not None:
            receipt.input_hash = hash_content(input_data)

        # Optional: parameters hash
        if parameters is not None:
            receipt.parameters_hash = hash_content(parameters)

        # Optional: model
        if model is not None:
            if isinstance(model, str):
                # Parse "provider/model_id" or just "model_id"
                if "/" in model:
                    provider, model_id = model.split("/", 1)
                    receipt.model = Model(provider=provider, model_id=model_id)
                else:
                    # Try to infer provider from model name
                    provider = _infer_provider(model)
                    receipt.model = Model(provider=provider, model_id=model)
            else:
                receipt.model = model

        # Optional: framework
        if framework is not None:
            if isinstance(framework, str):
                receipt.framework = Framework(name=framework)
            else:
                receipt.framework = framework

        # Optional: chaining
        if parent is not None or workflow_id is not None:
            receipt.chain = Chain(
                parent_receipt_id=parent,
                workflow_id=workflow_id or generate_ulid(),
                sequence=sequence,
            )

        # Optional: delegation
        if delegation is not None:
            receipt.delegation = delegation

        # Optional: metadata
        if metadata is not None:
            if isinstance(metadata, dict):
                known_keys = {"description", "tags", "ttl", "compliance"}
                extra = {k: v for k, v in metadata.items() if k not in known_keys} or None
                receipt.metadata = Metadata(
                    description=metadata.get("description"),
                    tags=metadata.get("tags"),
                    ttl=metadata.get("ttl"),
                    compliance=metadata.get("compliance"),
                    extra=extra,
                )
            else:
                receipt.metadata = metadata

        # Sign the receipt
        receipt.signature = sign_receipt(receipt, self._private_key)

        # Store
        self._store_receipt(receipt)

        return receipt

    def verify(self, receipt: Union[Receipt, dict, str], require_anchor: bool = False) -> bool:
        """
        Verify a receipt's cryptographic signature.

        Args:
            receipt: Receipt object, dict, or JSON string
            require_anchor: If True, also require valid on-chain anchor

        Returns:
            True if the receipt is valid
        """
        if isinstance(receipt, str):
            receipt = Receipt.from_json(receipt)
        elif isinstance(receipt, dict):
            receipt = Receipt.from_dict(receipt)

        # Verify signature
        if not verify_receipt(receipt):
            return False

        # Verify anchor if required
        if require_anchor:
            if receipt.anchor is None:
                return False
            # TODO: On-chain verification via Solana RPC
            # For now, just check that anchor fields are present
            if not receipt.anchor.tx_hash or not receipt.anchor.merkle_root:
                return False

        return True

    def get_receipt(self, receipt_id: str) -> Optional[Receipt]:
        """Retrieve a receipt by ID."""
        if self._db:
            cursor = self._db.execute(
                "SELECT receipt_json FROM receipts WHERE receipt_id = ?",
                (receipt_id,)
            )
            row = cursor.fetchone()
            if row:
                return Receipt.from_json(row[0])
        else:
            for r in self._memory_store:
                if r.receipt_id == receipt_id:
                    return r
        return None

    def get_chain(self, receipt_id: str) -> List[Receipt]:
        """
        Get the full receipt chain leading to a given receipt.
        Walks parent references backward to the root.
        """
        chain = []
        current_id = receipt_id

        while current_id:
            receipt = self.get_receipt(current_id)
            if receipt is None:
                break
            chain.append(receipt)

            if receipt.chain and receipt.chain.parent_receipt_id:
                parent = receipt.chain.parent_receipt_id
                if isinstance(parent, list):
                    current_id = parent[0]  # Follow first parent for linear chain
                else:
                    current_id = parent
            else:
                break

        return list(reversed(chain))

    def get_workflow(self, workflow_id: str) -> List[Receipt]:
        """Get all receipts in a workflow, ordered by sequence."""
        if self._db:
            cursor = self._db.execute(
                "SELECT receipt_json FROM receipts WHERE workflow_id = ? ORDER BY timestamp",
                (workflow_id,)
            )
            return [Receipt.from_json(row[0]) for row in cursor.fetchall()]
        else:
            return sorted(
                [r for r in self._memory_store
                 if r.chain and r.chain.workflow_id == workflow_id],
                key=lambda r: r.timestamp
            )

    def export(
        self,
        format: str = "json",
        start: Optional[str] = None,
        end: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> str:
        """
        Export receipts for compliance or analysis.

        Args:
            format: "json" or "eu-ai-act"
            start: Start timestamp (ISO 8601)
            end: End timestamp (ISO 8601)
            agent_id: Filter by agent ID

        Returns:
            JSON string of exported receipts
        """
        receipts = []

        if self._db:
            query = "SELECT receipt_json FROM receipts WHERE 1=1"
            params = []
            if start:
                query += " AND timestamp >= ?"
                params.append(start)
            if end:
                query += " AND timestamp <= ?"
                params.append(end)
            if agent_id:
                query += " AND agent_id = ?"
                params.append(agent_id)
            query += " ORDER BY timestamp"

            cursor = self._db.execute(query, params)
            receipts = [json.loads(row[0]) for row in cursor.fetchall()]
        else:
            for r in self._memory_store:
                if start and r.timestamp < start:
                    continue
                if end and r.timestamp > end:
                    continue
                if agent_id and r.agent_id != agent_id:
                    continue
                receipts.append(r.to_dict())

        if format == "eu-ai-act":
            return json.dumps({
                "compliance_framework": "EU AI Act (Regulation (EU) 2024/1689)",
                "export_timestamp": now_iso8601(),
                "articles_covered": ["Article 12", "Article 19", "Article 26"],
                "agent_id": agent_id or self._agent_id,
                "period": {"start": start, "end": end},
                "total_receipts": len(receipts),
                "receipts": receipts,
            }, indent=2)
        else:
            return json.dumps(receipts, indent=2)

    def _store_receipt(self, receipt: Receipt):
        """Persist a receipt to the configured store."""
        if self._store_type == "memory":
            self._memory_store.append(receipt)
        elif self._db:
            workflow_id = receipt.chain.workflow_id if receipt.chain else None
            parent_id = None
            if receipt.chain and receipt.chain.parent_receipt_id:
                parent = receipt.chain.parent_receipt_id
                parent_id = parent if isinstance(parent, str) else json.dumps(parent)

            self._db.execute(
                """INSERT OR REPLACE INTO receipts
                   (receipt_id, timestamp, agent_id, action_type, output_hash,
                    workflow_id, parent_receipt_id, receipt_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    receipt.receipt_id,
                    receipt.timestamp,
                    receipt.agent_id,
                    receipt.action_type,
                    receipt.output_hash,
                    workflow_id,
                    parent_id,
                    receipt.to_json(),
                )
            )
            self._db.commit()

    def close(self):
        """Close database connection if open."""
        if self._db:
            self._db.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _infer_provider(model_id: str) -> str:
    """Infer model provider from model ID string."""
    model_lower = model_id.lower()
    if "claude" in model_lower:
        return "anthropic"
    elif "gpt" in model_lower or "o1" in model_lower or "o3" in model_lower:
        return "openai"
    elif "gemini" in model_lower:
        return "google"
    elif "llama" in model_lower:
        return "meta"
    elif "mistral" in model_lower or "mixtral" in model_lower:
        return "mistral"
    elif "command" in model_lower:
        return "cohere"
    else:
        return "unknown"
