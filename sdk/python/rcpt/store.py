"""
RCPT Receipt Store

SQLite-backed receipt storage with query, verification, Merkle batching,
and export capabilities. This is what you'd run in production.

Usage:
    from rcpt import RCPTClient
    from rcpt.store import ReceiptStore

    client = RCPTClient()
    store = ReceiptStore("receipts.db")

    # Attest and store in one call
    receipt = store.attest(client, action_type="inference", output="Hello")

    # Query
    receipts = store.query(agent_id="did:key:...", action_type="inference", limit=100)
    chain = store.get_chain(receipt_id)

    # Batch anchor
    root, count = store.create_merkle_batch()

    # Export
    store.export_json("export.json")
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from rcpt.models import Receipt, ActionType
from rcpt.hashing import hash_receipt_canonical, build_merkle_tree


# ── Schema ──────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS receipts (
    receipt_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    output_hash TEXT NOT NULL,
    input_hash TEXT,
    signature TEXT NOT NULL,
    model_provider TEXT,
    model_id TEXT,
    parent_receipt_id TEXT,
    workflow_id TEXT,
    sequence INTEGER,
    description TEXT,
    tags TEXT,
    raw_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    batch_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_receipts_agent ON receipts(agent_id);
CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts(timestamp);
CREATE INDEX IF NOT EXISTS idx_receipts_action ON receipts(action_type);
CREATE INDEX IF NOT EXISTS idx_receipts_workflow ON receipts(workflow_id);
CREATE INDEX IF NOT EXISTS idx_receipts_parent ON receipts(parent_receipt_id);
CREATE INDEX IF NOT EXISTS idx_receipts_batch ON receipts(batch_id);

CREATE TABLE IF NOT EXISTS merkle_batches (
    batch_id TEXT PRIMARY KEY,
    merkle_root TEXT NOT NULL,
    receipt_count INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    anchored_at TEXT,
    anchor_tx TEXT
);
"""


class ReceiptStore:
    """
    SQLite-backed receipt store with full query and batch capabilities.

    Thread-safe for reads. Writes should be serialized (SQLite limitation).
    """

    def __init__(self, db_path: str = ":memory:"):
        """
        Args:
            db_path: Path to SQLite database. Use ":memory:" for in-memory.
        """
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)

    def attest(self, client: Any, **kwargs: Any) -> Receipt:
        """
        Generate a receipt via the client and store it.

        Args:
            client: RCPTClient instance.
            **kwargs: Passed to client.attest().

        Returns:
            The generated Receipt.
        """
        receipt = client.attest(**kwargs)
        self.store(receipt)
        return receipt

    def store(self, receipt: Receipt) -> None:
        """Store a receipt in the database."""
        self._store_row(receipt)
        self._conn.commit()

    def store_many(self, receipts: List[Receipt]) -> None:
        """Store multiple receipts in a single transaction."""
        for r in receipts:
            self._store_row(r)
        self._conn.commit()

    def _store_row(self, receipt: Receipt) -> None:
        """Insert a receipt row without committing (caller commits)."""
        d = receipt.to_dict()
        raw = json.dumps(d)

        model_provider = None
        model_id = None
        if receipt.model:
            model_provider = receipt.model.provider
            model_id = receipt.model.model_id

        parent_id = None
        workflow_id = None
        sequence = None
        if receipt.chain:
            parent_id = receipt.chain.parent_receipt_id
            if isinstance(parent_id, list):
                parent_id = parent_id[0] if parent_id else None
            workflow_id = receipt.chain.workflow_id
            sequence = receipt.chain.sequence

        description = None
        tags = None
        if receipt.metadata:
            description = receipt.metadata.description
            if receipt.metadata.tags:
                tags = json.dumps(receipt.metadata.tags)

        self._conn.execute(
            """INSERT OR REPLACE INTO receipts
               (receipt_id, timestamp, agent_id, action_type, output_hash,
                input_hash, signature, model_provider, model_id,
                parent_receipt_id, workflow_id, sequence,
                description, tags, raw_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                receipt.receipt_id, receipt.timestamp, receipt.agent_id,
                receipt.action_type, receipt.output_hash, receipt.input_hash,
                receipt.signature, model_provider, model_id,
                parent_id, workflow_id, sequence,
                description, tags, raw,
            ),
        )

    def get(self, receipt_id: str) -> Optional[Receipt]:
        """Get a receipt by ID."""
        row = self._conn.execute(
            "SELECT raw_json FROM receipts WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        if row is None:
            return None
        return Receipt.from_dict(json.loads(row["raw_json"]))

    def get_chain(self, receipt_id: str) -> List[Receipt]:
        """Walk a chain backward from receipt_id to the root."""
        chain = []
        current_id = receipt_id
        seen = set()

        while current_id and current_id not in seen:
            seen.add(current_id)
            receipt = self.get(current_id)
            if receipt is None:
                break
            chain.append(receipt)
            if receipt.chain and receipt.chain.parent_receipt_id:
                pid = receipt.chain.parent_receipt_id
                current_id = pid[0] if isinstance(pid, list) else pid
            else:
                break

        chain.reverse()
        return chain

    def query(
        self,
        agent_id: Optional[str] = None,
        action_type: Optional[str] = None,
        workflow_id: Optional[str] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Receipt]:
        """
        Query receipts with optional filters.

        Args:
            agent_id: Filter by agent DID.
            action_type: Filter by action type.
            workflow_id: Filter by workflow ID.
            start: Start timestamp (inclusive).
            end: End timestamp (inclusive).
            limit: Max results.
            offset: Pagination offset.

        Returns:
            List of matching Receipt objects.
        """
        conditions = []
        params: List[Any] = []

        if agent_id:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if action_type:
            conditions.append("action_type = ?")
            params.append(action_type)
        if workflow_id:
            conditions.append("workflow_id = ?")
            params.append(workflow_id)
        if start:
            conditions.append("timestamp >= ?")
            params.append(start)
        if end:
            conditions.append("timestamp <= ?")
            params.append(end)

        where = " AND ".join(conditions) if conditions else "1=1"
        sql = f"SELECT raw_json FROM receipts WHERE {where} ORDER BY timestamp ASC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = self._conn.execute(sql, params).fetchall()
        return [Receipt.from_dict(json.loads(row["raw_json"])) for row in rows]

    def count(self, **kwargs: Any) -> int:
        """Count receipts matching the given filters."""
        conditions = []
        params: List[Any] = []

        for key in ["agent_id", "action_type", "workflow_id"]:
            if key in kwargs and kwargs[key]:
                conditions.append(f"{key} = ?")
                params.append(kwargs[key])

        where = " AND ".join(conditions) if conditions else "1=1"
        row = self._conn.execute(f"SELECT COUNT(*) as cnt FROM receipts WHERE {where}", params).fetchone()
        return row["cnt"]

    def agents(self) -> List[Dict[str, Any]]:
        """List all agents with receipt counts."""
        rows = self._conn.execute(
            """SELECT agent_id, COUNT(*) as receipt_count,
                      MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
               FROM receipts GROUP BY agent_id ORDER BY receipt_count DESC"""
        ).fetchall()
        return [dict(row) for row in rows]

    # ── Merkle Batching ─────────────────────────────────────────────────

    def create_merkle_batch(self, batch_size: Optional[int] = None) -> Tuple[str, int]:
        """
        Create a Merkle batch from unbatched receipts.

        Args:
            batch_size: Max receipts per batch. None = all unbatched.

        Returns:
            (merkle_root, receipt_count)
        """
        limit_clause = f"LIMIT {batch_size}" if batch_size else ""
        rows = self._conn.execute(
            f"SELECT receipt_id, raw_json FROM receipts WHERE batch_id IS NULL ORDER BY timestamp ASC {limit_clause}"
        ).fetchall()

        if not rows:
            return "", 0

        hashes = [hash_receipt_canonical(json.loads(row["raw_json"])) for row in rows]
        root, _ = build_merkle_tree(hashes)

        batch_id = Receipt.from_dict(json.loads(rows[0]["raw_json"])).receipt_id[:10] + f"-batch-{len(rows)}"

        self._conn.execute(
            "INSERT INTO merkle_batches (batch_id, merkle_root, receipt_count) VALUES (?, ?, ?)",
            (batch_id, root, len(rows)),
        )

        receipt_ids = [row["receipt_id"] for row in rows]
        placeholders = ",".join(["?"] * len(receipt_ids))
        self._conn.execute(
            f"UPDATE receipts SET batch_id = ? WHERE receipt_id IN ({placeholders})",
            [batch_id] + receipt_ids,
        )
        self._conn.commit()

        return root, len(rows)

    def get_batches(self) -> List[Dict[str, Any]]:
        """List all Merkle batches."""
        rows = self._conn.execute(
            "SELECT * FROM merkle_batches ORDER BY created_at DESC"
        ).fetchall()
        return [dict(row) for row in rows]

    def mark_anchored(self, batch_id: str, tx_hash: str) -> None:
        """Mark a batch as anchored on-chain."""
        self._conn.execute(
            "UPDATE merkle_batches SET anchored_at = datetime('now'), anchor_tx = ? WHERE batch_id = ?",
            (tx_hash, batch_id),
        )
        self._conn.commit()

    # ── Export ──────────────────────────────────────────────────────────

    def export_json(self, path: str, **kwargs: Any) -> int:
        """Export receipts to a JSON file.

        If no filter kwargs are provided, exports all receipts.
        Filtering kwargs: agent_id, action_type, workflow_id, start, end.
        Note: 'limit' defaults to all receipts when no filters are specified.
        """
        if kwargs:
            # Apply filters but override default limit to avoid silent truncation
            kwargs.setdefault("limit", 2 ** 31 - 1)
            receipts = self.query(**kwargs)
            data = [r.to_dict() for r in receipts]
        else:
            data = self.export_all()
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        return len(data)

    def export_all(self) -> List[Dict]:
        """Export all receipts as dicts."""
        rows = self._conn.execute("SELECT raw_json FROM receipts ORDER BY timestamp ASC").fetchall()
        return [json.loads(row["raw_json"]) for row in rows]

    # ── Stats ──────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        total = self._conn.execute("SELECT COUNT(*) as cnt FROM receipts").fetchone()["cnt"]
        agents = self._conn.execute("SELECT COUNT(DISTINCT agent_id) as cnt FROM receipts").fetchone()["cnt"]
        batched = self._conn.execute("SELECT COUNT(*) as cnt FROM receipts WHERE batch_id IS NOT NULL").fetchone()["cnt"]
        batches = self._conn.execute("SELECT COUNT(*) as cnt FROM merkle_batches").fetchone()["cnt"]
        anchored = self._conn.execute("SELECT COUNT(*) as cnt FROM merkle_batches WHERE anchor_tx IS NOT NULL").fetchone()["cnt"]

        actions = {}
        for row in self._conn.execute("SELECT action_type, COUNT(*) as cnt FROM receipts GROUP BY action_type"):
            actions[row["action_type"]] = row["cnt"]

        return {
            "total_receipts": total,
            "agents": agents,
            "batched_receipts": batched,
            "merkle_batches": batches,
            "anchored_batches": anchored,
            "action_types": actions,
        }

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
