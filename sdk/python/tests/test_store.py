"""
RCPT Receipt Store — Test Suite

Tests SQLite storage, querying, Merkle batching, and export.
"""

import json
import os
import tempfile
import unittest

from rcpt import RCPTClient, ActionType, ReceiptStore, Delegation


class TestStoreBasic(unittest.TestCase):
    def setUp(self):
        self.client = RCPTClient()
        self.store = ReceiptStore(":memory:")

    def tearDown(self):
        self.store.close()

    def test_attest_and_get(self):
        r = self.store.attest(self.client, action_type=ActionType.INFERENCE, output="hello")
        got = self.store.get(r.receipt_id)
        self.assertIsNotNone(got)
        self.assertEqual(got.receipt_id, r.receipt_id)
        self.assertEqual(got.output_hash, r.output_hash)

    def test_get_nonexistent(self):
        self.assertIsNone(self.store.get("nonexistent"))

    def test_store_many(self):
        receipts = [
            self.client.attest(action_type=ActionType.INFERENCE, output=f"msg-{i}")
            for i in range(10)
        ]
        self.store.store_many(receipts)
        self.assertEqual(self.store.count(), 10)

    def test_count(self):
        for i in range(5):
            self.store.attest(self.client, action_type=ActionType.INFERENCE, output=f"msg-{i}")
        self.assertEqual(self.store.count(), 5)
        self.assertEqual(self.store.count(agent_id=self.client.agent_id), 5)

    def test_upsert(self):
        r = self.store.attest(self.client, action_type=ActionType.INFERENCE, output="test")
        self.store.store(r)  # Should not raise
        self.assertEqual(self.store.count(), 1)


class TestStoreQuery(unittest.TestCase):
    def setUp(self):
        self.client = RCPTClient()
        self.client2 = RCPTClient()
        self.store = ReceiptStore(":memory:")

        # Store mixed receipts
        for i in range(5):
            self.store.attest(self.client, action_type=ActionType.INFERENCE, output=f"inf-{i}", model="claude-sonnet-4-5")
        for i in range(3):
            self.store.attest(self.client, action_type=ActionType.TOOL_CALL, output=f"tool-{i}")
        for i in range(2):
            self.store.attest(self.client2, action_type=ActionType.INFERENCE, output=f"other-{i}")

    def tearDown(self):
        self.store.close()

    def test_query_all(self):
        results = self.store.query(limit=100)
        self.assertEqual(len(results), 10)

    def test_query_by_agent(self):
        results = self.store.query(agent_id=self.client.agent_id)
        self.assertEqual(len(results), 8)

    def test_query_by_action_type(self):
        results = self.store.query(action_type="tool_call")
        self.assertEqual(len(results), 3)

    def test_query_combined(self):
        results = self.store.query(agent_id=self.client.agent_id, action_type="inference")
        self.assertEqual(len(results), 5)

    def test_query_limit(self):
        results = self.store.query(limit=3)
        self.assertEqual(len(results), 3)

    def test_agents(self):
        agents = self.store.agents()
        self.assertEqual(len(agents), 2)
        self.assertEqual(agents[0]["receipt_count"], 8)  # client1 has more


class TestStoreChain(unittest.TestCase):
    def setUp(self):
        self.client = RCPTClient()
        self.store = ReceiptStore(":memory:")

    def tearDown(self):
        self.store.close()

    def test_get_chain(self):
        r1 = self.store.attest(self.client, action_type=ActionType.INFERENCE, output="step 1")
        r2 = self.store.attest(self.client, action_type=ActionType.TOOL_CALL, output="step 2", parent=r1.receipt_id)
        r3 = self.store.attest(self.client, action_type=ActionType.INFERENCE, output="step 3", parent=r2.receipt_id)

        chain = self.store.get_chain(r3.receipt_id)
        self.assertEqual(len(chain), 3)
        self.assertEqual(chain[0].receipt_id, r1.receipt_id)
        self.assertEqual(chain[2].receipt_id, r3.receipt_id)

    def test_chain_single(self):
        r = self.store.attest(self.client, action_type=ActionType.INFERENCE, output="solo")
        chain = self.store.get_chain(r.receipt_id)
        self.assertEqual(len(chain), 1)


class TestStoreMerkle(unittest.TestCase):
    def setUp(self):
        self.client = RCPTClient()
        self.store = ReceiptStore(":memory:")

    def tearDown(self):
        self.store.close()

    def test_create_batch(self):
        for i in range(10):
            self.store.attest(self.client, action_type=ActionType.INFERENCE, output=f"msg-{i}")

        root, count = self.store.create_merkle_batch()
        self.assertEqual(count, 10)
        self.assertTrue(root.startswith("sha256:"))

    def test_batch_marks_receipts(self):
        for i in range(5):
            self.store.attest(self.client, action_type=ActionType.INFERENCE, output=f"msg-{i}")

        self.store.create_merkle_batch()

        # Second batch should have 0 receipts (all are batched)
        _, count2 = self.store.create_merkle_batch()
        self.assertEqual(count2, 0)

    def test_batch_list(self):
        for i in range(5):
            self.store.attest(self.client, action_type=ActionType.INFERENCE, output=f"msg-{i}")
        self.store.create_merkle_batch()

        batches = self.store.get_batches()
        self.assertEqual(len(batches), 1)
        self.assertEqual(batches[0]["receipt_count"], 5)

    def test_mark_anchored(self):
        for i in range(3):
            self.store.attest(self.client, action_type=ActionType.INFERENCE, output=f"msg-{i}")
        self.store.create_merkle_batch()

        batches = self.store.get_batches()
        self.store.mark_anchored(batches[0]["batch_id"], "5qKLz9...txhash")

        updated = self.store.get_batches()
        self.assertIsNotNone(updated[0]["anchored_at"])
        self.assertEqual(updated[0]["anchor_tx"], "5qKLz9...txhash")

    def test_empty_batch(self):
        root, count = self.store.create_merkle_batch()
        self.assertEqual(root, "")
        self.assertEqual(count, 0)


class TestStoreExport(unittest.TestCase):
    def setUp(self):
        self.client = RCPTClient()
        self.store = ReceiptStore(":memory:")

    def tearDown(self):
        self.store.close()

    def test_export_json(self):
        for i in range(5):
            self.store.attest(self.client, action_type=ActionType.INFERENCE, output=f"msg-{i}")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            count = self.store.export_json(path)
            self.assertEqual(count, 5)
            with open(path) as f:
                data = json.load(f)
            self.assertEqual(len(data), 5)
        finally:
            os.unlink(path)

    def test_export_all(self):
        for i in range(3):
            self.store.attest(self.client, action_type=ActionType.INFERENCE, output=f"msg-{i}")
        data = self.store.export_all()
        self.assertEqual(len(data), 3)

    def test_export_json_no_silent_truncation(self):
        """export_json must return ALL receipts, not just the first 100."""
        for i in range(105):
            self.store.attest(self.client, action_type=ActionType.INFERENCE, output=f"bulk-{i}")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            count = self.store.export_json(path)
            self.assertEqual(count, 105, "export_json silently capped at 100 — bug not fixed")
            with open(path) as f:
                data = json.load(f)
            self.assertEqual(len(data), 105)
        finally:
            os.unlink(path)


class TestStoreStats(unittest.TestCase):
    def test_stats(self):
        client = RCPTClient()
        store = ReceiptStore(":memory:")

        for i in range(5):
            store.attest(client, action_type=ActionType.INFERENCE, output=f"inf-{i}")
        for i in range(3):
            store.attest(client, action_type=ActionType.TOOL_CALL, output=f"tool-{i}")
        store.create_merkle_batch()

        s = store.stats()
        self.assertEqual(s["total_receipts"], 8)
        self.assertEqual(s["agents"], 1)
        self.assertEqual(s["batched_receipts"], 8)
        self.assertEqual(s["merkle_batches"], 1)
        self.assertEqual(s["action_types"]["inference"], 5)
        self.assertEqual(s["action_types"]["tool_call"], 3)
        store.close()


class TestStorePersistence(unittest.TestCase):
    def test_file_persistence(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            path = f.name

        try:
            client = RCPTClient()

            # Write
            store1 = ReceiptStore(path)
            r = store1.attest(client, action_type=ActionType.INFERENCE, output="persisted")
            store1.close()

            # Read back
            store2 = ReceiptStore(path)
            got = store2.get(r.receipt_id)
            self.assertIsNotNone(got)
            self.assertEqual(got.receipt_id, r.receipt_id)
            store2.close()
        finally:
            os.unlink(path)

    def test_context_manager(self):
        with ReceiptStore(":memory:") as store:
            client = RCPTClient()
            store.attest(client, action_type=ActionType.INFERENCE, output="ctx")
            self.assertEqual(store.count(), 1)


if __name__ == "__main__":
    unittest.main()
