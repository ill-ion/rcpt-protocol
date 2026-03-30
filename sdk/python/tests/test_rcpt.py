"""
RCPT Protocol — Test Suite

Covers:
1. Key generation (Ed25519)
2. Attestation (receipt creation + signing)
3. Verification (signature validation)
4. Tamper detection (modified receipt fails verification)
5. Receipt chaining (parent_receipt_id linkage)
6. JSON roundtrip (serialize/deserialize)
7. Merkle proofs (build tree, generate proof, verify proof)
8. Receipt schema compliance (7 required fields present)

Plus additional edge-case and integration tests.
"""

import json
import unittest
import copy

from rcpt import (
    RCPTClient,
    Receipt,
    ActionType,
    Model,
    Framework,
    Chain,
    Delegation,
    Anchor,
    Metadata,
    generate_keypair,
    sign_receipt,
    verify_receipt,
    hash_content,
    hash_receipt_canonical,
)
from rcpt.hashing import (
    build_merkle_tree,
    get_merkle_proof,
    verify_merkle_proof,
    canonical_serialize,
)
from rcpt.models import generate_ulid, now_iso8601


class TestKeyGeneration(unittest.TestCase):
    """1. Key generation (Ed25519)"""

    def test_generate_keypair_returns_three_parts(self):
        private_key, public_key, did = generate_keypair()
        self.assertIsInstance(private_key, str)
        self.assertIsInstance(public_key, str)
        self.assertIsInstance(did, str)

    def test_keypair_did_format(self):
        _, _, did = generate_keypair()
        self.assertTrue(did.startswith("did:key:z6Mk"), f"DID should start with did:key:z6Mk, got: {did}")

    def test_keypairs_are_unique(self):
        _, pub1, did1 = generate_keypair()
        _, pub2, did2 = generate_keypair()
        self.assertNotEqual(pub1, pub2)
        self.assertNotEqual(did1, did2)

    def test_client_generates_keypair_when_none_provided(self):
        client = RCPTClient()
        self.assertTrue(client.agent_id.startswith("did:key:z"))
        self.assertIsInstance(client.public_key, str)


class TestAttestation(unittest.TestCase):
    """2. Attestation (receipt creation + signing)"""

    def setUp(self):
        self.client = RCPTClient()

    def test_basic_attestation(self):
        receipt = self.client.attest(
            action_type=ActionType.INFERENCE,
            output="Hello world",
        )
        self.assertIsInstance(receipt, Receipt)
        self.assertEqual(receipt.rcpt_version, "0.1")
        self.assertEqual(receipt.action_type, "inference")
        self.assertTrue(receipt.signature.startswith("ed25519:"))

    def test_attestation_with_model_string(self):
        receipt = self.client.attest(
            action_type=ActionType.INFERENCE,
            output="Response text",
            model="claude-sonnet-4-5",
        )
        self.assertEqual(receipt.model.provider, "anthropic")
        self.assertEqual(receipt.model.model_id, "claude-sonnet-4-5")

    def test_attestation_with_model_provider_slash(self):
        receipt = self.client.attest(
            action_type=ActionType.INFERENCE,
            output="Response text",
            model="openai/gpt-4o",
        )
        self.assertEqual(receipt.model.provider, "openai")
        self.assertEqual(receipt.model.model_id, "gpt-4o")

    def test_attestation_with_model_object(self):
        receipt = self.client.attest(
            action_type=ActionType.INFERENCE,
            output="Response",
            model=Model(provider="anthropic", model_id="claude-opus-4-5", version="20250514"),
        )
        self.assertEqual(receipt.model.version, "20250514")

    def test_attestation_with_input_data(self):
        receipt = self.client.attest(
            action_type=ActionType.INFERENCE,
            output="Hello",
            input_data="What is 2+2?",
        )
        self.assertIsNotNone(receipt.input_hash)
        self.assertTrue(receipt.input_hash.startswith("sha256:"))

    def test_attestation_with_parameters(self):
        receipt = self.client.attest(
            action_type=ActionType.INFERENCE,
            output="Hello",
            parameters={"temperature": 0.7, "max_tokens": 1000},
        )
        self.assertIsNotNone(receipt.parameters_hash)

    def test_attestation_with_framework(self):
        receipt = self.client.attest(
            action_type=ActionType.TOOL_CALL,
            output="result",
            framework="langchain",
        )
        self.assertEqual(receipt.framework.name, "langchain")

    def test_attestation_with_delegation(self):
        receipt = self.client.attest(
            action_type=ActionType.DELEGATION,
            output="delegated",
            delegation=Delegation(
                delegator_id="did:web:company.com:users:jane",
                scope=["read:documents"],
                expires="2026-12-31T23:59:59.000Z",
            ),
        )
        self.assertEqual(receipt.delegation.delegator_id, "did:web:company.com:users:jane")

    def test_attestation_with_metadata_dict(self):
        receipt = self.client.attest(
            action_type=ActionType.INFERENCE,
            output="Hello",
            metadata={"description": "Test receipt", "tags": ["test", "unit"]},
        )
        self.assertEqual(receipt.metadata.description, "Test receipt")
        self.assertEqual(receipt.metadata.tags, ["test", "unit"])

    def test_attestation_metadata_extra_field_preserved(self):
        """Extra metadata fields must survive attest() and JSON roundtrip."""
        receipt = self.client.attest(
            action_type=ActionType.INFERENCE,
            output="test",
            metadata={"description": "Test", "custom_key": "custom_value", "tags": ["x"]},
        )
        self.assertEqual(receipt.metadata.extra, {"custom_key": "custom_value"})
        # Roundtrip
        restored = Receipt.from_json(receipt.to_json())
        self.assertEqual(restored.metadata.extra, {"custom_key": "custom_value"})
        # Signature still verifies after roundtrip
        self.assertTrue(self.client.verify(restored))

    def test_attestation_with_metadata_object(self):
        receipt = self.client.attest(
            action_type=ActionType.OBSERVATION,
            output="Observed something",
            metadata=Metadata(description="Observation", compliance=["EU-AI-Act-Art-12"]),
        )
        self.assertEqual(receipt.metadata.compliance, ["EU-AI-Act-Art-12"])

    def test_all_action_types(self):
        for action_type in ActionType:
            receipt = self.client.attest(
                action_type=action_type,
                output=f"Output for {action_type.value}",
            )
            self.assertEqual(receipt.action_type, action_type.value)

    def test_attestation_string_action_type(self):
        receipt = self.client.attest(
            action_type="custom",
            output="Custom action",
        )
        self.assertEqual(receipt.action_type, "custom")

    def test_output_hash_deterministic(self):
        r1 = self.client.attest(action_type=ActionType.INFERENCE, output="Same text")
        r2 = self.client.attest(action_type=ActionType.INFERENCE, output="Same text")
        self.assertEqual(r1.output_hash, r2.output_hash)

    def test_output_hash_differs_for_different_content(self):
        r1 = self.client.attest(action_type=ActionType.INFERENCE, output="Text A")
        r2 = self.client.attest(action_type=ActionType.INFERENCE, output="Text B")
        self.assertNotEqual(r1.output_hash, r2.output_hash)

    def test_receipt_ids_are_unique(self):
        r1 = self.client.attest(action_type=ActionType.INFERENCE, output="A")
        r2 = self.client.attest(action_type=ActionType.INFERENCE, output="B")
        self.assertNotEqual(r1.receipt_id, r2.receipt_id)

    def test_receipt_id_is_ulid_format(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="test")
        self.assertEqual(len(receipt.receipt_id), 26)

    def test_agent_id_matches_client(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="test")
        self.assertEqual(receipt.agent_id, self.client.agent_id)


class TestVerification(unittest.TestCase):
    """3. Verification (signature validation)"""

    def setUp(self):
        self.client = RCPTClient()

    def test_verify_valid_receipt(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Hello")
        self.assertTrue(self.client.verify(receipt))

    def test_verify_from_json_string(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Hello")
        json_str = receipt.to_json()
        self.assertTrue(self.client.verify(json_str))

    def test_verify_from_dict(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Hello")
        d = receipt.to_dict()
        self.assertTrue(self.client.verify(d))

    def test_verify_receipt_with_all_optional_fields(self):
        receipt = self.client.attest(
            action_type=ActionType.TOOL_CALL,
            output="API response",
            input_data="query params",
            parameters={"timeout": 30},
            model="claude-sonnet-4-5",
            framework="langchain",
            workflow_id="wf-001",
            metadata={"description": "Full receipt test"},
        )
        self.assertTrue(self.client.verify(receipt))

    def test_cross_client_verification(self):
        """A receipt from one client can be verified by another."""
        client_a = RCPTClient()
        receipt = client_a.attest(action_type=ActionType.INFERENCE, output="Hello")
        client_b = RCPTClient()
        self.assertTrue(client_b.verify(receipt))


class TestTamperDetection(unittest.TestCase):
    """4. Tamper detection (modified receipt fails verification)"""

    def setUp(self):
        self.client = RCPTClient()

    def test_tampered_output_hash(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Original")
        receipt.output_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        self.assertFalse(self.client.verify(receipt))

    def test_tampered_action_type(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Test")
        receipt.action_type = "tool_call"
        self.assertFalse(self.client.verify(receipt))

    def test_tampered_agent_id(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Test")
        _, _, other_did = generate_keypair()
        receipt.agent_id = other_did
        self.assertFalse(self.client.verify(receipt))

    def test_tampered_timestamp(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Test")
        receipt.timestamp = "2020-01-01T00:00:00.000Z"
        self.assertFalse(self.client.verify(receipt))

    def test_tampered_receipt_id(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Test")
        receipt.receipt_id = generate_ulid()
        self.assertFalse(self.client.verify(receipt))

    def test_empty_signature_fails(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Test")
        receipt.signature = ""
        self.assertFalse(self.client.verify(receipt))

    def test_invalid_signature_prefix(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Test")
        receipt.signature = "rsa256:" + receipt.signature.split(":")[1]
        self.assertFalse(self.client.verify(receipt))

    def test_corrupted_signature_bytes(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Test")
        receipt.signature = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        self.assertFalse(self.client.verify(receipt))


class TestReceiptChaining(unittest.TestCase):
    """5. Receipt chaining (parent_receipt_id linkage)"""

    def setUp(self):
        self.client = RCPTClient()

    def test_single_parent_chain(self):
        r1 = self.client.attest(action_type=ActionType.INFERENCE, output="Step 1")
        r2 = self.client.attest(
            action_type=ActionType.TOOL_CALL,
            output="Step 2",
            parent=r1.receipt_id,
        )
        self.assertIsNotNone(r2.chain)
        self.assertEqual(r2.chain.parent_receipt_id, r1.receipt_id)

    def test_multi_step_chain(self):
        r1 = self.client.attest(action_type=ActionType.INFERENCE, output="Step 1")
        r2 = self.client.attest(action_type=ActionType.TOOL_CALL, output="Step 2", parent=r1.receipt_id)
        r3 = self.client.attest(action_type=ActionType.INFERENCE, output="Step 3", parent=r2.receipt_id)
        self.assertEqual(r3.chain.parent_receipt_id, r2.receipt_id)

    def test_workflow_id_assignment(self):
        r1 = self.client.attest(
            action_type=ActionType.INFERENCE,
            output="Start",
            workflow_id="wf-test-123",
        )
        self.assertEqual(r1.chain.workflow_id, "wf-test-123")

    def test_workflow_id_auto_generated(self):
        r1 = self.client.attest(
            action_type=ActionType.INFERENCE,
            output="Start",
            parent="some-parent-id",
        )
        self.assertIsNotNone(r1.chain.workflow_id)
        self.assertEqual(len(r1.chain.workflow_id), 26)

    def test_chained_receipts_verify(self):
        r1 = self.client.attest(action_type=ActionType.INFERENCE, output="Step 1")
        r2 = self.client.attest(action_type=ActionType.TOOL_CALL, output="Step 2", parent=r1.receipt_id)
        self.assertTrue(self.client.verify(r1))
        self.assertTrue(self.client.verify(r2))

    def test_get_chain_walks_backward(self):
        r1 = self.client.attest(action_type=ActionType.INFERENCE, output="Step 1")
        r2 = self.client.attest(action_type=ActionType.TOOL_CALL, output="Step 2", parent=r1.receipt_id)
        r3 = self.client.attest(action_type=ActionType.INFERENCE, output="Step 3", parent=r2.receipt_id)
        chain = self.client.get_chain(r3.receipt_id)
        self.assertEqual(len(chain), 3)
        self.assertEqual(chain[0].receipt_id, r1.receipt_id)
        self.assertEqual(chain[2].receipt_id, r3.receipt_id)

    def test_multi_parent_chain(self):
        """Multiple parent receipts (fan-in)."""
        r1 = self.client.attest(action_type=ActionType.INFERENCE, output="Branch A")
        r2 = self.client.attest(action_type=ActionType.INFERENCE, output="Branch B")
        r3 = self.client.attest(
            action_type=ActionType.INFERENCE,
            output="Merged",
            parent=[r1.receipt_id, r2.receipt_id],
        )
        self.assertEqual(r3.chain.parent_receipt_id, [r1.receipt_id, r2.receipt_id])
        self.assertTrue(self.client.verify(r3))

    def test_sequence_numbers(self):
        r1 = self.client.attest(
            action_type=ActionType.INFERENCE,
            output="Step 1",
            workflow_id="wf-seq",
            sequence=0,
        )
        r2 = self.client.attest(
            action_type=ActionType.TOOL_CALL,
            output="Step 2",
            parent=r1.receipt_id,
            workflow_id="wf-seq",
            sequence=1,
        )
        self.assertEqual(r1.chain.sequence, 0)
        self.assertEqual(r2.chain.sequence, 1)


class TestJSONRoundtrip(unittest.TestCase):
    """6. JSON roundtrip (serialize/deserialize)"""

    def setUp(self):
        self.client = RCPTClient()

    def test_basic_roundtrip(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Hello")
        json_str = receipt.to_json()
        restored = Receipt.from_json(json_str)
        self.assertEqual(receipt.receipt_id, restored.receipt_id)
        self.assertEqual(receipt.signature, restored.signature)
        self.assertEqual(receipt.output_hash, restored.output_hash)
        self.assertEqual(receipt.agent_id, restored.agent_id)

    def test_roundtrip_preserves_all_fields(self):
        receipt = self.client.attest(
            action_type=ActionType.TOOL_CALL,
            output="API response",
            input_data="query",
            parameters={"timeout": 30},
            model="claude-sonnet-4-5",
            framework=Framework(name="langchain", version="0.2.0"),
            parent="parent-id",
            workflow_id="wf-001",
            sequence=3,
            delegation=Delegation(
                delegator_id="did:web:example.com:users:alice",
                scope=["read:all"],
                expires="2026-12-31T00:00:00.000Z",
            ),
            metadata=Metadata(
                description="Test",
                tags=["unit", "test"],
                ttl=3600,
                compliance=["EU-AI-Act-Art-12"],
            ),
        )
        json_str = receipt.to_json()
        restored = Receipt.from_json(json_str)

        self.assertEqual(restored.input_hash, receipt.input_hash)
        self.assertEqual(restored.parameters_hash, receipt.parameters_hash)
        self.assertEqual(restored.model.provider, "anthropic")
        self.assertEqual(restored.model.model_id, "claude-sonnet-4-5")
        self.assertEqual(restored.framework.name, "langchain")
        self.assertEqual(restored.framework.version, "0.2.0")
        self.assertEqual(restored.chain.parent_receipt_id, "parent-id")
        self.assertEqual(restored.chain.workflow_id, "wf-001")
        self.assertEqual(restored.chain.sequence, 3)
        self.assertEqual(restored.delegation.delegator_id, "did:web:example.com:users:alice")
        self.assertEqual(restored.delegation.scope, ["read:all"])
        self.assertEqual(restored.metadata.description, "Test")
        self.assertEqual(restored.metadata.tags, ["unit", "test"])
        self.assertEqual(restored.metadata.compliance, ["EU-AI-Act-Art-12"])

    def test_roundtrip_dict(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="test")
        d = receipt.to_dict()
        restored = Receipt.from_dict(d)
        self.assertEqual(receipt.receipt_id, restored.receipt_id)
        self.assertEqual(receipt.signature, restored.signature)

    def test_roundtrip_preserves_verification(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Verify me")
        json_str = receipt.to_json()
        restored = Receipt.from_json(json_str)
        self.assertTrue(self.client.verify(restored))

    def test_json_is_valid_json(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Test")
        json_str = receipt.to_json()
        parsed = json.loads(json_str)
        self.assertIsInstance(parsed, dict)

    def test_optional_fields_omitted_when_none(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Minimal")
        d = receipt.to_dict()
        self.assertNotIn("input_hash", d)
        self.assertNotIn("model", d)
        self.assertNotIn("chain", d)
        self.assertNotIn("delegation", d)
        self.assertNotIn("anchor", d)
        self.assertNotIn("metadata", d)


class TestMerkleProofs(unittest.TestCase):
    """7. Merkle proofs (build tree, generate proof, verify proof)"""

    def test_build_merkle_tree_single(self):
        hashes = [hash_content("single")]
        root, levels = build_merkle_tree(hashes)
        self.assertTrue(root.startswith("sha256:"))
        self.assertEqual(len(levels), 1)

    def test_build_merkle_tree_multiple(self):
        hashes = [hash_content(f"item-{i}") for i in range(4)]
        root, levels = build_merkle_tree(hashes)
        self.assertTrue(root.startswith("sha256:"))
        self.assertGreater(len(levels), 1)

    def test_merkle_root_deterministic(self):
        hashes = [hash_content(f"item-{i}") for i in range(4)]
        root1, _ = build_merkle_tree(hashes)
        root2, _ = build_merkle_tree(hashes)
        self.assertEqual(root1, root2)

    def test_merkle_root_order_independent(self):
        """Merkle tree sorts leaves, so order shouldn't matter."""
        hashes_a = [hash_content("a"), hash_content("b"), hash_content("c")]
        hashes_b = [hash_content("c"), hash_content("a"), hash_content("b")]
        root_a, _ = build_merkle_tree(hashes_a)
        root_b, _ = build_merkle_tree(hashes_b)
        self.assertEqual(root_a, root_b)

    def test_merkle_proof_and_verify(self):
        hashes = [hash_content(f"receipt-{i}") for i in range(8)]
        root, _ = build_merkle_tree(hashes)
        target = hashes[3]
        proof = get_merkle_proof(hashes, target)
        self.assertTrue(verify_merkle_proof(target, proof, root))

    def test_merkle_proof_invalid_leaf(self):
        hashes = [hash_content(f"receipt-{i}") for i in range(4)]
        root, _ = build_merkle_tree(hashes)
        target = hashes[0]
        proof = get_merkle_proof(hashes, target)
        fake_leaf = hash_content("not-in-tree")
        self.assertFalse(verify_merkle_proof(fake_leaf, proof, root))

    def test_merkle_proof_all_leaves(self):
        """Every leaf should have a valid proof."""
        hashes = [hash_content(f"item-{i}") for i in range(7)]
        root, _ = build_merkle_tree(hashes)
        for h in hashes:
            proof = get_merkle_proof(hashes, h)
            self.assertTrue(verify_merkle_proof(h, proof, root), f"Proof failed for {h}")

    def test_merkle_tree_empty_raises(self):
        with self.assertRaises(ValueError):
            build_merkle_tree([])

    def test_merkle_proof_missing_hash_raises(self):
        hashes = [hash_content(f"item-{i}") for i in range(4)]
        with self.assertRaises(ValueError):
            get_merkle_proof(hashes, hash_content("not-present"))

    def test_merkle_with_real_receipts(self):
        """End-to-end: attest receipts, build tree, verify proofs."""
        client = RCPTClient()
        receipts = [
            client.attest(action_type=ActionType.INFERENCE, output=f"output-{i}")
            for i in range(5)
        ]
        hashes = [hash_receipt_canonical(r.to_dict()) for r in receipts]
        root, _ = build_merkle_tree(hashes)
        for h in hashes:
            proof = get_merkle_proof(hashes, h)
            self.assertTrue(verify_merkle_proof(h, proof, root))


class TestSchemaCompliance(unittest.TestCase):
    """8. Receipt schema compliance (7 required fields present)"""

    REQUIRED_FIELDS = [
        "rcpt_version",
        "receipt_id",
        "timestamp",
        "agent_id",
        "action_type",
        "output_hash",
        "signature",
    ]

    def setUp(self):
        self.client = RCPTClient()

    def test_all_required_fields_present(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Test")
        d = receipt.to_dict()
        for field_name in self.REQUIRED_FIELDS:
            self.assertIn(field_name, d, f"Required field '{field_name}' missing from receipt")

    def test_required_fields_non_empty(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Test")
        d = receipt.to_dict()
        for field_name in self.REQUIRED_FIELDS:
            self.assertTrue(d[field_name], f"Required field '{field_name}' is empty")

    def test_rcpt_version_value(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Test")
        self.assertEqual(receipt.rcpt_version, "0.1")

    def test_receipt_id_format(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Test")
        self.assertEqual(len(receipt.receipt_id), 26)
        valid_chars = set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        self.assertTrue(all(c in valid_chars for c in receipt.receipt_id))

    def test_timestamp_format(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Test")
        self.assertTrue(receipt.timestamp.endswith("Z"))
        self.assertIn("T", receipt.timestamp)

    def test_agent_id_format(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Test")
        self.assertTrue(receipt.agent_id.startswith("did:key:z"))

    def test_output_hash_format(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Test")
        self.assertTrue(receipt.output_hash.startswith("sha256:"))
        hex_part = receipt.output_hash[7:]
        self.assertEqual(len(hex_part), 64)
        int(hex_part, 16)  # Should be valid hex

    def test_signature_format(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Test")
        self.assertTrue(receipt.signature.startswith("ed25519:"))

    def test_json_schema_field_count(self):
        receipt = self.client.attest(action_type=ActionType.INFERENCE, output="Minimal")
        d = receipt.to_dict()
        self.assertEqual(len(d), 7)


class TestHashing(unittest.TestCase):
    """Additional hashing tests."""

    def test_hash_string(self):
        h = hash_content("hello")
        self.assertTrue(h.startswith("sha256:"))
        self.assertEqual(len(h), 71)  # "sha256:" + 64 hex chars

    def test_hash_bytes(self):
        h = hash_content(b"hello")
        self.assertTrue(h.startswith("sha256:"))

    def test_hash_dict(self):
        h = hash_content({"key": "value"})
        self.assertTrue(h.startswith("sha256:"))

    def test_hash_list(self):
        h = hash_content([1, 2, 3])
        self.assertTrue(h.startswith("sha256:"))

    def test_hash_deterministic(self):
        h1 = hash_content("test")
        h2 = hash_content("test")
        self.assertEqual(h1, h2)

    def test_canonical_dict_key_order(self):
        """JCS should produce same output regardless of dict key order."""
        d1 = {"b": 2, "a": 1, "c": 3}
        d2 = {"c": 3, "a": 1, "b": 2}
        self.assertEqual(canonical_serialize(d1), canonical_serialize(d2))


class TestStorage(unittest.TestCase):
    """Storage backend tests."""

    def test_memory_store(self):
        client = RCPTClient(store="memory")
        r = client.attest(action_type=ActionType.INFERENCE, output="test")
        retrieved = client.get_receipt(r.receipt_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.receipt_id, r.receipt_id)

    def test_get_nonexistent_receipt(self):
        client = RCPTClient()
        self.assertIsNone(client.get_receipt("nonexistent"))

    def test_sqlite_store(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            client = RCPTClient(store=f"sqlite:///{db_path}")
            r = client.attest(action_type=ActionType.INFERENCE, output="stored")
            retrieved = client.get_receipt(r.receipt_id)
            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved.receipt_id, r.receipt_id)
            client.close()
        finally:
            os.unlink(db_path)

    def test_workflow_retrieval(self):
        client = RCPTClient()
        wf_id = "wf-test-retrieval"
        r1 = client.attest(action_type=ActionType.INFERENCE, output="A", workflow_id=wf_id)
        r2 = client.attest(action_type=ActionType.TOOL_CALL, output="B", parent=r1.receipt_id, workflow_id=wf_id)
        workflow = client.get_workflow(wf_id)
        self.assertEqual(len(workflow), 2)


class TestExport(unittest.TestCase):
    """Export functionality tests."""

    def test_json_export(self):
        client = RCPTClient()
        client.attest(action_type=ActionType.INFERENCE, output="test1")
        client.attest(action_type=ActionType.TOOL_CALL, output="test2")
        exported = client.export(format="json")
        data = json.loads(exported)
        self.assertEqual(len(data), 2)

    def test_eu_ai_act_export(self):
        client = RCPTClient()
        client.attest(action_type=ActionType.INFERENCE, output="test")
        exported = client.export(format="eu-ai-act")
        data = json.loads(exported)
        self.assertEqual(data["compliance_framework"], "EU AI Act (Regulation (EU) 2024/1689)")
        self.assertIn("Article 12", data["articles_covered"])
        self.assertEqual(data["total_receipts"], 1)


class TestHelpers(unittest.TestCase):
    """ULID and timestamp helpers."""

    def test_ulid_length(self):
        ulid = generate_ulid()
        self.assertEqual(len(ulid), 26)

    def test_ulid_uniqueness(self):
        ulids = {generate_ulid() for _ in range(100)}
        self.assertEqual(len(ulids), 100)

    def test_ulid_sortable(self):
        """ULIDs generated sequentially should sort in order."""
        import time
        u1 = generate_ulid()
        time.sleep(0.002)
        u2 = generate_ulid()
        self.assertLess(u1, u2)

    def test_now_iso8601_format(self):
        ts = now_iso8601()
        self.assertTrue(ts.endswith("Z"))
        self.assertIn("T", ts)


if __name__ == "__main__":
    unittest.main()
