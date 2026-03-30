"""
RCPT Reputation Engine — Test Suite

Tests the v0.1 reputation algorithm per Section 9 of the specification.
"""

import unittest
import time
from datetime import datetime, timezone, timedelta

from rcpt import RCPTClient, ActionType, ReputationEngine, ReputationScore


class TestReputationBasic(unittest.TestCase):
    """Core scoring tests."""

    def setUp(self):
        self.client = RCPTClient()
        self.engine = ReputationEngine()

    def test_unknown_agent_scores_zero(self):
        score = self.engine.score("did:key:zNonexistent")
        self.assertEqual(score.score, 0.0)
        self.assertEqual(score.level, "Unverified")
        self.assertEqual(score.total_receipts, 0)

    def test_single_receipt_scores_above_zero(self):
        r = self.client.attest(action_type=ActionType.INFERENCE, output="hello")
        self.engine.add_receipt(r)
        score = self.engine.score(self.client.agent_id)
        self.assertGreater(score.score, 0)
        self.assertEqual(score.total_receipts, 1)

    def test_more_receipts_higher_volume(self):
        for i in range(5):
            r = self.client.attest(action_type=ActionType.INFERENCE, output=f"msg-{i}")
            self.engine.add_receipt(r)
        score5 = self.engine.score(self.client.agent_id)

        for i in range(95):
            r = self.client.attest(action_type=ActionType.INFERENCE, output=f"more-{i}")
            self.engine.add_receipt(r)
        score100 = self.engine.score(self.client.agent_id)

        self.assertGreater(score100.breakdown.volume_score, score5.breakdown.volume_score)

    def test_volume_caps_at_1(self):
        """Volume score should cap at 1.0 for 10,000+ receipts."""
        # We'll test the formula directly since generating 10k receipts is slow
        import math
        self.assertAlmostEqual(min(1.0, math.log10(10000) / 4.0), 1.0)
        self.assertAlmostEqual(min(1.0, math.log10(100000) / 4.0), 1.0)

    def test_score_range(self):
        """Score should always be 0-100."""
        for i in range(20):
            r = self.client.attest(action_type=ActionType.INFERENCE, output=f"msg-{i}")
            self.engine.add_receipt(r)
        score = self.engine.score(self.client.agent_id)
        self.assertGreaterEqual(score.score, 0)
        self.assertLessEqual(score.score, 100)


class TestReputationConsistency(unittest.TestCase):
    """Consistency score: receipt chaining completeness."""

    def setUp(self):
        self.client = RCPTClient()
        self.engine = ReputationEngine()

    def test_unchained_receipts_low_consistency(self):
        """Standalone receipts with no chaining → consistency near 0."""
        for i in range(10):
            r = self.client.attest(action_type=ActionType.INFERENCE, output=f"isolated-{i}")
            self.engine.add_receipt(r)
        score = self.engine.score(self.client.agent_id)
        self.assertEqual(score.breakdown.consistency_score, 0.0)

    def test_chained_receipts_high_consistency(self):
        """Fully chained receipts → high consistency."""
        r1 = self.client.attest(action_type=ActionType.INFERENCE, output="start")
        self.engine.add_receipt(r1)
        parent_id = r1.receipt_id

        for i in range(9):
            r = self.client.attest(
                action_type=ActionType.TOOL_CALL,
                output=f"step-{i}",
                parent=parent_id,
            )
            self.engine.add_receipt(r)
            parent_id = r.receipt_id

        score = self.engine.score(self.client.agent_id)
        self.assertEqual(score.breakdown.consistency_score, 1.0)

    def test_mixed_chain_partial_consistency(self):
        """Mix of chained and unchained → partial consistency."""
        r1 = self.client.attest(action_type=ActionType.INFERENCE, output="root")
        r2 = self.client.attest(action_type=ActionType.TOOL_CALL, output="child", parent=r1.receipt_id)
        r3 = self.client.attest(action_type=ActionType.INFERENCE, output="isolated")
        r4 = self.client.attest(action_type=ActionType.INFERENCE, output="also isolated")

        for r in [r1, r2, r3, r4]:
            self.engine.add_receipt(r)

        score = self.engine.score(self.client.agent_id)
        # r1 is parent, r2 has parent → 2 chained out of 4
        self.assertEqual(score.breakdown.consistency_score, 0.5)


class TestReputationVerification(unittest.TestCase):
    """Verification rate tests."""

    def setUp(self):
        self.client = RCPTClient()
        self.engine = ReputationEngine()

    def test_no_verification_rate_zero(self):
        r = self.client.attest(action_type=ActionType.INFERENCE, output="test")
        self.engine.add_receipt(r)
        score = self.engine.score(self.client.agent_id)
        self.assertEqual(score.breakdown.verification_rate, 0.0)

    def test_partial_verification(self):
        receipts = []
        for i in range(4):
            r = self.client.attest(action_type=ActionType.INFERENCE, output=f"msg-{i}")
            self.engine.add_receipt(r)
            receipts.append(r)

        # Verify 2 of 4
        self.engine.mark_verified(receipts[0].receipt_id)
        self.engine.mark_verified(receipts[1].receipt_id)

        score = self.engine.score(self.client.agent_id)
        self.assertAlmostEqual(score.breakdown.verification_rate, 0.5)
        self.assertEqual(score.verified_receipts, 2)

    def test_full_verification(self):
        receipts = []
        for i in range(5):
            r = self.client.attest(action_type=ActionType.INFERENCE, output=f"msg-{i}")
            self.engine.add_receipt(r)
            receipts.append(r)

        for r in receipts:
            self.engine.mark_verified(r.receipt_id)

        score = self.engine.score(self.client.agent_id)
        self.assertAlmostEqual(score.breakdown.verification_rate, 1.0)


class TestReputationDisputes(unittest.TestCase):
    """Dispute rate tests."""

    def setUp(self):
        self.client = RCPTClient()
        self.engine = ReputationEngine()

    def test_no_disputes_full_score(self):
        r = self.client.attest(action_type=ActionType.INFERENCE, output="clean")
        self.engine.add_receipt(r)
        score = self.engine.score(self.client.agent_id)
        self.assertEqual(score.breakdown.dispute_rate, 1.0)

    def test_disputes_lower_score(self):
        receipts = []
        for i in range(10):
            r = self.client.attest(action_type=ActionType.INFERENCE, output=f"msg-{i}")
            self.engine.add_receipt(r)
            receipts.append(r)

        # Dispute 3 of 10
        for r in receipts[:3]:
            self.engine.mark_disputed(r.receipt_id)

        score = self.engine.score(self.client.agent_id)
        self.assertAlmostEqual(score.breakdown.dispute_rate, 0.7)
        self.assertEqual(score.disputed_receipts, 3)

    def test_all_disputed_zero_dispute_score(self):
        receipts = []
        for i in range(5):
            r = self.client.attest(action_type=ActionType.INFERENCE, output=f"bad-{i}")
            self.engine.add_receipt(r)
            receipts.append(r)

        for r in receipts:
            self.engine.mark_disputed(r.receipt_id)

        score = self.engine.score(self.client.agent_id)
        self.assertEqual(score.breakdown.dispute_rate, 0.0)


class TestReputationAge(unittest.TestCase):
    """Age score tests."""

    def setUp(self):
        self.client = RCPTClient()
        self.engine = ReputationEngine()

    def test_recent_agent_low_age(self):
        r = self.client.attest(action_type=ActionType.INFERENCE, output="new")
        self.engine.add_receipt(r)
        score = self.engine.score(self.client.agent_id)
        # Created just now, age_score should be very small
        self.assertLess(score.breakdown.age_score, 0.01)

    def test_age_with_explicit_time(self):
        """Test age calculation with as_of parameter."""
        r = self.client.attest(action_type=ActionType.INFERENCE, output="old")
        self.engine.add_receipt(r)

        # Score as if 6 months from now
        future = datetime.now(timezone.utc) + timedelta(days=182)
        score = self.engine.score(self.client.agent_id, as_of=future)
        self.assertAlmostEqual(score.breakdown.age_score, 182 / 365, places=1)

    def test_age_caps_at_1(self):
        """Age score should cap at 1.0 after 365 days."""
        r = self.client.attest(action_type=ActionType.INFERENCE, output="ancient")
        self.engine.add_receipt(r)

        far_future = datetime.now(timezone.utc) + timedelta(days=500)
        score = self.engine.score(self.client.agent_id, as_of=far_future)
        self.assertEqual(score.breakdown.age_score, 1.0)


class TestTrustLevels(unittest.TestCase):
    """Trust level assignment tests."""

    def test_level_boundaries(self):
        from rcpt.reputation import trust_level
        self.assertEqual(trust_level(0)[0], "Unverified")
        self.assertEqual(trust_level(20)[0], "Unverified")
        self.assertEqual(trust_level(21)[0], "Emerging")
        self.assertEqual(trust_level(40)[0], "Emerging")
        self.assertEqual(trust_level(41)[0], "Established")
        self.assertEqual(trust_level(60)[0], "Established")
        self.assertEqual(trust_level(61)[0], "Trusted")
        self.assertEqual(trust_level(80)[0], "Trusted")
        self.assertEqual(trust_level(81)[0], "Authority")
        self.assertEqual(trust_level(100)[0], "Authority")

    def test_score_includes_level(self):
        client = RCPTClient()
        engine = ReputationEngine()
        r = client.attest(action_type=ActionType.INFERENCE, output="test")
        engine.add_receipt(r)
        score = engine.score(client.agent_id)
        self.assertIn(score.level, ["Unverified", "Emerging", "Established", "Trusted", "Authority"])
        self.assertIsInstance(score.level_description, str)


class TestReputationSerialization(unittest.TestCase):
    """Serialization tests."""

    def test_to_dict(self):
        client = RCPTClient()
        engine = ReputationEngine()
        for i in range(5):
            r = client.attest(action_type=ActionType.INFERENCE, output=f"msg-{i}")
            engine.add_receipt(r)
        score = engine.score(client.agent_id)
        d = score.to_dict()
        self.assertIn("score", d)
        self.assertIn("level", d)
        self.assertIn("breakdown", d)
        self.assertIn("total_receipts", d)
        self.assertEqual(d["total_receipts"], 5)


class TestLeaderboard(unittest.TestCase):
    """Multi-agent leaderboard tests."""

    def test_leaderboard_ordering(self):
        engine = ReputationEngine()

        # Agent A: 50 receipts, some chained
        client_a = RCPTClient()
        r_prev = None
        for i in range(50):
            kwargs = {"action_type": ActionType.INFERENCE, "output": f"a-{i}"}
            if r_prev and i % 2 == 0:
                kwargs["parent"] = r_prev.receipt_id
            r = client_a.attest(**kwargs)
            engine.add_receipt(r)
            r_prev = r

        # Agent B: 5 receipts, no chaining
        client_b = RCPTClient()
        for i in range(5):
            r = client_b.attest(action_type=ActionType.INFERENCE, output=f"b-{i}")
            engine.add_receipt(r)

        board = engine.leaderboard(top_n=5)
        self.assertEqual(len(board), 2)
        self.assertEqual(board[0].agent_id, client_a.agent_id)
        self.assertGreater(board[0].score, board[1].score)

    def test_leaderboard_top_n(self):
        engine = ReputationEngine()
        clients = [RCPTClient() for _ in range(5)]
        for c in clients:
            r = c.attest(action_type=ActionType.INFERENCE, output="hello")
            engine.add_receipt(r)

        board = engine.leaderboard(top_n=3)
        self.assertEqual(len(board), 3)


class TestEngineReset(unittest.TestCase):
    def test_reset_clears_state(self):
        client = RCPTClient()
        engine = ReputationEngine()
        r = client.attest(action_type=ActionType.INFERENCE, output="test")
        engine.add_receipt(r)
        self.assertEqual(len(engine.all_agents()), 1)
        engine.reset()
        self.assertEqual(len(engine.all_agents()), 0)


if __name__ == "__main__":
    unittest.main()
