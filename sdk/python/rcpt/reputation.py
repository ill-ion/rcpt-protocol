"""
RCPT Reputation Engine

Computes agent reputation scores from receipt history per the RCPT v0.1 spec (Section 9).

Algorithm:
    reputation = weighted_sum(
        volume_score       * 0.20,
        consistency_score  * 0.25,
        age_score          * 0.15,
        verification_rate  * 0.20,
        dispute_rate       * 0.20
    )

Score range: 0-100.
Trust levels: Unverified (0-20), Emerging (21-40), Established (41-60),
              Trusted (61-80), Authority (81-100).

Usage:
    from rcpt import RCPTClient
    from rcpt.reputation import ReputationEngine

    client = RCPTClient()
    engine = ReputationEngine()

    # Feed receipts
    for receipt in receipts:
        engine.add_receipt(receipt)

    # Mark some as externally verified
    engine.mark_verified(receipt_id)

    # Compute score
    score = engine.score("did:key:z6Mk...")
    print(score)
    # ReputationScore(score=72.5, level="Trusted", breakdown={...})
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from rcpt.models import Receipt


# ── Trust Levels ────────────────────────────────────────────────────────────

TRUST_LEVELS = [
    (0, 20, "Unverified", "New or untested agent"),
    (21, 40, "Emerging", "Some history, limited verification"),
    (41, 60, "Established", "Consistent history, some third-party verification"),
    (61, 80, "Trusted", "Strong history, low disputes, regularly verified"),
    (81, 100, "Authority", "Extensive history, zero disputes, widely verified"),
]


def trust_level(score: float) -> tuple[str, str]:
    """Return (level_name, description) for a given score."""
    clamped = max(0, min(100, score))
    for low, high, name, desc in TRUST_LEVELS:
        if low <= clamped <= high:
            return name, desc
    return "Unverified", "New or untested agent"


# ── Score Components ────────────────────────────────────────────────────────

@dataclass
class ScoreBreakdown:
    """Individual component scores before weighting."""
    volume_score: float = 0.0
    consistency_score: float = 0.0
    age_score: float = 0.0
    verification_rate: float = 0.0
    dispute_rate: float = 0.0

    def to_dict(self) -> dict:
        return {
            "volume_score": round(self.volume_score, 4),
            "consistency_score": round(self.consistency_score, 4),
            "age_score": round(self.age_score, 4),
            "verification_rate": round(self.verification_rate, 4),
            "dispute_rate": round(self.dispute_rate, 4),
        }


@dataclass
class ReputationScore:
    """Computed reputation score for an agent."""
    agent_id: str
    score: float
    level: str
    level_description: str
    breakdown: ScoreBreakdown
    total_receipts: int
    verified_receipts: int
    disputed_receipts: int
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "score": round(self.score, 2),
            "level": self.level,
            "level_description": self.level_description,
            "breakdown": self.breakdown.to_dict(),
            "total_receipts": self.total_receipts,
            "verified_receipts": self.verified_receipts,
            "disputed_receipts": self.disputed_receipts,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


# ── Agent State ─────────────────────────────────────────────────────────────

@dataclass
class _AgentState:
    """Internal tracking state for a single agent."""
    receipts: List[Receipt] = field(default_factory=list)
    verified_ids: Set[str] = field(default_factory=set)
    disputed_ids: Set[str] = field(default_factory=set)
    first_timestamp: Optional[datetime] = None
    last_timestamp: Optional[datetime] = None


# ── Weights ─────────────────────────────────────────────────────────────────

DEFAULT_WEIGHTS = {
    "volume": 0.20,
    "consistency": 0.25,
    "age": 0.15,
    "verification": 0.20,
    "dispute": 0.20,
}


# ── Engine ──────────────────────────────────────────────────────────────────

class ReputationEngine:
    """
    Computes agent reputation scores from RCPT receipt history.

    Thread-safe for reads; add_receipt/mark_verified/mark_disputed
    should be called from a single thread or externally synchronized.
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        """
        Args:
            weights: Override default scoring weights.
                     Keys: volume, consistency, age, verification, dispute.
                     Values must sum to 1.0.
        """
        self.weights = weights or dict(DEFAULT_WEIGHTS)
        self._agents: Dict[str, _AgentState] = {}

    def _ensure_agent(self, agent_id: str) -> _AgentState:
        if agent_id not in self._agents:
            self._agents[agent_id] = _AgentState()
        return self._agents[agent_id]

    def add_receipt(self, receipt: Receipt) -> None:
        """
        Add a receipt to the engine for reputation computation.

        Args:
            receipt: A verified Receipt object. The engine does NOT verify
                     signatures — callers should verify before adding.
        """
        state = self._ensure_agent(receipt.agent_id)
        state.receipts.append(receipt)

        ts = _parse_timestamp(receipt.timestamp)
        if ts:
            if state.first_timestamp is None or ts < state.first_timestamp:
                state.first_timestamp = ts
            if state.last_timestamp is None or ts > state.last_timestamp:
                state.last_timestamp = ts

    def add_receipts(self, receipts: List[Receipt]) -> None:
        """Add multiple receipts at once."""
        for r in receipts:
            self.add_receipt(r)

    def mark_verified(self, receipt_id: str, agent_id: Optional[str] = None) -> None:
        """
        Mark a receipt as externally verified (e.g., by a third-party auditor
        or on-chain Merkle proof verification).

        Args:
            receipt_id: The receipt ID that was verified.
            agent_id: Agent ID (optional; auto-detected if receipt is known).
        """
        if agent_id:
            state = self._ensure_agent(agent_id)
            state.verified_ids.add(receipt_id)
        else:
            # Find which agent owns this receipt
            for aid, state in self._agents.items():
                for r in state.receipts:
                    if r.receipt_id == receipt_id:
                        state.verified_ids.add(receipt_id)
                        return

    def mark_disputed(self, receipt_id: str, agent_id: Optional[str] = None) -> None:
        """
        Mark a receipt as disputed (e.g., output didn't match claimed intent,
        or the action was unauthorized).

        Args:
            receipt_id: The receipt ID being disputed.
            agent_id: Agent ID (optional; auto-detected if receipt is known).
        """
        if agent_id:
            state = self._ensure_agent(agent_id)
            state.disputed_ids.add(receipt_id)
        else:
            for aid, state in self._agents.items():
                for r in state.receipts:
                    if r.receipt_id == receipt_id:
                        state.disputed_ids.add(receipt_id)
                        return

    def score(
        self,
        agent_id: str,
        as_of: Optional[datetime] = None,
    ) -> ReputationScore:
        """
        Compute the reputation score for an agent.

        Args:
            agent_id: The agent's DID.
            as_of: Compute score as of this datetime (default: now UTC).

        Returns:
            ReputationScore with score, level, and detailed breakdown.
        """
        state = self._agents.get(agent_id)
        if state is None or len(state.receipts) == 0:
            return ReputationScore(
                agent_id=agent_id,
                score=0.0,
                level="Unverified",
                level_description="New or untested agent",
                breakdown=ScoreBreakdown(),
                total_receipts=0,
                verified_receipts=0,
                disputed_receipts=0,
            )

        now = as_of or datetime.now(timezone.utc)
        total = len(state.receipts)
        verified = len(state.verified_ids)
        disputed = len(state.disputed_ids)

        # ── 1. Volume Score ─────────────────────────────────────────────
        # min(1.0, log10(total_receipts) / 4) — caps at 10,000
        if total <= 0:
            volume = 0.0
        else:
            volume = min(1.0, math.log10(total) / 4.0)

        # ── 2. Consistency Score ────────────────────────────────────────
        # Fraction of receipts that are part of a complete chain
        # (have either a parent or are a root that has children)
        chained = 0
        receipt_ids = {r.receipt_id for r in state.receipts}
        parent_ids = set()
        for r in state.receipts:
            if r.chain and r.chain.parent_receipt_id:
                parent = r.chain.parent_receipt_id
                if isinstance(parent, list):
                    parent_ids.update(parent)
                else:
                    parent_ids.add(parent)

        for r in state.receipts:
            has_parent = (
                r.chain is not None
                and r.chain.parent_receipt_id is not None
            )
            is_parent = r.receipt_id in parent_ids
            if has_parent or is_parent:
                chained += 1

        consistency = chained / total if total > 0 else 0.0

        # ── 3. Age Score ────────────────────────────────────────────────
        # min(1.0, days_since_first_receipt / 365)
        if state.first_timestamp:
            days = (now - state.first_timestamp).total_seconds() / 86400
            age = min(1.0, days / 365.0)
        else:
            age = 0.0

        # ── 4. Verification Rate ────────────────────────────────────────
        # Fraction of receipts verified by third parties
        verification = verified / total if total > 0 else 0.0

        # ── 5. Dispute Rate ─────────────────────────────────────────────
        # 1.0 - (disputed_receipts / total_receipts)
        dispute = 1.0 - (disputed / total) if total > 0 else 1.0

        # ── Weighted Sum ────────────────────────────────────────────────
        raw = (
            volume * self.weights["volume"]
            + consistency * self.weights["consistency"]
            + age * self.weights["age"]
            + verification * self.weights["verification"]
            + dispute * self.weights["dispute"]
        )
        final_score = round(raw * 100, 2)

        level_name, level_desc = trust_level(final_score)

        breakdown = ScoreBreakdown(
            volume_score=volume,
            consistency_score=consistency,
            age_score=age,
            verification_rate=verification,
            dispute_rate=dispute,
        )

        return ReputationScore(
            agent_id=agent_id,
            score=final_score,
            level=level_name,
            level_description=level_desc,
            breakdown=breakdown,
            total_receipts=total,
            verified_receipts=verified,
            disputed_receipts=disputed,
            first_seen=state.first_timestamp.isoformat() if state.first_timestamp else None,
            last_seen=state.last_timestamp.isoformat() if state.last_timestamp else None,
        )

    def leaderboard(self, top_n: int = 10) -> List[ReputationScore]:
        """
        Get the top agents by reputation score.

        Args:
            top_n: Number of agents to return.

        Returns:
            List of ReputationScore, sorted descending.
        """
        scores = [self.score(aid) for aid in self._agents]
        scores.sort(key=lambda s: s.score, reverse=True)
        return scores[:top_n]

    def all_agents(self) -> List[str]:
        """List all tracked agent DIDs."""
        return list(self._agents.keys())

    def reset(self) -> None:
        """Clear all tracked state."""
        self._agents.clear()


def _parse_timestamp(ts: str) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp string."""
    try:
        # Handle "2026-02-21T02:25:48.513Z" format
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except (ValueError, AttributeError):
        return None
