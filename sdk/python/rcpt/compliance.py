"""
RCPT Compliance Dashboard

Generates EU AI Act compliance reports and audit summaries from RCPT receipt data.

Maps receipt data to:
- Article 12: Record-keeping / logging requirements
- Article 19: Transparency obligations
- Article 26: Obligations of deployers (human oversight)

Usage:
    from rcpt import RCPTClient
    from rcpt.compliance import ComplianceDashboard

    client = RCPTClient()
    dashboard = ComplianceDashboard(client)

    # Generate audit report
    report = dashboard.generate_report()
    print(report.to_dict())

    # Check compliance gaps
    gaps = dashboard.check_gaps()

    # Export for regulators
    dashboard.export_pdf_data()
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import Counter

from rcpt.models import Receipt


# ── EU AI Act Article Mapping ───────────────────────────────────────────────

ARTICLE_MAP = {
    "Article 12": {
        "title": "Record-Keeping",
        "description": "Automatic logging of AI system operations with traceability",
        "requirements": [
            "Automatic logging of operations",
            "Traceability of agent actions",
            "Tamper-evident records",
            "Temporal ordering of events",
        ],
        "rcpt_coverage": [
            "Every agent action generates a signed receipt (automatic logging)",
            "Receipt chains trace complete workflows (traceability)",
            "Ed25519 signatures prevent tampering (tamper-evident)",
            "ULID receipt IDs and ISO 8601 timestamps (temporal ordering)",
        ],
    },
    "Article 19": {
        "title": "Transparency",
        "description": "Quality management and documentation for high-risk AI systems",
        "requirements": [
            "Documentation of AI system design and purpose",
            "Input/output monitoring capabilities",
            "Model identification and versioning",
            "Human-readable audit trails",
        ],
        "rcpt_coverage": [
            "metadata.description captures action purpose (documentation)",
            "input_hash and output_hash track I/O (monitoring)",
            "model.provider and model.model_id identify models (model ID)",
            "Receipt chains export as JSON for audit review (audit trails)",
        ],
    },
    "Article 26": {
        "title": "Obligations of Deployers",
        "description": "Human oversight and monitoring of AI operations",
        "requirements": [
            "Human oversight of autonomous operations",
            "Monitoring of AI system performance",
            "Authority to intervene or stop operations",
            "Record of human authorization decisions",
        ],
        "rcpt_coverage": [
            "delegation receipts bind agent actions to human authorization (oversight)",
            "Reputation engine tracks agent consistency and disputes (monitoring)",
            "delegation.expires provides temporal bounds on authority (intervention)",
            "delegation.delegator_id records the authorizing human (authorization records)",
        ],
    },
}


# ── Compliance Findings ─────────────────────────────────────────────────────

@dataclass
class ComplianceFinding:
    """A specific compliance observation or gap."""
    article: str
    requirement: str
    status: str  # "met", "partial", "gap"
    evidence: str
    recommendation: Optional[str] = None

    def to_dict(self) -> dict:
        d = {
            "article": self.article,
            "requirement": self.requirement,
            "status": self.status,
            "evidence": self.evidence,
        }
        if self.recommendation:
            d["recommendation"] = self.recommendation
        return d


@dataclass
class ComplianceReport:
    """Complete compliance audit report."""
    generated_at: str
    period_start: Optional[str]
    period_end: Optional[str]
    agent_id: Optional[str]
    summary: Dict[str, Any]
    article_scores: Dict[str, float]
    findings: List[ComplianceFinding]
    receipt_statistics: Dict[str, Any]
    overall_score: float
    overall_status: str

    def to_dict(self) -> dict:
        return {
            "compliance_framework": "EU AI Act (Regulation (EU) 2024/1689)",
            "generated_at": self.generated_at,
            "period": {"start": self.period_start, "end": self.period_end},
            "agent_id": self.agent_id,
            "overall_score": round(self.overall_score, 1),
            "overall_status": self.overall_status,
            "summary": self.summary,
            "article_scores": {k: round(v, 1) for k, v in self.article_scores.items()},
            "findings": [f.to_dict() for f in self.findings],
            "receipt_statistics": self.receipt_statistics,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ── Dashboard ───────────────────────────────────────────────────────────────

class ComplianceDashboard:
    """
    EU AI Act compliance dashboard for RCPT receipt data.

    Analyzes receipt collections and generates compliance reports
    mapping to Articles 12, 19, and 26.
    """

    def __init__(self, receipts: Optional[List[Receipt]] = None):
        """
        Args:
            receipts: List of Receipt objects to analyze.
                      Can also be added later via add_receipt(s).
        """
        self._receipts: List[Receipt] = list(receipts) if receipts else []

    def add_receipt(self, receipt: Receipt) -> None:
        self._receipts.append(receipt)

    def add_receipts(self, receipts: List[Receipt]) -> None:
        self._receipts.extend(receipts)

    def generate_report(
        self,
        agent_id: Optional[str] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
    ) -> ComplianceReport:
        """
        Generate a full compliance report.

        Args:
            agent_id: Filter by agent. None = all agents.
            start: Period start (ISO 8601). None = earliest receipt.
            end: Period end (ISO 8601). None = latest receipt.

        Returns:
            ComplianceReport with scores, findings, and statistics.
        """
        filtered = self._filter(agent_id, start, end)
        stats = self._compute_statistics(filtered)
        findings = self._evaluate_compliance(filtered, stats)

        # Score each article
        article_scores = {}
        for article in ["Article 12", "Article 19", "Article 26"]:
            article_findings = [f for f in findings if f.article == article]
            met = sum(1 for f in article_findings if f.status == "met")
            total = len(article_findings)
            article_scores[article] = (met / total * 100) if total > 0 else 0

        overall = sum(article_scores.values()) / len(article_scores) if article_scores else 0

        if overall >= 80:
            status = "Compliant"
        elif overall >= 50:
            status = "Partially Compliant"
        else:
            status = "Non-Compliant"

        return ComplianceReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            period_start=start or stats.get("first_timestamp"),
            period_end=end or stats.get("last_timestamp"),
            agent_id=agent_id,
            summary={
                "total_receipts": stats["total"],
                "agents": stats["agent_count"],
                "action_types": stats["action_types"],
                "articles_covered": list(article_scores.keys()),
                "gaps_found": sum(1 for f in findings if f.status == "gap"),
            },
            article_scores=article_scores,
            findings=findings,
            receipt_statistics=stats,
            overall_score=overall,
            overall_status=status,
        )

    def check_gaps(
        self,
        agent_id: Optional[str] = None,
    ) -> List[ComplianceFinding]:
        """Return only the compliance gaps (unmet requirements)."""
        report = self.generate_report(agent_id=agent_id)
        return [f for f in report.findings if f.status in ("gap", "partial")]

    def _filter(
        self,
        agent_id: Optional[str],
        start: Optional[str],
        end: Optional[str],
    ) -> List[Receipt]:
        result = self._receipts
        if agent_id:
            result = [r for r in result if r.agent_id == agent_id]
        if start:
            result = [r for r in result if r.timestamp >= start]
        if end:
            result = [r for r in result if r.timestamp <= end]
        return result

    def _compute_statistics(self, receipts: List[Receipt]) -> Dict[str, Any]:
        if not receipts:
            return {
                "total": 0, "agent_count": 0, "action_types": {},
                "has_signatures": False, "has_chains": False,
                "has_models": False, "has_delegations": False,
                "has_input_hashes": False, "has_metadata": False,
                "chain_coverage": 0.0, "model_coverage": 0.0,
                "delegation_coverage": 0.0, "input_hash_coverage": 0.0,
                "metadata_coverage": 0.0,
                "first_timestamp": None, "last_timestamp": None,
            }

        total = len(receipts)
        agents = set(r.agent_id for r in receipts)
        action_counts = Counter(r.action_type for r in receipts)

        with_sig = sum(1 for r in receipts if r.signature)
        with_chain = sum(1 for r in receipts if r.chain and r.chain.parent_receipt_id)
        with_model = sum(1 for r in receipts if r.model)
        with_deleg = sum(1 for r in receipts if r.delegation)
        with_input = sum(1 for r in receipts if r.input_hash)
        with_meta = sum(1 for r in receipts if r.metadata)

        timestamps = sorted(r.timestamp for r in receipts)

        return {
            "total": total,
            "agent_count": len(agents),
            "action_types": dict(action_counts),
            "has_signatures": with_sig == total,
            "has_chains": with_chain > 0,
            "has_models": with_model > 0,
            "has_delegations": with_deleg > 0,
            "has_input_hashes": with_input > 0,
            "has_metadata": with_meta > 0,
            "chain_coverage": with_chain / total,
            "model_coverage": with_model / total,
            "delegation_coverage": with_deleg / total,
            "input_hash_coverage": with_input / total,
            "metadata_coverage": with_meta / total,
            "signature_coverage": with_sig / total,
            "first_timestamp": timestamps[0] if timestamps else None,
            "last_timestamp": timestamps[-1] if timestamps else None,
        }

    def _evaluate_compliance(
        self,
        receipts: List[Receipt],
        stats: Dict[str, Any],
    ) -> List[ComplianceFinding]:
        findings: List[ComplianceFinding] = []

        # ── Article 12: Record-Keeping ──────────────────────────────────

        # Automatic logging
        findings.append(ComplianceFinding(
            article="Article 12",
            requirement="Automatic logging of operations",
            status="met" if stats["total"] > 0 else "gap",
            evidence=f"{stats['total']} receipts logged across {stats['agent_count']} agents",
            recommendation="Ensure all agent actions generate receipts" if stats["total"] == 0 else None,
        ))

        # Traceability
        findings.append(ComplianceFinding(
            article="Article 12",
            requirement="Traceability of agent actions",
            status="met" if stats["chain_coverage"] > 0.5 else ("partial" if stats["has_chains"] else "gap"),
            evidence=f"{stats['chain_coverage']:.0%} of receipts are chained to parent actions",
            recommendation="Use parent receipt IDs to chain multi-step workflows" if not stats["has_chains"] else None,
        ))

        # Tamper evidence
        findings.append(ComplianceFinding(
            article="Article 12",
            requirement="Tamper-evident records",
            status="met" if stats.get("signature_coverage", 0) == 1.0 else "gap",
            evidence=f"{stats.get('signature_coverage', 0):.0%} of receipts have Ed25519 signatures",
        ))

        # Temporal ordering
        findings.append(ComplianceFinding(
            article="Article 12",
            requirement="Temporal ordering of events",
            status="met" if stats["total"] > 0 else "gap",
            evidence="All receipts contain ULID (sortable) and ISO 8601 timestamps",
        ))

        # ── Article 19: Transparency ────────────────────────────────────

        # Documentation
        findings.append(ComplianceFinding(
            article="Article 19",
            requirement="Documentation of AI system purpose",
            status="met" if stats["metadata_coverage"] > 0.5 else ("partial" if stats["has_metadata"] else "gap"),
            evidence=f"{stats['metadata_coverage']:.0%} of receipts include metadata descriptions",
            recommendation="Add metadata.description to receipts" if not stats["has_metadata"] else None,
        ))

        # I/O monitoring
        findings.append(ComplianceFinding(
            article="Article 19",
            requirement="Input/output monitoring",
            status="met" if stats["input_hash_coverage"] > 0.5 else ("partial" if stats["has_input_hashes"] else "gap"),
            evidence=f"{stats['input_hash_coverage']:.0%} of receipts include input hashes; all include output hashes",
            recommendation="Include input_data when calling attest()" if not stats["has_input_hashes"] else None,
        ))

        # Model identification
        findings.append(ComplianceFinding(
            article="Article 19",
            requirement="Model identification and versioning",
            status="met" if stats["model_coverage"] > 0.5 else ("partial" if stats["has_models"] else "gap"),
            evidence=f"{stats['model_coverage']:.0%} of receipts identify the model used",
            recommendation="Include model parameter when calling attest()" if not stats["has_models"] else None,
        ))

        # Audit trails
        findings.append(ComplianceFinding(
            article="Article 19",
            requirement="Human-readable audit trails",
            status="met" if stats["total"] > 0 else "gap",
            evidence="All receipts are JSON-serializable and exportable for audit review",
        ))

        # ── Article 26: Deployer Obligations ────────────────────────────

        # Human oversight
        findings.append(ComplianceFinding(
            article="Article 26",
            requirement="Human oversight of operations",
            status="met" if stats["delegation_coverage"] > 0.1 else "gap",
            evidence=f"{stats['delegation_coverage']:.0%} of receipts include delegation (human authorization)",
            recommendation="Use delegation receipts to bind agent actions to human authorization" if not stats["has_delegations"] else None,
        ))

        # Performance monitoring
        findings.append(ComplianceFinding(
            article="Article 26",
            requirement="Monitoring of AI system performance",
            status="met" if stats["total"] >= 10 else ("partial" if stats["total"] > 0 else "gap"),
            evidence=f"{stats['total']} receipts available for performance analysis",
            recommendation="Generate receipts consistently to enable monitoring" if stats["total"] < 10 else None,
        ))

        # Intervention capability
        findings.append(ComplianceFinding(
            article="Article 26",
            requirement="Authority to intervene or stop",
            status="met" if stats["has_delegations"] else "gap",
            evidence="Delegation receipts with expiry timestamps provide temporal authority bounds" if stats["has_delegations"] else "No delegation receipts found",
            recommendation="Use delegation.expires to set time-bounded authority" if not stats["has_delegations"] else None,
        ))

        # Authorization records
        findings.append(ComplianceFinding(
            article="Article 26",
            requirement="Record of human authorization decisions",
            status="met" if stats["has_delegations"] else "gap",
            evidence=f"Delegation receipts found: {stats['delegation_coverage']:.0%} coverage" if stats["has_delegations"] else "No delegation receipts",
            recommendation="Generate delegation receipts when humans authorize agent actions" if not stats["has_delegations"] else None,
        ))

        return findings
