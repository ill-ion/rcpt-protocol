"""
RCPT Compliance Dashboard — Test Suite

Tests EU AI Act compliance report generation and gap analysis.
"""

import json
import unittest

from rcpt import (
    RCPTClient,
    ActionType,
    ComplianceDashboard,
    ComplianceReport,
    ComplianceFinding,
    Delegation,
    Metadata,
    Model,
)


class TestComplianceReportBasic(unittest.TestCase):

    def test_empty_report(self):
        dashboard = ComplianceDashboard()
        report = dashboard.generate_report()
        self.assertEqual(report.summary["total_receipts"], 0)
        self.assertEqual(report.overall_status, "Non-Compliant")

    def test_report_with_receipts(self):
        client = RCPTClient()
        receipts = [
            client.attest(action_type=ActionType.INFERENCE, output=f"msg-{i}")
            for i in range(5)
        ]
        dashboard = ComplianceDashboard(receipts)
        report = dashboard.generate_report()
        self.assertEqual(report.summary["total_receipts"], 5)
        self.assertGreater(report.overall_score, 0)

    def test_report_serialization(self):
        client = RCPTClient()
        receipts = [
            client.attest(action_type=ActionType.INFERENCE, output="test")
        ]
        dashboard = ComplianceDashboard(receipts)
        report = dashboard.generate_report()
        d = report.to_dict()
        self.assertIn("compliance_framework", d)
        self.assertEqual(d["compliance_framework"], "EU AI Act (Regulation (EU) 2024/1689)")
        self.assertIn("overall_score", d)
        self.assertIn("findings", d)

        # JSON serialization should work
        j = report.to_json()
        parsed = json.loads(j)
        self.assertIsInstance(parsed, dict)

    def test_report_articles_covered(self):
        client = RCPTClient()
        receipts = [client.attest(action_type=ActionType.INFERENCE, output="test")]
        dashboard = ComplianceDashboard(receipts)
        report = dashboard.generate_report()
        self.assertIn("Article 12", report.article_scores)
        self.assertIn("Article 19", report.article_scores)
        self.assertIn("Article 26", report.article_scores)


class TestComplianceArticle12(unittest.TestCase):
    """Article 12: Record-Keeping"""

    def test_logging_met(self):
        client = RCPTClient()
        receipts = [client.attest(action_type=ActionType.INFERENCE, output="test")]
        dashboard = ComplianceDashboard(receipts)
        report = dashboard.generate_report()
        logging_findings = [
            f for f in report.findings
            if f.article == "Article 12" and "logging" in f.requirement.lower()
        ]
        self.assertTrue(any(f.status == "met" for f in logging_findings))

    def test_tamper_evidence_met(self):
        client = RCPTClient()
        receipts = [client.attest(action_type=ActionType.INFERENCE, output="test")]
        dashboard = ComplianceDashboard(receipts)
        report = dashboard.generate_report()
        tamper_findings = [
            f for f in report.findings
            if f.article == "Article 12" and "tamper" in f.requirement.lower()
        ]
        self.assertTrue(any(f.status == "met" for f in tamper_findings))

    def test_traceability_with_chains(self):
        client = RCPTClient()
        r1 = client.attest(action_type=ActionType.INFERENCE, output="start")
        r2 = client.attest(action_type=ActionType.TOOL_CALL, output="step", parent=r1.receipt_id)
        r3 = client.attest(action_type=ActionType.INFERENCE, output="end", parent=r2.receipt_id)
        dashboard = ComplianceDashboard([r1, r2, r3])
        report = dashboard.generate_report()
        trace_findings = [
            f for f in report.findings
            if f.article == "Article 12" and "traceability" in f.requirement.lower()
        ]
        self.assertTrue(any(f.status == "met" for f in trace_findings))

    def test_traceability_gap_without_chains(self):
        client = RCPTClient()
        receipts = [
            client.attest(action_type=ActionType.INFERENCE, output=f"isolated-{i}")
            for i in range(5)
        ]
        dashboard = ComplianceDashboard(receipts)
        report = dashboard.generate_report()
        trace_findings = [
            f for f in report.findings
            if f.article == "Article 12" and "traceability" in f.requirement.lower()
        ]
        self.assertTrue(any(f.status == "gap" for f in trace_findings))


class TestComplianceArticle19(unittest.TestCase):
    """Article 19: Transparency"""

    def test_model_id_met(self):
        client = RCPTClient()
        receipts = [
            client.attest(
                action_type=ActionType.INFERENCE,
                output="response",
                model="claude-sonnet-4-5",
            )
        ]
        dashboard = ComplianceDashboard(receipts)
        report = dashboard.generate_report()
        model_findings = [
            f for f in report.findings
            if f.article == "Article 19" and "model" in f.requirement.lower()
        ]
        self.assertTrue(any(f.status == "met" for f in model_findings))

    def test_model_id_gap(self):
        client = RCPTClient()
        receipts = [
            client.attest(action_type=ActionType.INFERENCE, output="no model info")
        ]
        dashboard = ComplianceDashboard(receipts)
        report = dashboard.generate_report()
        model_findings = [
            f for f in report.findings
            if f.article == "Article 19" and "model" in f.requirement.lower()
        ]
        self.assertTrue(any(f.status == "gap" for f in model_findings))

    def test_io_monitoring_met(self):
        client = RCPTClient()
        receipts = [
            client.attest(
                action_type=ActionType.INFERENCE,
                output="answer",
                input_data="question",
            )
        ]
        dashboard = ComplianceDashboard(receipts)
        report = dashboard.generate_report()
        io_findings = [
            f for f in report.findings
            if f.article == "Article 19" and "input/output" in f.requirement.lower()
        ]
        self.assertTrue(any(f.status == "met" for f in io_findings))

    def test_documentation_with_metadata(self):
        client = RCPTClient()
        receipts = [
            client.attest(
                action_type=ActionType.INFERENCE,
                output="result",
                metadata={"description": "Analyzed quarterly earnings data"},
            )
        ]
        dashboard = ComplianceDashboard(receipts)
        report = dashboard.generate_report()
        doc_findings = [
            f for f in report.findings
            if f.article == "Article 19" and "documentation" in f.requirement.lower()
        ]
        self.assertTrue(any(f.status == "met" for f in doc_findings))


class TestComplianceArticle26(unittest.TestCase):
    """Article 26: Obligations of Deployers"""

    def test_delegation_met(self):
        client = RCPTClient()
        receipts = [
            client.attest(
                action_type=ActionType.DELEGATION,
                output="authorized",
                delegation=Delegation(
                    delegator_id="did:web:company.com:users:alice",
                    scope=["read:all"],
                    expires="2026-12-31T23:59:59.000Z",
                ),
            )
        ]
        dashboard = ComplianceDashboard(receipts)
        report = dashboard.generate_report()
        oversight_findings = [
            f for f in report.findings
            if f.article == "Article 26" and "oversight" in f.requirement.lower()
        ]
        self.assertTrue(any(f.status == "met" for f in oversight_findings))

    def test_delegation_gap(self):
        client = RCPTClient()
        receipts = [
            client.attest(action_type=ActionType.INFERENCE, output="no delegation")
        ]
        dashboard = ComplianceDashboard(receipts)
        report = dashboard.generate_report()
        oversight_findings = [
            f for f in report.findings
            if f.article == "Article 26" and "oversight" in f.requirement.lower()
        ]
        self.assertTrue(any(f.status == "gap" for f in oversight_findings))


class TestComplianceGaps(unittest.TestCase):
    """Gap analysis tests."""

    def test_check_gaps_returns_only_gaps(self):
        client = RCPTClient()
        receipts = [client.attest(action_type=ActionType.INFERENCE, output="bare minimum")]
        dashboard = ComplianceDashboard(receipts)
        gaps = dashboard.check_gaps()
        for g in gaps:
            self.assertIn(g.status, ("gap", "partial"))

    def test_full_compliance_few_gaps(self):
        """Well-instrumented receipts should have fewer gaps."""
        client = RCPTClient()
        r1 = client.attest(
            action_type=ActionType.DELEGATION,
            output="authorized",
            delegation=Delegation(
                delegator_id="did:web:company.com:users:bob",
                scope=["full"],
                expires="2026-12-31T23:59:59.000Z",
            ),
            metadata={"description": "Human authorized agent operations"},
        )
        r2 = client.attest(
            action_type=ActionType.INFERENCE,
            output="analysis result",
            input_data="analyze Q3 earnings",
            model="claude-sonnet-4-5",
            parent=r1.receipt_id,
            metadata={"description": "Earnings analysis"},
        )
        r3 = client.attest(
            action_type=ActionType.TOOL_CALL,
            output="API data",
            input_data="GET /api/earnings",
            parent=r2.receipt_id,
            metadata={"description": "Fetched earnings from API"},
        )
        dashboard = ComplianceDashboard([r1, r2, r3])
        report = dashboard.generate_report()
        gaps = [f for f in report.findings if f.status == "gap"]
        # Should have very few gaps with fully instrumented receipts
        self.assertLessEqual(len(gaps), 2)
        self.assertGreater(report.overall_score, 60)


class TestComplianceOverallStatus(unittest.TestCase):

    def test_non_compliant(self):
        dashboard = ComplianceDashboard()
        report = dashboard.generate_report()
        self.assertEqual(report.overall_status, "Non-Compliant")

    def test_partially_compliant(self):
        client = RCPTClient()
        receipts = [
            client.attest(
                action_type=ActionType.INFERENCE,
                output=f"msg-{i}",
                model="claude-sonnet-4-5",
                input_data="prompt",
                metadata={"description": "test"},
            )
            for i in range(10)
        ]
        dashboard = ComplianceDashboard(receipts)
        report = dashboard.generate_report()
        # Without delegation, Article 26 will be low, so likely partially compliant
        self.assertIn(report.overall_status, ["Partially Compliant", "Compliant"])

    def test_agent_filter(self):
        client_a = RCPTClient()
        client_b = RCPTClient()
        receipts = [
            client_a.attest(action_type=ActionType.INFERENCE, output="a"),
            client_b.attest(action_type=ActionType.INFERENCE, output="b"),
        ]
        dashboard = ComplianceDashboard(receipts)
        report = dashboard.generate_report(agent_id=client_a.agent_id)
        self.assertEqual(report.summary["total_receipts"], 1)


if __name__ == "__main__":
    unittest.main()
