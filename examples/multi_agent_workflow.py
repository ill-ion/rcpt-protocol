#!/usr/bin/env python3
"""
Example: Enterprise Multi-Agent Workflow

Demonstrates a realistic multi-agent workflow where:
1. A human delegates authority to an agent team
2. A research agent searches for data
3. An analysis agent processes results
4. An action agent executes recommendations
5. The full chain is verified and exported

Run:
    python examples/multi_agent_workflow.py
"""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk", "python"))

from rcpt import RCPTClient, ActionType, ReceiptStore, Delegation, ReputationEngine, ComplianceDashboard

print("=" * 60)
print("  RCPT Example: Enterprise Multi-Agent Workflow")
print("=" * 60)

# ── Setup: Create agents with persistent identities ─────────────────────

coordinator = RCPTClient()  # orchestrator
researcher = RCPTClient()   # data retrieval
analyst = RCPTClient()      # analysis
executor = RCPTClient()     # action

store = ReceiptStore(":memory:")

print(f"\nAgents created:")
print(f"  Coordinator: {coordinator.agent_id[:40]}...")
print(f"  Researcher:  {researcher.agent_id[:40]}...")
print(f"  Analyst:     {analyst.agent_id[:40]}...")
print(f"  Executor:    {executor.agent_id[:40]}...")

# ── Step 1: Human delegates authority ────────────────────────────────────

print(f"\n{'─' * 60}")
print("Step 1: Human delegates authority to coordinator")

deleg = store.attest(
    coordinator,
    action_type=ActionType.DELEGATION,
    output="Agent team authorized for Q3 earnings analysis",
    delegation=Delegation(
        delegator_id="did:web:acme.com:users:jane-cfo",
        scope=["read:financials", "write:reports", "send:email"],
        expires="2026-02-22T00:00:00.000Z",
    ),
    metadata={"description": "CFO authorizes Q3 analysis workflow"},
)
print(f"  Receipt: {deleg.receipt_id}")
print(f"  Delegator: did:web:acme.com:users:jane-cfo")

# ── Step 2: Coordinator dispatches research task ─────────────────────────

print(f"\n{'─' * 60}")
print("Step 2: Coordinator dispatches research task")

dispatch = store.attest(
    coordinator,
    action_type=ActionType.INFERENCE,
    output="Dispatching earnings data retrieval to research agent",
    model="claude-sonnet-4-5",
    parent=deleg.receipt_id,
    metadata={"description": "Task dispatch: Q3 earnings data retrieval"},
)
print(f"  Receipt: {dispatch.receipt_id}")

# ── Step 3: Research agent retrieves data ────────────────────────────────

print(f"\n{'─' * 60}")
print("Step 3: Research agent retrieves earnings data")

search1 = store.attest(
    researcher,
    action_type=ActionType.TOOL_CALL,
    output='{"revenue": "$4.2B", "eps": "$3.87", "guidance": "raised"}',
    input_data="GET /api/financials/q3-2025",
    parent=dispatch.receipt_id,
    metadata={"description": "API call: quarterly financials endpoint", "tags": ["api", "financials"]},
)
print(f"  Receipt: {search1.receipt_id}")
print(f"  Data: revenue=$4.2B, EPS=$3.87")

search2 = store.attest(
    researcher,
    action_type=ActionType.TOOL_CALL,
    output='{"sp500_avg_eps": "$3.21", "sector_avg": "$3.45"}',
    input_data="GET /api/market/benchmarks",
    parent=search1.receipt_id,
    metadata={"description": "API call: market benchmarks", "tags": ["api", "benchmarks"]},
)
print(f"  Receipt: {search2.receipt_id}")
print(f"  Benchmark: S&P avg EPS=$3.21")

# ── Step 4: Analyst processes data ───────────────────────────────────────

print(f"\n{'─' * 60}")
print("Step 4: Analysis agent generates report")

analysis = store.attest(
    analyst,
    action_type=ActionType.INFERENCE,
    output="Q3 EPS of $3.87 exceeds S&P 500 average by 20.6%. Revenue growth of 12% YoY. Recommend: increase position.",
    input_data="Analyze Q3 earnings vs benchmarks",
    model="claude-sonnet-4-5",
    parent=search2.receipt_id,
    metadata={"description": "Earnings analysis with recommendation", "tags": ["analysis", "report"]},
)
print(f"  Receipt: {analysis.receipt_id}")
print(f"  Finding: EPS exceeds benchmark by 20.6%")

# ── Step 5: Executor sends report ────────────────────────────────────────

print(f"\n{'─' * 60}")
print("Step 5: Action agent sends email report")

action = store.attest(
    executor,
    action_type=ActionType.TRANSACTION,
    output="Email sent to jane@acme.com: Q3 Earnings Analysis — Outperformance Confirmed",
    parent=analysis.receipt_id,
    metadata={"description": "Email: Q3 earnings report to CFO", "tags": ["email", "action"]},
)
print(f"  Receipt: {action.receipt_id}")

# ── Verify the chain ────────────────────────────────────────────────────

print(f"\n{'─' * 60}")
print("Verification: Walking the receipt chain")

chain = store.get_chain(action.receipt_id)
print(f"\n  Chain length: {len(chain)} receipts")
for i, r in enumerate(chain):
    verified = coordinator.verify(r) or researcher.verify(r) or analyst.verify(r) or executor.verify(r)
    status = "✓" if verified else "✗"
    print(f"  {status} [{i}] {r.receipt_id[:16]}...  {r.action_type:12s}  {r.agent_id[:24]}...")

# ── Merkle batch ────────────────────────────────────────────────────────

print(f"\n{'─' * 60}")
print("Merkle Anchoring")

root, count = store.create_merkle_batch()
print(f"  Merkle root: {root}")
print(f"  Receipts in batch: {count}")

# ── Compliance check ────────────────────────────────────────────────────

print(f"\n{'─' * 60}")
print("EU AI Act Compliance Check")

all_receipts = [store.get(r.receipt_id) for r in chain]
dashboard = ComplianceDashboard(all_receipts)
report = dashboard.generate_report()

print(f"  Overall: {report.overall_score:.0f}/100 ({report.overall_status})")
for article, score in report.article_scores.items():
    bar = "█" * int(score / 5) + "░" * (20 - int(score / 5))
    print(f"  {article}: {bar} {score:.0f}%")

gaps = dashboard.check_gaps()
if gaps:
    print(f"\n  Gaps ({len(gaps)}):")
    for g in gaps:
        print(f"    {'⚠' if g.status == 'partial' else '✗'} {g.article}: {g.requirement}")

# ── Reputation ──────────────────────────────────────────────────────────

print(f"\n{'─' * 60}")
print("Agent Reputation Scores")

engine = ReputationEngine()
for r in all_receipts:
    engine.add_receipt(r)

for agent_name, client in [("Coordinator", coordinator), ("Researcher", researcher), ("Analyst", analyst), ("Executor", executor)]:
    score = engine.score(client.agent_id)
    print(f"  {agent_name:12s}: {score.score:5.1f}  [{score.level}]")

# ── Store stats ─────────────────────────────────────────────────────────

print(f"\n{'─' * 60}")
print("Store Statistics")

stats = store.stats()
print(f"  Total receipts: {stats['total_receipts']}")
print(f"  Agents: {stats['agents']}")
print(f"  Merkle batches: {stats['merkle_batches']}")
print(f"  Action types: {stats['action_types']}")

store.close()
print(f"\n{'=' * 60}")
print("  Workflow complete. Every action is signed, chained, and verifiable.")
print(f"{'=' * 60}")
