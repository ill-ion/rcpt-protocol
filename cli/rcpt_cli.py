#!/usr/bin/env python3
"""
RCPT CLI — Command-line tool for RCPT receipt operations.

Commands:
    rcpt keygen              Generate a new Ed25519 keypair
    rcpt attest              Generate a signed receipt
    rcpt verify <file>       Verify a receipt's signature
    rcpt inspect <file>      Pretty-print a receipt with verification status
    rcpt chain <file>        Show the receipt chain from a JSON array
    rcpt hash <text>         Compute SHA-256 hash of content
    rcpt merkle <file>       Build Merkle tree from receipt array, print root
    rcpt compliance <file>   Run EU AI Act compliance check on receipts
    rcpt reputation <file>   Compute reputation scores from receipts

Usage:
    pip install rcpt
    python -m rcpt_cli keygen
    python -m rcpt_cli verify receipt.json
    echo "hello" | python -m rcpt_cli hash -
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List

from rcpt import RCPTClient, ActionType, Receipt
from rcpt.crypto import generate_keypair
from rcpt.hashing import hash_content, hash_receipt_canonical, build_merkle_tree
from rcpt.reputation import ReputationEngine
from rcpt.compliance import ComplianceDashboard


# ── Colors ──────────────────────────────────────────────────────────────────

class C:
    GREEN = "\033[92m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    DIM = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @staticmethod
    def ok(text: str) -> str:
        return f"{C.GREEN}✓{C.RESET} {text}"

    @staticmethod
    def fail(text: str) -> str:
        return f"{C.RED}✗{C.RESET} {text}"

    @staticmethod
    def dim(text: str) -> str:
        return f"{C.DIM}{text}{C.RESET}"

    @staticmethod
    def bold(text: str) -> str:
        return f"{C.BOLD}{text}{C.RESET}"

    @staticmethod
    def cyan(text: str) -> str:
        return f"{C.CYAN}{text}{C.RESET}"


# ── Commands ────────────────────────────────────────────────────────────────

def cmd_keygen(args: argparse.Namespace) -> None:
    """Generate a new Ed25519 keypair."""
    private_key, public_key, agent_id = generate_keypair()
    if args.json:
        print(json.dumps({
            "agent_id": agent_id,
            "public_key": public_key,
            "private_key": private_key,
        }, indent=2))
    else:
        print(f"{C.bold('Agent ID:')}    {C.cyan(agent_id)}")
        print(f"{C.bold('Public Key:')}  {public_key}")
        print(f"{C.bold('Private Key:')} {private_key}")
        print()
        print(C.dim("Store the private key securely. The agent ID is derived from the public key."))


def cmd_attest(args: argparse.Namespace) -> None:
    """Generate a signed receipt."""
    client = RCPTClient(private_key=args.key) if args.key else RCPTClient()

    # Read output from stdin or argument
    if args.output == "-":
        output = sys.stdin.read()
    else:
        output = args.output

    kwargs = {
        "action_type": args.type,
        "output": output,
    }
    if args.model:
        kwargs["model"] = args.model
    if args.parent:
        kwargs["parent"] = args.parent
    if args.input:
        kwargs["input_data"] = args.input

    receipt = client.attest(**kwargs)
    print(receipt.to_json())


def cmd_verify(args: argparse.Namespace) -> None:
    """Verify a receipt's signature."""
    data = _read_json(args.file)
    client = RCPTClient()

    if isinstance(data, list):
        valid_count = 0
        for i, item in enumerate(data):
            receipt = Receipt.from_dict(item)
            valid = client.verify(receipt)
            valid_count += int(valid)
            status = C.ok("valid") if valid else C.fail("INVALID")
            print(f"  {status}  {receipt.receipt_id}  {C.dim(receipt.action_type)}")
        print()
        print(f"{valid_count}/{len(data)} receipts verified")
        sys.exit(0 if valid_count == len(data) else 1)
    else:
        receipt = Receipt.from_dict(data)
        valid = client.verify(receipt)
        if valid:
            print(C.ok(f"Receipt {receipt.receipt_id} is valid"))
        else:
            print(C.fail(f"Receipt {receipt.receipt_id} is INVALID"))
        sys.exit(0 if valid else 1)


def cmd_inspect(args: argparse.Namespace) -> None:
    """Pretty-print a receipt with verification status."""
    data = _read_json(args.file)
    client = RCPTClient()

    items = data if isinstance(data, list) else [data]

    for item in items:
        receipt = Receipt.from_dict(item)
        valid = client.verify(receipt)

        status = C.ok("VERIFIED") if valid else C.fail("INVALID SIGNATURE")
        print(f"\n{C.bold('Receipt')} {C.cyan(receipt.receipt_id)}  [{status}]")
        print(f"  {C.dim('version')}      {receipt.rcpt_version}")
        print(f"  {C.dim('timestamp')}    {receipt.timestamp}")
        print(f"  {C.dim('agent_id')}     {receipt.agent_id}")
        print(f"  {C.dim('action_type')}  {receipt.action_type}")
        print(f"  {C.dim('output_hash')} {receipt.output_hash}")
        print(f"  {C.dim('signature')}   {receipt.signature[:40]}...")

        if receipt.input_hash:
            print(f"  {C.dim('input_hash')}  {receipt.input_hash}")
        if receipt.model:
            print(f"  {C.dim('model')}       {receipt.model.provider}/{receipt.model.model_id}")
        if receipt.chain:
            print(f"  {C.dim('parent')}      {receipt.chain.parent_receipt_id}")
            if receipt.chain.workflow_id:
                print(f"  {C.dim('workflow')}    {receipt.chain.workflow_id}")
        if receipt.metadata:
            if receipt.metadata.description:
                print(f"  {C.dim('description')} {receipt.metadata.description}")
            if receipt.metadata.tags:
                print(f"  {C.dim('tags')}        {', '.join(receipt.metadata.tags)}")


def cmd_hash(args: argparse.Namespace) -> None:
    """Compute SHA-256 hash of content."""
    if args.text == "-":
        text = sys.stdin.read()
    else:
        text = args.text
    print(hash_content(text))


def cmd_merkle(args: argparse.Namespace) -> None:
    """Build Merkle tree from receipts."""
    data = _read_json(args.file)
    if not isinstance(data, list):
        data = [data]

    hashes = [hash_receipt_canonical(item) for item in data]
    root, levels = build_merkle_tree(hashes)

    print(f"{C.bold('Merkle Root:')} {C.cyan(root)}")
    print(f"{C.dim(f'{len(data)} receipts, {len(levels)} tree levels')}")

    if args.json:
        print(json.dumps({
            "merkle_root": root,
            "receipt_count": len(data),
            "tree_depth": len(levels),
        }, indent=2))


def cmd_compliance(args: argparse.Namespace) -> None:
    """Run EU AI Act compliance check."""
    data = _read_json(args.file)
    if not isinstance(data, list):
        data = [data]

    receipts = [Receipt.from_dict(item) for item in data]
    dashboard = ComplianceDashboard(receipts)

    if args.gaps_only:
        gaps = dashboard.check_gaps()
        if not gaps:
            print(C.ok("No compliance gaps found"))
            return
        for g in gaps:
            status_icon = "⚠" if g.status == "partial" else "✗"
            print(f"  {status_icon} {C.bold(g.article)}: {g.requirement}")
            print(f"    {C.dim(g.evidence)}")
            if g.recommendation:
                print(f"    → {g.recommendation}")
        return

    report = dashboard.generate_report()

    if args.json:
        print(report.to_json())
        return

    # Pretty print
    status_color = C.GREEN if report.overall_score >= 80 else (C.RED if report.overall_score < 50 else "\033[93m")
    print(f"\n{C.bold('EU AI Act Compliance Report')}")
    print(f"  Status: {status_color}{report.overall_status}{C.RESET}")
    print(f"  Score:  {status_color}{report.overall_score:.1f}/100{C.RESET}")
    print(f"  Receipts analyzed: {report.summary['total_receipts']}")
    print()

    for article, score in report.article_scores.items():
        bar_len = int(score / 5)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        print(f"  {article}: {bar} {score:.0f}%")

    print()
    gaps = [f for f in report.findings if f.status in ("gap", "partial")]
    if gaps:
        print(f"  {len(gaps)} gap(s) found:")
        for g in gaps:
            print(f"    {'⚠' if g.status == 'partial' else '✗'} {g.article}: {g.requirement}")
    else:
        print(C.ok("No compliance gaps"))


def cmd_reputation(args: argparse.Namespace) -> None:
    """Compute reputation scores."""
    data = _read_json(args.file)
    if not isinstance(data, list):
        data = [data]

    receipts = [Receipt.from_dict(item) for item in data]
    engine = ReputationEngine()
    engine.add_receipts(receipts)

    if args.agent:
        score = engine.score(args.agent)
        _print_score(score, args.json)
    else:
        board = engine.leaderboard(top_n=args.top)
        if args.json:
            print(json.dumps([s.to_dict() for s in board], indent=2))
        else:
            for i, s in enumerate(board, 1):
                did_short = s.agent_id[:30] + "..."
                bar_len = int(s.score / 5)
                bar = "█" * bar_len + "░" * (20 - bar_len)
                print(f"  {i}. {did_short}  {bar} {s.score:.1f}  [{s.level}]")


def _print_score(score, as_json: bool) -> None:
    if as_json:
        print(json.dumps(score.to_dict(), indent=2))
        return

    print(f"\n{C.bold('Agent:')} {C.cyan(score.agent_id)}")
    print(f"  Score: {score.score:.1f}/100  [{score.level}]")
    print(f"  {C.dim(score.level_description)}")
    print()
    b = score.breakdown
    print(f"  Volume:       {_bar(b.volume_score)}")
    print(f"  Consistency:  {_bar(b.consistency_score)}")
    print(f"  Age:          {_bar(b.age_score)}")
    print(f"  Verification: {_bar(b.verification_rate)}")
    print(f"  Dispute-free: {_bar(b.dispute_rate)}")
    print()
    print(f"  {score.total_receipts} receipts, {score.verified_receipts} verified, {score.disputed_receipts} disputed")


def _bar(val: float) -> str:
    n = int(val * 20)
    return "█" * n + "░" * (20 - n) + f" {val:.0%}"


# ── Helpers ─────────────────────────────────────────────────────────────────

def _read_json(path: str) -> dict | list:
    """Read JSON from a file path or stdin."""
    if path == "-":
        return json.load(sys.stdin)
    with open(path) as f:
        return json.load(f)


# ── Parser ──────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="rcpt",
        description="RCPT Protocol — CLI for receipt operations",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # keygen
    p_keygen = sub.add_parser("keygen", help="Generate a new Ed25519 keypair")
    p_keygen.add_argument("--json", action="store_true", help="Output as JSON")

    # attest
    p_attest = sub.add_parser("attest", help="Generate a signed receipt")
    p_attest.add_argument("output", help="Action output text (use - for stdin)")
    p_attest.add_argument("--type", default="inference", help="Action type (default: inference)")
    p_attest.add_argument("--model", help="Model identifier")
    p_attest.add_argument("--parent", help="Parent receipt ID for chaining")
    p_attest.add_argument("--input", help="Input data to hash")
    p_attest.add_argument("--key", help="Private key (base64url)")

    # verify
    p_verify = sub.add_parser("verify", help="Verify receipt signature(s)")
    p_verify.add_argument("file", help="Receipt JSON file (or - for stdin)")

    # inspect
    p_inspect = sub.add_parser("inspect", help="Pretty-print receipt details")
    p_inspect.add_argument("file", help="Receipt JSON file (or - for stdin)")

    # hash
    p_hash = sub.add_parser("hash", help="Compute SHA-256 hash")
    p_hash.add_argument("text", help="Text to hash (or - for stdin)")

    # chain
    p_chain = sub.add_parser("chain", help="Display receipt chain")
    p_chain.add_argument("file", help="Receipt array JSON file")

    # merkle
    p_merkle = sub.add_parser("merkle", help="Build Merkle tree from receipts")
    p_merkle.add_argument("file", help="Receipt array JSON file")
    p_merkle.add_argument("--json", action="store_true", help="Output as JSON")

    # compliance
    p_comp = sub.add_parser("compliance", help="EU AI Act compliance check")
    p_comp.add_argument("file", help="Receipt array JSON file")
    p_comp.add_argument("--json", action="store_true", help="Output as JSON")
    p_comp.add_argument("--gaps-only", action="store_true", help="Show only gaps")

    # reputation
    p_rep = sub.add_parser("reputation", help="Compute reputation scores")
    p_rep.add_argument("file", help="Receipt array JSON file")
    p_rep.add_argument("--agent", help="Filter by agent DID")
    p_rep.add_argument("--top", type=int, default=10, help="Leaderboard size")
    p_rep.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    commands = {
        "keygen": cmd_keygen,
        "attest": cmd_attest,
        "verify": cmd_verify,
        "inspect": cmd_inspect,
        "hash": cmd_hash,
        "merkle": cmd_merkle,
        "compliance": cmd_compliance,
        "reputation": cmd_reputation,
    }

    fn = commands.get(args.command)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
