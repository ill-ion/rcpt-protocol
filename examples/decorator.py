#!/usr/bin/env python3
"""
Example: @receipted Decorator

The simplest way to add RCPT to existing code.
Wrap any function with @receipted and every call gets a signed receipt.

Run:
    python examples/decorator.py
"""

import functools
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk", "python"))

from rcpt import RCPTClient, ActionType

# ── The Decorator ────────────────────────────────────────────────────────

_default_client = None

def get_client():
    global _default_client
    if _default_client is None:
        _default_client = RCPTClient()
    return _default_client


def receipted(action_type=ActionType.INFERENCE, model=None):
    """
    Decorator that generates an RCPT receipt for every function call.

    Usage:
        @receipted(action_type=ActionType.TOOL_CALL)
        def search(query):
            return api.search(query)
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            result = fn(*args, **kwargs)

            client = get_client()
            receipt = client.attest(
                action_type=action_type,
                output=str(result),
                input_data=json.dumps({"args": str(args), "kwargs": str(kwargs)}),
                model=model,
                metadata={
                    "description": f"{fn.__module__}.{fn.__name__}()",
                    "tags": [fn.__name__, action_type],
                },
            )
            # Attach receipt to the result if it's a dict
            if isinstance(result, dict):
                result["_rcpt_receipt_id"] = receipt.receipt_id

            wrapper._last_receipt = receipt
            wrapper._receipts = getattr(wrapper, "_receipts", [])
            wrapper._receipts.append(receipt)

            return result
        return wrapper
    return decorator


# ── Demo ─────────────────────────────────────────────────────────────────

@receipted(action_type=ActionType.INFERENCE, model="claude-sonnet-4-5")
def analyze(text):
    """Simulate an LLM analysis."""
    return f"Analysis of '{text}': positive sentiment, 0.92 confidence"


@receipted(action_type=ActionType.TOOL_CALL)
def search_api(query):
    """Simulate an API call."""
    return {"results": [f"Result for: {query}"], "count": 1}


@receipted(action_type=ActionType.TRANSACTION)
def send_email(to, subject):
    """Simulate sending an email."""
    return f"Email sent to {to}: {subject}"


if __name__ == "__main__":
    print("RCPT @receipted Decorator Demo\n")

    # Just use your functions normally
    result1 = analyze("The product launch exceeded expectations")
    print(f"1. {result1}")
    print(f"   Receipt: {analyze._last_receipt.receipt_id}\n")

    result2 = search_api("quarterly earnings ACME Corp")
    print(f"2. {result2}")
    print(f"   Receipt: {search_api._last_receipt.receipt_id}\n")

    result3 = send_email("ceo@acme.com", "Q3 Results Summary")
    print(f"3. {result3}")
    print(f"   Receipt: {send_email._last_receipt.receipt_id}\n")

    # Verify all
    client = get_client()
    all_receipts = analyze._receipts + search_api._receipts + send_email._receipts
    print(f"Total receipts: {len(all_receipts)}")
    for r in all_receipts:
        status = "✓" if client.verify(r) else "✗"
        print(f"  {status} {r.receipt_id}  {r.action_type}")
