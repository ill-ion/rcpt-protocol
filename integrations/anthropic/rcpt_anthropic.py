"""
RCPT × Anthropic SDK Integration

Drop-in wrapper around the Anthropic Python SDK that generates a signed
receipt for every message, tool use, and streaming response.

Usage:
    from rcpt_anthropic import ReceiptedAnthropic

    client = ReceiptedAnthropic(api_key="sk-ant-...")

    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=1024,
        messages=[{"role": "user", "content": "Hello"}],
    )

    print(client.receipts[-1].to_json())
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

try:
    import anthropic
    from anthropic import Anthropic
except ImportError:
    raise ImportError(
        "rcpt-anthropic requires the anthropic package. "
        "Install with: pip install anthropic"
    )

from rcpt import RCPTClient, ActionType, Receipt


class ReceiptedMessages:
    """Wrapper around anthropic.messages that generates receipts."""

    def __init__(self, original_messages: Any, rcpt_client: RCPTClient, receipts: List[Receipt]):
        self._original = original_messages
        self._rcpt = rcpt_client
        self._receipts = receipts

    def create(self, **kwargs: Any) -> Any:
        """Create a message and generate RCPT receipts."""
        response = self._original.create(**kwargs)

        # Extract output
        output_parts = []
        tool_uses = []
        for block in response.content:
            if block.type == "text":
                output_parts.append(block.text)
            elif block.type == "tool_use":
                tool_uses.append({
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })

        output_text = "\n".join(output_parts) if output_parts else ""

        # Build input from messages
        messages = kwargs.get("messages", [])
        input_data = json.dumps(messages, default=str) if messages else None

        # Inference receipt
        model_name = kwargs.get("model", response.model)
        receipt = self._rcpt.attest(
            action_type=ActionType.INFERENCE,
            output=output_text or json.dumps(tool_uses),
            input_data=input_data,
            model=model_name,  # Provider auto-detected as "anthropic"
            metadata={
                "description": f"Anthropic message: {model_name}",
                "tags": ["anthropic", "message"],
            },
        )
        self._receipts.append(receipt)

        # Tool use receipts
        parent_id = receipt.receipt_id
        for tu in tool_uses:
            tu_receipt = self._rcpt.attest(
                action_type=ActionType.TOOL_CALL,
                output=json.dumps(tu),
                parent=parent_id,
                metadata={
                    "description": f"Tool use: {tu['name']}",
                    "tags": ["anthropic", "tool_use", tu["name"]],
                },
            )
            self._receipts.append(tu_receipt)

        return response

    def stream(self, **kwargs: Any) -> Any:
        """Stream a message. Receipt is generated after stream completes."""
        # Collect the stream, then receipt the full result
        with self._original.stream(**kwargs) as stream:
            response = stream.get_final_message()

        # Now receipt the complete response (same as create)
        output_parts = []
        for block in response.content:
            if block.type == "text":
                output_parts.append(block.text)

        model_name = kwargs.get("model", response.model)
        receipt = self._rcpt.attest(
            action_type=ActionType.INFERENCE,
            output="\n".join(output_parts),
            model=model_name,
            metadata={
                "description": f"Anthropic streamed message: {model_name}",
                "tags": ["anthropic", "message", "stream"],
            },
        )
        self._receipts.append(receipt)

        return response


class ReceiptedAnthropic:
    """
    Drop-in replacement for anthropic.Anthropic that generates RCPT receipts.

    Usage:
        client = ReceiptedAnthropic(api_key="sk-ant-...")
        message = client.messages.create(model="claude-sonnet-4-5", ...)
        print(client.receipts)
    """

    def __init__(
        self,
        rcpt_client: Optional[RCPTClient] = None,
        **anthropic_kwargs: Any,
    ):
        self._anthropic = Anthropic(**anthropic_kwargs)
        self._rcpt = rcpt_client or RCPTClient()
        self.receipts: List[Receipt] = []

        self.messages = ReceiptedMessages(
            self._anthropic.messages, self._rcpt, self.receipts
        )

    @property
    def receipt_count(self) -> int:
        return len(self.receipts)

    @property
    def agent_id(self) -> str:
        return self._rcpt.agent_id

    def export_receipts(self, format: str = "json") -> str:
        if format == "eu-ai-act":
            return self._rcpt.export(format="eu-ai-act")
        return json.dumps([r.to_dict() for r in self.receipts], indent=2)

    def verify_all(self) -> bool:
        return all(self._rcpt.verify(r) for r in self.receipts)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._anthropic, name)
