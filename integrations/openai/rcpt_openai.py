"""
RCPT × OpenAI SDK Integration

Drop-in wrapper around the OpenAI Python SDK that generates a signed
receipt for every chat completion, embedding, and tool call.

Usage:
    from rcpt_openai import ReceiptedOpenAI

    client = ReceiptedOpenAI(api_key="sk-...")

    # Use exactly like the normal OpenAI client
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello"}],
    )

    # Receipt generated automatically
    print(client.receipts[-1].to_json())
    print(f"Total receipts: {client.receipt_count}")
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

try:
    import openai
    from openai import OpenAI
    from openai.types.chat import ChatCompletion
except ImportError:
    raise ImportError(
        "rcpt-openai requires the openai package. "
        "Install with: pip install openai"
    )

from rcpt import RCPTClient, ActionType, Receipt


class ReceiptedCompletions:
    """Wrapper around openai.chat.completions that generates receipts."""

    def __init__(self, original_completions: Any, rcpt_client: RCPTClient, receipts: List[Receipt]):
        self._original = original_completions
        self._rcpt = rcpt_client
        self._receipts = receipts

    def create(self, **kwargs: Any) -> ChatCompletion:
        """Create a chat completion and generate an RCPT receipt."""
        response = self._original.create(**kwargs)

        # Extract output text
        output_parts = []
        tool_calls = []
        for choice in response.choices:
            msg = choice.message
            if msg.content:
                output_parts.append(msg.content)
            if msg.tool_calls:
                for tc in msg.tool_calls:
                    tool_calls.append({
                        "id": tc.id,
                        "function": tc.function.name,
                        "arguments": tc.function.arguments,
                    })

        output_text = "\n".join(output_parts) if output_parts else ""

        # Build input from messages
        messages = kwargs.get("messages", [])
        input_data = json.dumps(messages, default=str) if messages else None

        # Generate inference receipt
        model_name = kwargs.get("model", response.model)
        receipt = self._rcpt.attest(
            action_type=ActionType.INFERENCE,
            output=output_text or json.dumps(tool_calls),
            input_data=input_data,
            model=f"openai/{model_name}",
            metadata={
                "description": f"OpenAI chat completion: {model_name}",
                "tags": ["openai", "chat"],
            },
        )
        self._receipts.append(receipt)

        # If there were tool calls, generate additional receipts
        parent_id = receipt.receipt_id
        for tc in tool_calls:
            tc_receipt = self._rcpt.attest(
                action_type=ActionType.TOOL_CALL,
                output=json.dumps(tc),
                parent=parent_id,
                metadata={
                    "description": f"Tool call: {tc['function']}",
                    "tags": ["openai", "tool_call", tc["function"]],
                },
            )
            self._receipts.append(tc_receipt)

        return response


class ReceiptedChat:
    """Wrapper around openai.chat that provides receipted completions."""

    def __init__(self, original_chat: Any, rcpt_client: RCPTClient, receipts: List[Receipt]):
        self.completions = ReceiptedCompletions(
            original_chat.completions, rcpt_client, receipts
        )


class ReceiptedEmbeddings:
    """Wrapper around openai.embeddings that generates receipts."""

    def __init__(self, original_embeddings: Any, rcpt_client: RCPTClient, receipts: List[Receipt]):
        self._original = original_embeddings
        self._rcpt = rcpt_client
        self._receipts = receipts

    def create(self, **kwargs: Any) -> Any:
        """Create embeddings and generate an RCPT receipt."""
        response = self._original.create(**kwargs)

        input_data = kwargs.get("input", "")
        if isinstance(input_data, list):
            input_data = json.dumps(input_data)

        model_name = kwargs.get("model", "unknown")
        receipt = self._rcpt.attest(
            action_type=ActionType.INFERENCE,
            output=f"embedding:{len(response.data)} vectors",
            input_data=str(input_data),
            model=f"openai/{model_name}",
            metadata={
                "description": f"Embedding: {model_name}, {len(response.data)} vectors",
                "tags": ["openai", "embedding"],
            },
        )
        self._receipts.append(receipt)

        return response


class ReceiptedOpenAI:
    """
    Drop-in replacement for openai.OpenAI that generates RCPT receipts
    for every API call.

    Usage:
        client = ReceiptedOpenAI(api_key="sk-...")
        response = client.chat.completions.create(model="gpt-4o", messages=[...])
        print(client.receipts)  # list of Receipt objects
    """

    def __init__(
        self,
        rcpt_client: Optional[RCPTClient] = None,
        **openai_kwargs: Any,
    ):
        """
        Args:
            rcpt_client: Optional RCPTClient. Generated if not provided.
            **openai_kwargs: Passed directly to openai.OpenAI() (api_key, base_url, etc.)
        """
        self._openai = OpenAI(**openai_kwargs)
        self._rcpt = rcpt_client or RCPTClient()
        self.receipts: List[Receipt] = []

        self.chat = ReceiptedChat(self._openai.chat, self._rcpt, self.receipts)
        self.embeddings = ReceiptedEmbeddings(self._openai.embeddings, self._rcpt, self.receipts)

    @property
    def receipt_count(self) -> int:
        return len(self.receipts)

    @property
    def agent_id(self) -> str:
        return self._rcpt.agent_id

    def export_receipts(self, format: str = "json") -> str:
        """Export all receipts."""
        if format == "eu-ai-act":
            return self._rcpt.export(format="eu-ai-act")
        return json.dumps([r.to_dict() for r in self.receipts], indent=2)

    def verify_all(self) -> bool:
        """Verify all stored receipts."""
        return all(self._rcpt.verify(r) for r in self.receipts)

    def __getattr__(self, name: str) -> Any:
        """Proxy everything else to the underlying OpenAI client."""
        return getattr(self._openai, name)
