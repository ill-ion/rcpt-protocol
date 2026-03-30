"""
RCPT × LangChain Integration

Automatic receipt generation for every LLM call, tool invocation,
and chain execution in LangChain / LangGraph workflows.

Usage:
    from rcpt import RCPTClient
    from rcpt_langchain import RCPTCallbackHandler

    client = RCPTClient(private_key="base64url:...")
    handler = RCPTCallbackHandler(client)

    # Attach to any LangChain component
    llm = ChatAnthropic(model="claude-sonnet-4-5", callbacks=[handler])
    result = llm.invoke("What is 2+2?")

    # Every LLM call, tool call, and chain run now has a signed receipt
    print(handler.receipts)  # list of Receipt objects
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.outputs import LLMResult
    from langchain_core.agents import AgentAction, AgentFinish
except ImportError:
    raise ImportError(
        "rcpt-langchain requires langchain-core. "
        "Install with: pip install langchain-core"
    )

from rcpt import RCPTClient, ActionType, Receipt
from rcpt.hashing import hash_content


class RCPTCallbackHandler(BaseCallbackHandler):
    """
    LangChain callback handler that generates RCPT receipts for agent actions.

    Generates receipts for:
    - LLM calls (inference receipts)
    - Tool invocations (tool_call receipts)
    - Chain runs (inference receipts with chaining)
    - Agent actions (delegation + tool_call receipts)

    Receipts are automatically chained within a workflow using run IDs.
    """

    def __init__(
        self,
        client: RCPTClient,
        *,
        workflow_id: Optional[str] = None,
        include_prompts: bool = True,
        include_metadata: bool = True,
        model_name: Optional[str] = None,
        framework_version: Optional[str] = None,
    ):
        """
        Args:
            client: RCPTClient instance for signing receipts.
            workflow_id: Optional workflow ID to group all receipts. Auto-generated if not provided.
            include_prompts: If True, hash input prompts into receipts (input_hash field).
            include_metadata: If True, include run metadata in receipts.
            model_name: Override model name detection (e.g., "claude-sonnet-4-5").
            framework_version: LangChain version string for the framework field.
        """
        super().__init__()
        self.client = client
        self.workflow_id = workflow_id
        self.include_prompts = include_prompts
        self.include_metadata = include_metadata
        self.model_name = model_name
        self.framework_version = framework_version

        # Receipt storage
        self.receipts: List[Receipt] = []

        # Track run_id → receipt_id for chaining
        self._run_receipt_map: Dict[str, str] = {}
        # Track run_id → parent_run_id for hierarchy
        self._run_parent_map: Dict[str, Optional[str]] = {}
        # Track sequence within workflow
        self._sequence = 0

    @property
    def receipt_count(self) -> int:
        """Number of receipts generated."""
        return len(self.receipts)

    def _get_parent_receipt_id(self, parent_run_id: Optional[UUID]) -> Optional[str]:
        """Resolve parent run ID to parent receipt ID."""
        if parent_run_id is None:
            return None
        return self._run_receipt_map.get(str(parent_run_id))

    def _make_receipt(
        self,
        action_type: ActionType,
        output: Any,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        input_data: Any = None,
        model: Optional[str] = None,
        metadata: Optional[dict] = None,
        tags: Optional[List[str]] = None,
    ) -> Receipt:
        """Create and store a receipt."""
        parent_receipt = self._get_parent_receipt_id(parent_run_id)

        kwargs: Dict[str, Any] = {
            "action_type": action_type,
            "output": _serialize(output),
            "framework": "langchain",
        }

        if self.include_prompts and input_data is not None:
            kwargs["input_data"] = _serialize(input_data)

        effective_model = model or self.model_name
        if effective_model:
            kwargs["model"] = effective_model

        if parent_receipt or self.workflow_id:
            kwargs["parent"] = parent_receipt
            kwargs["workflow_id"] = self.workflow_id
            kwargs["sequence"] = self._sequence

        if self.include_metadata:
            meta: Dict[str, Any] = {}
            if metadata:
                meta["description"] = json.dumps(metadata)[:200]
            if tags:
                meta["tags"] = tags
            if meta:
                kwargs["metadata"] = meta

        receipt = self.client.attest(**kwargs)
        self.receipts.append(receipt)

        # Track for chaining
        self._run_receipt_map[str(run_id)] = receipt.receipt_id
        self._run_parent_map[str(run_id)] = str(parent_run_id) if parent_run_id else None
        self._sequence += 1

        return receipt

    # ── LLM callbacks ───────────────────────────────────────────────────────

    def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Generate an inference receipt when an LLM call completes."""
        # Extract output text
        output_text = ""
        if response.generations:
            gen_texts = []
            for gen_list in response.generations:
                for gen in gen_list:
                    gen_texts.append(gen.text)
            output_text = "\n".join(gen_texts)

        # Try to extract model name from response
        model = self.model_name
        if response.llm_output and isinstance(response.llm_output, dict):
            model = response.llm_output.get("model_name", model)

        self._make_receipt(
            action_type=ActionType.INFERENCE,
            output=output_text,
            run_id=run_id,
            parent_run_id=parent_run_id,
            model=model,
        )

    # ── Tool callbacks ──────────────────────────────────────────────────────

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Generate a tool_call receipt when a tool completes."""
        self._make_receipt(
            action_type=ActionType.TOOL_CALL,
            output=output,
            run_id=run_id,
            parent_run_id=parent_run_id,
        )

    # ── Chain callbacks ─────────────────────────────────────────────────────

    def on_chain_end(
        self,
        outputs: Dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Generate a receipt when a chain completes."""
        self._make_receipt(
            action_type=ActionType.INFERENCE,
            output=outputs,
            run_id=run_id,
            parent_run_id=parent_run_id,
            tags=["chain"],
        )

    # ── Agent callbacks ─────────────────────────────────────────────────────

    def on_agent_action(
        self,
        action: AgentAction,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Generate a receipt when an agent decides on an action."""
        self._make_receipt(
            action_type=ActionType.TOOL_CALL,
            output={"tool": action.tool, "tool_input": str(action.tool_input)},
            run_id=run_id,
            parent_run_id=parent_run_id,
            input_data=action.log,
            tags=["agent_action"],
        )

    def on_agent_finish(
        self,
        finish: AgentFinish,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Generate a receipt when an agent finishes."""
        self._make_receipt(
            action_type=ActionType.INFERENCE,
            output=finish.return_values,
            run_id=run_id,
            parent_run_id=parent_run_id,
            tags=["agent_finish"],
        )

    # ── Retriever callbacks ─────────────────────────────────────────────────

    def on_retriever_end(
        self,
        documents: Any,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Generate an observation receipt when a retriever returns documents."""
        doc_summary = []
        if hasattr(documents, '__iter__'):
            for doc in documents:
                if hasattr(doc, 'page_content'):
                    doc_summary.append(doc.page_content[:100])
                else:
                    doc_summary.append(str(doc)[:100])

        self._make_receipt(
            action_type=ActionType.OBSERVATION,
            output={"document_count": len(doc_summary), "preview": doc_summary[:3]},
            run_id=run_id,
            parent_run_id=parent_run_id,
            tags=["retriever"],
        )

    # ── Utility ─────────────────────────────────────────────────────────────

    def get_receipt_chain(self) -> List[Receipt]:
        """Get all receipts in order."""
        return list(self.receipts)

    def export_receipts(self, format: str = "json") -> str:
        """Export all receipts as JSON."""
        if format == "eu-ai-act":
            return self.client.export(format="eu-ai-act")
        return json.dumps([r.to_dict() for r in self.receipts], indent=2)

    def reset(self) -> None:
        """Clear all stored receipts and reset state."""
        self.receipts.clear()
        self._run_receipt_map.clear()
        self._run_parent_map.clear()
        self._sequence = 0


def _serialize(data: Any) -> str:
    """Convert arbitrary data to a string for hashing."""
    if isinstance(data, str):
        return data
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    try:
        return json.dumps(data, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(data)
