"""
RCPT × CrewAI Integration

Automatic receipt generation for CrewAI agent workflows.
Generates receipts for agent steps, tool calls, task completions,
and crew-level orchestration with full receipt chaining across agents.

Usage:
    from crewai import Agent, Task, Crew
    from rcpt import RCPTClient
    from rcpt_crewai import RCPTCrewPlugin

    client = RCPTClient()
    plugin = RCPTCrewPlugin(client)

    # Wrap your crew
    crew = Crew(agents=[...], tasks=[...])
    result = plugin.kickoff(crew, inputs={...})

    # Every agent action now has a signed receipt
    print(plugin.receipts)
    print(plugin.export(format="eu-ai-act"))
"""

from __future__ import annotations

import json
import functools
from typing import Any, Dict, List, Optional, Callable

try:
    from crewai import Agent, Task, Crew
    from crewai.tools import BaseTool
    HAS_CREWAI = True
except ImportError:
    HAS_CREWAI = False

from rcpt import RCPTClient, ActionType, Receipt
from rcpt.models import generate_ulid


class RCPTCrewPlugin:
    """
    RCPT plugin for CrewAI that generates receipts for all agent actions.

    Creates a receipt chain across the entire crew workflow:
    - Crew kickoff → delegation receipt (root)
    - Each agent step → inference receipt (chained to crew)
    - Each tool call → tool_call receipt (chained to agent step)
    - Task completion → inference receipt with output hash

    All receipts share a workflow_id for easy grouping and export.
    """

    def __init__(
        self,
        client: Optional[RCPTClient] = None,
        *,
        workflow_id: Optional[str] = None,
        model_name: Optional[str] = None,
    ):
        """
        Args:
            client: RCPTClient instance. Generated if not provided.
            workflow_id: Optional workflow ID. Auto-generated if not provided.
            model_name: Default model name for receipts.
        """
        if not HAS_CREWAI:
            raise ImportError(
                "rcpt-crewai requires crewai. Install with: pip install crewai"
            )

        self.client = client or RCPTClient()
        self.workflow_id = workflow_id or generate_ulid()
        self.model_name = model_name
        self.receipts: List[Receipt] = []
        self._sequence = 0
        self._crew_receipt_id: Optional[str] = None
        self._agent_receipt_map: Dict[str, str] = {}  # agent role → latest receipt_id

    def kickoff(self, crew: Crew, inputs: Optional[Dict[str, Any]] = None) -> Any:
        """
        Run a CrewAI crew with RCPT receipt generation.

        Wraps the crew's kickoff to instrument all agent actions.
        """
        # Generate root delegation receipt for crew kickoff
        crew_description = f"Crew with {len(crew.agents)} agents, {len(crew.tasks)} tasks"
        self._crew_receipt_id = self._attest(
            action_type=ActionType.DELEGATION,
            output=crew_description,
            input_data=json.dumps(inputs) if inputs else None,
            description=f"Crew kickoff: {crew_description}",
            tags=["crew", "kickoff"],
        ).receipt_id

        # Wrap agent tools to generate receipts
        self._instrument_agents(crew.agents)

        # Wrap tasks to generate receipts on completion
        self._instrument_tasks(crew.tasks, crew.agents)

        # Run the crew
        result = crew.kickoff(inputs=inputs) if inputs else crew.kickoff()

        # Generate completion receipt
        self._attest(
            action_type=ActionType.INFERENCE,
            output=str(result),
            parent=self._crew_receipt_id,
            description="Crew completed",
            tags=["crew", "complete"],
        )

        return result

    def _instrument_agents(self, agents: List[Agent]) -> None:
        """Wrap agent tools to generate receipts on tool calls."""
        for agent in agents:
            if not agent.tools:
                continue
            wrapped_tools = []
            for tool in agent.tools:
                wrapped = self._wrap_tool(tool, agent.role)
                wrapped_tools.append(wrapped)
            agent.tools = wrapped_tools

    def _wrap_tool(self, tool: Any, agent_role: str) -> Any:
        """Wrap a tool's _run method to generate a receipt."""
        original_run = tool._run

        plugin = self

        @functools.wraps(original_run)
        def receipted_run(*args: Any, **kwargs: Any) -> Any:
            # Run the original tool
            result = original_run(*args, **kwargs)

            # Generate receipt
            parent = plugin._agent_receipt_map.get(agent_role, plugin._crew_receipt_id)
            tool_name = getattr(tool, 'name', type(tool).__name__)
            receipt = plugin._attest(
                action_type=ActionType.TOOL_CALL,
                output=str(result),
                input_data=json.dumps({"args": str(args), "kwargs": str(kwargs)}),
                parent=parent,
                description=f"{agent_role} → {tool_name}",
                tags=["tool_call", agent_role, tool_name],
            )
            plugin._agent_receipt_map[agent_role] = receipt.receipt_id

            return result

        tool._run = receipted_run
        return tool

    def _instrument_tasks(self, tasks: List[Task], agents: List[Agent]) -> None:
        """Wrap task callbacks to generate receipts on completion."""
        for task in tasks:
            original_callback = task.callback

            plugin = self
            task_desc = task.description[:100] if task.description else "task"

            def make_callback(orig_cb: Optional[Callable], desc: str) -> Callable:
                def receipted_callback(output: Any) -> Any:
                    agent_role = "unknown"
                    if hasattr(output, 'agent') and output.agent:
                        agent_role = output.agent

                    parent = plugin._agent_receipt_map.get(
                        agent_role, plugin._crew_receipt_id
                    )
                    receipt = plugin._attest(
                        action_type=ActionType.INFERENCE,
                        output=str(output),
                        parent=parent,
                        description=f"Task complete: {desc}",
                        tags=["task_complete", agent_role],
                    )
                    plugin._agent_receipt_map[agent_role] = receipt.receipt_id

                    if orig_cb:
                        return orig_cb(output)
                    return output

                return receipted_callback

            task.callback = make_callback(original_callback, task_desc)

    def _attest(
        self,
        action_type: ActionType,
        output: str,
        input_data: Optional[str] = None,
        parent: Optional[str] = None,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> Receipt:
        """Generate a receipt and store it."""
        kwargs: Dict[str, Any] = {
            "action_type": action_type,
            "output": output,
            "workflow_id": self.workflow_id,
            "sequence": self._sequence,
        }
        if input_data:
            kwargs["input_data"] = input_data
        if parent:
            kwargs["parent"] = parent
        if self.model_name:
            kwargs["model"] = self.model_name

        metadata: Dict[str, Any] = {}
        if description:
            metadata["description"] = description
        if tags:
            metadata["tags"] = tags
        if metadata:
            kwargs["metadata"] = metadata

        receipt = self.client.attest(**kwargs)
        self.receipts.append(receipt)
        self._sequence += 1
        return receipt

    @property
    def receipt_count(self) -> int:
        return len(self.receipts)

    def export(self, format: str = "json") -> str:
        """Export all receipts."""
        if format == "eu-ai-act":
            return self.client.export(format="eu-ai-act")
        return json.dumps([r.to_dict() for r in self.receipts], indent=2)

    def get_chain(self, receipt_id: Optional[str] = None) -> List[Receipt]:
        """Get receipt chain. Defaults to the last receipt."""
        target = receipt_id or (self.receipts[-1].receipt_id if self.receipts else None)
        if not target:
            return []
        return self.client.get_chain(target)

    def reset(self) -> None:
        """Clear all receipts and reset state."""
        self.receipts.clear()
        self._agent_receipt_map.clear()
        self._sequence = 0
        self._crew_receipt_id = None
        self.workflow_id = generate_ulid()
