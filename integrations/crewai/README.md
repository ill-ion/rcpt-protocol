# RCPT × CrewAI

Automatic receipt generation for CrewAI multi-agent workflows. Every agent step, tool call, and task completion gets a signed, chained, verifiable receipt.

## Install

```bash
pip install rcpt crewai
```

## Quick Start

```python
from crewai import Agent, Task, Crew
from rcpt import RCPTClient
from rcpt_crewai import RCPTCrewPlugin

client = RCPTClient()
plugin = RCPTCrewPlugin(client)

researcher = Agent(role="Researcher", goal="Find data", tools=[search_tool])
writer = Agent(role="Writer", goal="Write report")

task1 = Task(description="Research AI trends", agent=researcher)
task2 = Task(description="Write summary", agent=writer)

crew = Crew(agents=[researcher, writer], tasks=[task1, task2])

# Run with RCPT receipts
result = plugin.kickoff(crew)

print(f"Generated {plugin.receipt_count} receipts")
print(plugin.export(format="eu-ai-act"))
```

## Receipt Chain Structure

```
Crew Kickoff (delegation)
├── Researcher: tool_call (search)
├── Researcher: tool_call (search)
├── Task 1 Complete (inference)
├── Writer: inference
└── Task 2 Complete (inference)
```

Every receipt is chained to its parent via `parent_receipt_id`, and all share a `workflow_id` for grouping.

## License

Apache 2.0
