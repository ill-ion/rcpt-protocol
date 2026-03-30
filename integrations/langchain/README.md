# RCPT × LangChain

Automatic receipt generation for every LLM call, tool invocation, and chain execution in LangChain / LangGraph workflows.

## Install

```bash
pip install rcpt rcpt-langchain
```

## Quick Start

```python
from langchain_anthropic import ChatAnthropic
from rcpt import RCPTClient
from rcpt_langchain import RCPTCallbackHandler

# Create RCPT client and callback handler
client = RCPTClient(private_key="base64url:...")
handler = RCPTCallbackHandler(client)

# Attach to any LangChain component
llm = ChatAnthropic(model="claude-sonnet-4-5", callbacks=[handler])
result = llm.invoke("What is the capital of France?")

# Every call now has a signed, verifiable receipt
print(f"Receipts generated: {handler.receipt_count}")
for receipt in handler.receipts:
    print(receipt.to_json())
```

## What Gets Receipted

| LangChain Event | RCPT Action Type | Triggered By |
|---|---|---|
| LLM completion | `inference` | `on_llm_end` |
| Tool execution | `tool_call` | `on_tool_end` |
| Chain completion | `inference` | `on_chain_end` |
| Agent action | `tool_call` | `on_agent_action` |
| Agent finish | `inference` | `on_agent_finish` |
| Retriever result | `observation` | `on_retriever_end` |

## Automatic Chaining

Receipts are automatically chained using LangChain's `run_id` and `parent_run_id`. A multi-step agent workflow produces a linked receipt chain that reconstructs the full decision path.

## With LangGraph

```python
from langgraph.graph import StateGraph
from rcpt import RCPTClient
from rcpt_langchain import RCPTCallbackHandler

client = RCPTClient()
handler = RCPTCallbackHandler(client, workflow_id="my-workflow")

# Build your graph as normal
graph = StateGraph(...)
app = graph.compile()

# Run with RCPT receipts
result = app.invoke({"input": "..."}, config={"callbacks": [handler]})

# Export for EU AI Act compliance
print(handler.export_receipts(format="eu-ai-act"))
```

## Configuration

```python
handler = RCPTCallbackHandler(
    client,
    workflow_id="custom-workflow-id",    # Group receipts under a workflow
    include_prompts=True,                # Hash input prompts (default: True)
    include_metadata=True,               # Include run metadata (default: True)
    model_name="claude-sonnet-4-5",  # Override model detection
)
```

## License

Apache 2.0
