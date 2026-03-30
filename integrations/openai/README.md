# RCPT × OpenAI

Drop-in replacement for the OpenAI Python SDK that generates a signed receipt for every API call.

## Install

```bash
pip install rcpt openai
```

## Usage

```python
from rcpt_openai import ReceiptedOpenAI

# Use exactly like openai.OpenAI()
client = ReceiptedOpenAI(api_key="sk-...")

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "What is the capital of France?"}],
)

print(response.choices[0].message.content)  # "Paris"
print(client.receipt_count)                  # 1
print(client.receipts[-1].to_json())         # signed receipt

# Tool calls generate additional receipts
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "What's the weather?"}],
    tools=[...],
)
# Receipt for the inference + receipt for each tool call
```

## What Gets Receipted

| API Call | Receipt Type |
|---|---|
| `chat.completions.create()` | `inference` |
| Tool calls in response | `tool_call` (chained to parent inference) |
| `embeddings.create()` | `inference` |

## License

Apache 2.0
