# RCPT × Anthropic

Drop-in replacement for the Anthropic Python SDK that generates a signed receipt for every API call.

## Install

```bash
pip install rcpt anthropic
```

## Usage

```python
from rcpt_anthropic import ReceiptedAnthropic

client = ReceiptedAnthropic(api_key="sk-ant-...")

message = client.messages.create(
    model="claude-sonnet-4-5",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Explain quantum computing in one sentence."}],
)

print(message.content[0].text)
print(client.receipts[-1].to_json())  # signed receipt
```

## What Gets Receipted

| API Call | Receipt Type |
|---|---|
| `messages.create()` | `inference` |
| Tool use in response | `tool_call` (chained to parent) |
| `messages.stream()` | `inference` (after stream completes) |

## License

Apache 2.0
