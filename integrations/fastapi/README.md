# RCPT × FastAPI

Automatic receipt generation for FastAPI-based agent APIs. Every request/response pair gets a signed receipt.

## Install

```bash
pip install rcpt fastapi
```

## Usage

```python
from fastapi import FastAPI
from rcpt_fastapi import RCPTMiddleware

app = FastAPI()
app.add_middleware(RCPTMiddleware)

@app.post("/agent/invoke")
async def invoke(prompt: str):
    return {"response": "Analysis complete"}
```

Every response now includes:
- `X-RCPT-Receipt-ID` header — the unique receipt ID
- `X-RCPT-Agent-ID` header — the agent's DID

## Built-in API

The middleware exposes introspection endpoints automatically:

| Endpoint | Description |
|---|---|
| `GET /rcpt/receipts` | List recent receipts |
| `GET /rcpt/receipt/{id}` | Get a specific receipt |
| `GET /rcpt/agent` | Agent identity and stats |
| `POST /rcpt/verify` | Verify a receipt (post JSON body) |

## Configuration

```python
from rcpt import RCPTClient

client = RCPTClient(private_key="base64url:...")

app.add_middleware(
    RCPTMiddleware,
    rcpt_client=client,
    include_paths=["/agent/", "/api/"],   # Only receipt these paths
    exclude_paths=["/health"],             # Skip these
    receipt_header="X-RCPT-Receipt-ID",    # Custom header name
    expose_api=True,                       # Enable /rcpt/* endpoints
)
```

## License

Apache 2.0
