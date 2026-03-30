"""
RCPT × FastAPI Middleware

Automatic receipt generation for FastAPI-based agent APIs.
Every request/response pair gets a signed, verifiable receipt.

Usage:
    from fastapi import FastAPI
    from rcpt_fastapi import RCPTMiddleware

    app = FastAPI()
    app.add_middleware(RCPTMiddleware)

    @app.post("/agent/invoke")
    async def invoke(prompt: str):
        return {"response": "Hello from the agent"}

    # Every response now includes an X-RCPT-Receipt-ID header.
    # Receipts are accessible at GET /rcpt/receipts
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable, Dict, List, Optional

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import Response, JSONResponse
except ImportError:
    raise ImportError(
        "rcpt-fastapi requires starlette (included with FastAPI). "
        "Install with: pip install fastapi"
    )

from rcpt import RCPTClient, ActionType, Receipt


class RCPTMiddleware(BaseHTTPMiddleware):
    """
    FastAPI/Starlette middleware that generates RCPT receipts for API calls.

    Adds receipt ID to response headers and provides a /rcpt/* API
    for querying receipts.

    Config:
        app.add_middleware(
            RCPTMiddleware,
            rcpt_client=RCPTClient(private_key="..."),
            include_paths=["/agent/", "/api/v1/"],
            exclude_paths=["/health", "/metrics"],
        )
    """

    def __init__(
        self,
        app: Any,
        rcpt_client: Optional[RCPTClient] = None,
        include_paths: Optional[List[str]] = None,
        exclude_paths: Optional[List[str]] = None,
        receipt_header: str = "X-RCPT-Receipt-ID",
        expose_api: bool = True,
    ):
        super().__init__(app)
        self.rcpt_client = rcpt_client or RCPTClient()
        self.include_paths = include_paths
        self.exclude_paths = exclude_paths or ["/rcpt/", "/health", "/docs", "/openapi.json"]
        self.receipt_header = receipt_header
        self.expose_api = expose_api
        self._receipts: List[Receipt] = []

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        # Handle RCPT API endpoints
        if self.expose_api and path.startswith("/rcpt/"):
            return await self._handle_rcpt_api(request, path)

        # Check if this path should be receipted
        if not self._should_receipt(path):
            return await call_next(request)

        # Read request body for input hash
        body = await request.body()
        input_data = body.decode("utf-8", errors="replace") if body else None

        # Time the request
        start = time.monotonic()
        response = await call_next(request)
        duration_ms = (time.monotonic() - start) * 1000

        # Read response body
        response_body = b""
        async for chunk in response.body_iterator:
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8")
            response_body += chunk

        # Generate receipt
        receipt = self.rcpt_client.attest(
            action_type=ActionType.INFERENCE,
            output=response_body.decode("utf-8", errors="replace"),
            input_data=input_data,
            metadata={
                "description": f"{request.method} {path}",
                "tags": [
                    "fastapi",
                    request.method.lower(),
                    f"status:{response.status_code}",
                ],
            },
        )
        self._receipts.append(receipt)

        # Build new response with receipt header
        new_response = Response(
            content=response_body,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
        )
        new_response.headers[self.receipt_header] = receipt.receipt_id
        new_response.headers["X-RCPT-Agent-ID"] = receipt.agent_id

        return new_response

    def _should_receipt(self, path: str) -> bool:
        """Determine if a path should generate a receipt."""
        # Check exclusions first
        for exc in self.exclude_paths:
            if path.startswith(exc):
                return False

        # If include_paths is set, only receipt matching paths
        if self.include_paths:
            return any(path.startswith(inc) for inc in self.include_paths)

        # Default: receipt everything not excluded
        return True

    async def _handle_rcpt_api(self, request: Request, path: str) -> Response:
        """Handle RCPT introspection API."""
        if path == "/rcpt/receipts":
            return JSONResponse([r.to_dict() for r in self._receipts[-100:]])

        if path == "/rcpt/agent":
            return JSONResponse({
                "agent_id": self.rcpt_client.agent_id,
                "public_key": self.rcpt_client.public_key,
                "receipt_count": len(self._receipts),
            })

        if path.startswith("/rcpt/receipt/"):
            receipt_id = path.split("/rcpt/receipt/")[1]
            for r in self._receipts:
                if r.receipt_id == receipt_id:
                    return JSONResponse(r.to_dict())
            return JSONResponse({"error": "Not found"}, status_code=404)

        if path == "/rcpt/verify":
            if request.method != "POST":
                return JSONResponse({"error": "POST required"}, status_code=405)
            body = await request.body()
            try:
                data = json.loads(body)
                receipt = Receipt.from_dict(data) if isinstance(data, dict) else Receipt.from_json(body.decode())
                valid = self.rcpt_client.verify(receipt)
                return JSONResponse({"valid": valid, "receipt_id": receipt.receipt_id})
            except Exception as e:
                return JSONResponse({"valid": False, "error": str(e)})

        return JSONResponse({"error": "Unknown RCPT endpoint"}, status_code=404)
