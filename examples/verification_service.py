#!/usr/bin/env python3
"""
RCPT Verification Service

A lightweight HTTP API for public receipt verification.
No API key needed — anyone can submit a receipt and get verification.

Endpoints:
    POST /verify          — Verify a single receipt
    POST /verify/batch    — Verify an array of receipts
    POST /inspect         — Verify + return parsed receipt details
    GET  /health          — Health check

Run:
    python examples/verification_service.py
    # → Listening on http://localhost:8420

Test:
    curl -X POST http://localhost:8420/verify \
      -H "Content-Type: application/json" \
      -d @receipt.json
"""

import json
import sys
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk", "python"))

from rcpt import RCPTClient, Receipt

# We create a client for verification only (the keypair is irrelevant for verify)
verifier = RCPTClient()


class VerifyHandler(BaseHTTPRequestHandler):
    """HTTP request handler for receipt verification."""

    def do_GET(self):
        if self.path == "/health":
            self._json_response(200, {"status": "ok", "service": "rcpt-verify", "version": "0.1.0"})
        elif self.path == "/":
            self._json_response(200, {
                "service": "RCPT Receipt Verification Service",
                "endpoints": {
                    "POST /verify": "Verify a single receipt",
                    "POST /verify/batch": "Verify an array of receipts",
                    "POST /inspect": "Verify + return parsed details",
                    "GET /health": "Health check",
                },
                "docs": "https://rcpt.dev",
            })
        else:
            self._json_response(404, {"error": "Not found"})

    def do_POST(self):
        try:
            body = self._read_body()
            data = json.loads(body)
        except (json.JSONDecodeError, Exception) as e:
            self._json_response(400, {"error": f"Invalid JSON: {str(e)}"})
            return

        if self.path == "/verify":
            self._handle_verify(data)
        elif self.path == "/verify/batch":
            self._handle_verify_batch(data)
        elif self.path == "/inspect":
            self._handle_inspect(data)
        else:
            self._json_response(404, {"error": "Not found"})

    def _handle_verify(self, data: dict):
        """Verify a single receipt."""
        try:
            receipt = Receipt.from_dict(data)
            valid = verifier.verify(receipt)
            self._json_response(200, {
                "valid": valid,
                "receipt_id": receipt.receipt_id,
                "agent_id": receipt.agent_id,
            })
        except Exception as e:
            self._json_response(400, {"valid": False, "error": str(e)})

    def _handle_verify_batch(self, data: Any):
        """Verify an array of receipts."""
        if not isinstance(data, list):
            self._json_response(400, {"error": "Expected JSON array"})
            return

        results = []
        for item in data:
            try:
                receipt = Receipt.from_dict(item)
                valid = verifier.verify(receipt)
                results.append({
                    "receipt_id": receipt.receipt_id,
                    "valid": valid,
                })
            except Exception as e:
                results.append({
                    "receipt_id": item.get("receipt_id", "unknown"),
                    "valid": False,
                    "error": str(e),
                })

        valid_count = sum(1 for r in results if r["valid"])
        self._json_response(200, {
            "total": len(results),
            "valid": valid_count,
            "invalid": len(results) - valid_count,
            "results": results,
        })

    def _handle_inspect(self, data: dict):
        """Verify and return full receipt details."""
        try:
            receipt = Receipt.from_dict(data)
            valid = verifier.verify(receipt)

            detail = {
                "valid": valid,
                "receipt_id": receipt.receipt_id,
                "rcpt_version": receipt.rcpt_version,
                "timestamp": receipt.timestamp,
                "agent_id": receipt.agent_id,
                "action_type": receipt.action_type,
                "output_hash": receipt.output_hash,
                "signature_prefix": receipt.signature[:40] + "..." if receipt.signature else None,
            }

            if receipt.input_hash:
                detail["input_hash"] = receipt.input_hash
            if receipt.model:
                detail["model"] = f"{receipt.model.provider}/{receipt.model.model_id}"
            if receipt.chain:
                detail["parent_receipt_id"] = receipt.chain.parent_receipt_id
                detail["workflow_id"] = receipt.chain.workflow_id
            if receipt.metadata:
                if receipt.metadata.description:
                    detail["description"] = receipt.metadata.description
                if receipt.metadata.tags:
                    detail["tags"] = receipt.metadata.tags

            self._json_response(200, detail)
        except Exception as e:
            self._json_response(400, {"valid": False, "error": str(e)})

    def _read_body(self) -> str:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode("utf-8")

    def _json_response(self, code: int, data: Any):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def log_message(self, format, *args):
        """Cleaner log format."""
        sys.stderr.write(f"  {args[0]}\n")


def main():
    port = int(os.environ.get("PORT", 8420))
    server = HTTPServer(("0.0.0.0", port), VerifyHandler)
    print(f"RCPT Verification Service")
    print(f"  Listening on http://localhost:{port}")
    print(f"  POST /verify — verify a receipt")
    print(f"  POST /verify/batch — verify multiple receipts")
    print(f"  POST /inspect — verify + full details")
    print()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
