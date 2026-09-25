#!/usr/bin/env python3
"""Minimal HTTP front end for the ticket pipeline — the container's entry point.

Endpoints (Module 02 standard): GET /health, GET /ready, POST /predict.
Listens on 8080: a non-root process cannot bind ports below 1024, and it never needs
to. The Kubernetes Service and Ingress map the public 443 to it.

Hardening in the handler itself:
  * request body capped at MAX_BODY bytes, JSON only, required fields checked
  * API key read from a header, never from the URL (URLs end up in logs)
  * errors return a generic message; details go to the server log, not the client
  * no server/version banner
"""

import json
import logging
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from ticketbot.pipeline import Pipeline  # noqa: E402

PORT = int(os.environ.get("PORT", "8080"))
MAX_BODY = 8 * 1024
PIPELINE = Pipeline(guarded=True)
PIPELINE_LOCK = threading.Lock()       # rate-limit/budget counters and the DB handle are shared state

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ticketbot")


class Handler(BaseHTTPRequestHandler):
    def send_response(self, code, message=None):   # same as the base class, minus the Server banner
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_request(self, code="-", size="-"):   # one line per request: method, path, status; no bodies or keys
        log.info("%s %s -> %s", self.command, self.path.split("?")[0], code)

    def log_message(self, fmt, *args):
        log.info(fmt, *args)

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"status": "ok"})
        if self.path == "/ready":
            return self._send(200, {"status": "ready"})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/predict":
            return self._send(404, {"error": "not found"})
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            return self._send(415, {"error": "content type must be application/json"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._send(400, {"error": "bad request"})
        if length <= 0 or length > MAX_BODY:
            return self._send(413, {"error": f"body must be 1..{MAX_BODY} bytes"})
        try:
            req = json.loads(self.rfile.read(length))
            customer_id, text = req["customer_id"], req["text"]
            if not isinstance(customer_id, str) or not isinstance(text, str):
                raise ValueError("fields must be strings")
        except (ValueError, KeyError, TypeError):
            return self._send(400, {"error": "bad request"})
        try:
            with PIPELINE_LOCK:
                r = PIPELINE.handle(self.headers.get("X-API-Key", ""), customer_id, text)
        except Exception:
            log.exception("pipeline failure")
            return self._send(500, {"error": "internal error"})
        code = {"ok": 200, "blocked": 422, "rejected": 429 if r.stage in ("rate_limit", "budget") else 401}[r.status]
        return self._send(code, {"status": r.status, "reply": r.reply, "queue": r.queue})


def main():
    log.info("listening on :%d", PORT)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
