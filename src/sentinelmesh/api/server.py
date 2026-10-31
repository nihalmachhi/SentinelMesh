"""Loopback HTTP server lifecycle and request dispatch."""

from __future__ import annotations

import json
import logging
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from sentinelmesh.api import routes
from sentinelmesh.api.security import (
    LOOPBACK_HOSTS,
    bearer_token_is_valid,
    request_origin_is_safe,
    response_security_headers,
)
from sentinelmesh.core.config import DB_PATH, MAX_IMPORT_BYTES
from sentinelmesh.metrics import PROCESS_METRICS
from sentinelmesh.storage.sqlite import Store

logger = logging.getLogger(__name__)
FRONTEND = routes.WEB.joinpath("index.html")


def create_handler(admin_token: str | None = None) -> type[BaseHTTPRequestHandler]:
    token = admin_token or secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        def reply(
            self,
            value: Any,
            status: int = 200,
            content_type: str = "application/json; charset=utf-8",
        ) -> None:
            body = (
                value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=True).encode()
            )
            PROCESS_METRICS.request(self.command)
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            response_security_headers(self)
            self.end_headers()
            self.wfile.write(body)

        def _request_origin_is_safe(self) -> bool:
            return request_origin_is_safe(self)

        def _authorized(self) -> bool:
            return bearer_token_is_valid(self, token)

        def _dispatch(self, method: str) -> None:
            if not self._request_origin_is_safe():
                self.reply({"error": "request host or origin is not allowed"}, 403)
                return
            body: Any = None
            if method == "POST":
                if not self._authorized():
                    self.reply({"error": "valid bearer token required"}, 403)
                    return
                content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                if content_type != "application/json":
                    self.reply({"error": "Content-Type must be application/json"}, 415)
                    return
                raw_length = self.headers.get("Content-Length")
                if raw_length is None or not raw_length.isascii() or not raw_length.isdigit():
                    self.reply({"error": "Content-Length must be a non-negative integer"}, 400)
                    return
                length = int(raw_length)
                if length <= 0:
                    self.reply({"error": "request body must not be empty"}, 400)
                    return
                if length > MAX_IMPORT_BYTES:
                    self.reply({"error": f"request exceeds {MAX_IMPORT_BYTES} byte limit"}, 413)
                    return
                raw_body = self.rfile.read(length)
                if len(raw_body) != length:
                    self.reply({"error": "request body length is invalid"}, 400)
                    return
                body = json.loads(raw_body)
                if urlparse(self.path).path != "/api/analyze" and not isinstance(body, dict):
                    raise ValueError("request body must be a JSON object")

            path = urlparse(self.path).path
            resolved = routes.resolve_route(method, path)
            if resolved is None:
                self.reply({"error": "not found"}, 404)
                return
            endpoint, match = resolved
            self.route_path = path
            endpoint(self, match, body)

        def do_GET(self) -> None:
            try:
                self._dispatch("GET")
            except Exception:
                logger.exception("GET request failed")
                self.reply({"error": "internal server error"}, 500)

        def do_POST(self) -> None:
            try:
                self._dispatch("POST")
            except KeyError as exc:
                self.reply({"error": str(exc)}, 404)
            except PermissionError as exc:
                self.reply({"error": str(exc)}, 403)
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self.reply({"error": str(exc)}, 400)
            except Exception:
                logger.exception("POST request failed")
                self.reply({"error": "internal server error"}, 500)

        def log_message(self, fmt: str, *args: object) -> None:
            logger.info("%s - %s", self.address_string(), fmt % args)

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    if host not in LOOPBACK_HOSTS:
        raise ValueError("Dashboard binds to loopback only")
    with Store(DB_PATH):
        pass
    token = secrets.token_urlsafe(32)
    server = ThreadingHTTPServer((host, port), create_handler(token))
    print(f"SentinelMesh dashboard: http://{host}:{server.server_port} (synthetic lab only)")
    print(f"Per-run admin token (keep local): {token}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SentinelMesh.")
    finally:
        server.server_close()
