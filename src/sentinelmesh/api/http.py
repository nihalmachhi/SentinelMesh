"""Loopback-only API with per-run authorization and simulated actions."""

from __future__ import annotations

import hmac
import json
import logging
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote, urlparse

from sentinelmesh.core.config import DB_PATH, MAX_IMPORT_BYTES, ROOT, SAMPLE_FLOWS
from sentinelmesh.ingest.flows import parse_flows
from sentinelmesh.investigation.tools import investigate, propose_simulated_action
from sentinelmesh.metrics import PROCESS_METRICS
from sentinelmesh.pipeline import run_pipeline
from sentinelmesh.storage.sqlite import Store

logger = logging.getLogger(__name__)
FRONTEND = ROOT / "frontend" / "index.html"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
CONTENT_SECURITY_POLICY = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"


def _host_port(value: str) -> tuple[str | None, int | None]:
    parsed = urlparse("//" + value)
    try:
        return parsed.hostname, parsed.port
    except ValueError:
        return None, None


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
                value
                if isinstance(value, bytes)
                else json.dumps(value, ensure_ascii=True).encode("utf-8")
            )
            PROCESS_METRICS.request(self.command)
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
            self.end_headers()
            self.wfile.write(body)

        def _request_origin_is_safe(self) -> bool:
            host_value = self.headers.get("Host", "")
            host, port = _host_port(host_value)
            if host not in LOOPBACK_HOSTS:
                return False
            server_port = getattr(self.server, "server_port", None)
            if server_port is not None and (port if port is not None else 80) != server_port:
                return False
            origin = self.headers.get("Origin")
            if origin is None:
                return True
            parsed = urlparse(origin)
            origin_host, origin_port = _host_port(parsed.netloc)
            return (
                parsed.scheme == "http"
                and origin_host == host
                and parsed.netloc.lower() == host_value.lower()
                and (origin_port is None or server_port is None or origin_port == server_port)
            )

        def _authorized(self) -> bool:
            supplied = self.headers.get("Authorization", "")
            prefix = "Bearer "
            return supplied.startswith(prefix) and hmac.compare_digest(
                supplied[len(prefix) :], token
            )

        def do_GET(self) -> None:
            try:
                if not self._request_origin_is_safe():
                    self.reply({"error": "request host or origin is not allowed"}, 403)
                    return
                path = urlparse(self.path).path
                if path == "/":
                    page = FRONTEND.read_text(encoding="utf-8")
                    self.reply(page.encode("utf-8"), content_type="text/html; charset=utf-8")
                elif path == "/api/health":
                    self.reply({"status": "ok", "mode": "synthetic-defense-lab"})
                elif path == "/metrics":
                    with Store(DB_PATH) as store:
                        body = PROCESS_METRICS.render(store.summary()).encode("utf-8")
                    self.reply(body, content_type="text/plain; version=0.0.4; charset=utf-8")
                elif path == "/sample":
                    self.reply(
                        SAMPLE_FLOWS.read_bytes(),
                        content_type="application/json; charset=utf-8",
                    )
                elif path.startswith("/api/"):
                    with Store(DB_PATH) as store:
                        if path == "/api/summary":
                            self.reply(store.summary())
                        elif path == "/api/graph":
                            from sentinelmesh.correlation.graph import graph_summary
                            from sentinelmesh.ingest.flows import parse_flow

                            try:
                                flows = [parse_flow(row) for row in store.list_flows()]
                                self.reply(graph_summary(flows))
                            except RuntimeError as exc:
                                self.reply({"error": str(exc)}, 503)
                        elif path == "/api/flows":
                            self.reply(store.list_flows())
                        elif path.startswith("/api/flows/"):
                            flow = store.get_flow(unquote(path.rsplit("/", 1)[-1]))
                            self.reply(flow or {"error": "flow not found"}, 200 if flow else 404)
                        elif path == "/api/drift":
                            from sentinelmesh.core.models import Flow
                            from sentinelmesh.drift import drift_report

                            self.reply(drift_report([Flow(**item) for item in store.list_flows()]))
                        elif path == "/api/findings":
                            self.reply(store.list_findings())
                        elif path == "/api/incidents":
                            self.reply(store.list_incidents())
                        elif path.startswith("/api/incidents/"):
                            item = store.get_incident(unquote(path.rsplit("/", 1)[-1]))
                            self.reply(
                                item or {"error": "incident not found"},
                                200 if item else 404,
                            )
                        else:
                            self.reply({"error": "not found"}, 404)
                else:
                    self.reply({"error": "not found"}, 404)
            except Exception:
                logger.exception("GET request failed")
                self.reply({"error": "internal server error"}, 500)

        def do_POST(self) -> None:
            try:
                if not self._request_origin_is_safe():
                    self.reply({"error": "request host or origin is not allowed"}, 403)
                    return
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
                raw_body = self.rfile.read(min(length, MAX_IMPORT_BYTES + 1))
                if len(raw_body) != length or len(raw_body) > MAX_IMPORT_BYTES:
                    self.reply({"error": "request body length is invalid"}, 400)
                    return
                body = json.loads(raw_body)
                path = urlparse(self.path).path
                if path == "/api/analyze":
                    flows = parse_flows(body)
                    started = time.perf_counter()
                    with Store(DB_PATH) as store:
                        result = run_pipeline(flows, store)
                        PROCESS_METRICS.analysis((time.perf_counter() - started) * 1000)
                        self.reply(result, 201)
                    return
                if not isinstance(body, dict):
                    raise ValueError("request body must be a JSON object")
                with Store(DB_PATH) as store:
                    if path.startswith("/api/incidents/") and path.endswith("/investigate"):
                        incident_id = unquote(path.split("/")[-2])
                        self.reply(investigate(store, incident_id), 201)
                        return
                    if path.startswith("/api/incidents/") and path.endswith("/simulate"):
                        incident_id = unquote(path.split("/")[-2])
                        item = propose_simulated_action(
                            store,
                            incident_id,
                            str(body.get("action", "")),
                            body.get("approved_by"),
                        )
                        self.reply(item, 201)
                        return
                self.reply({"error": "not found"}, 404)
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
