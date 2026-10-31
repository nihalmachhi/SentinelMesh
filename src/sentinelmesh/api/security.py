"""Request-origin, bearer-token, payload-size, and response-header policy."""

from __future__ import annotations

import hmac
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
)


def _host_port(value: str) -> tuple[str | None, int | None]:
    parsed = urlparse("//" + value)
    try:
        return parsed.hostname, parsed.port
    except ValueError:
        return None, None


def request_origin_is_safe(request: BaseHTTPRequestHandler) -> bool:
    host_value = request.headers.get("Host", "")
    host, port = _host_port(host_value)
    if host not in LOOPBACK_HOSTS:
        return False
    server_port = getattr(request.server, "server_port", None)
    if server_port is not None and (port if port is not None else 80) != server_port:
        return False
    origin = request.headers.get("Origin")
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


def bearer_token_is_valid(request: BaseHTTPRequestHandler, expected: str) -> bool:
    supplied = request.headers.get("Authorization", "")
    prefix = "Bearer "
    return supplied.startswith(prefix) and hmac.compare_digest(supplied[len(prefix) :], expected)


def response_security_headers(request: BaseHTTPRequestHandler) -> None:
    request.send_header("Cache-Control", "no-store")
    request.send_header("X-Content-Type-Options", "nosniff")
    request.send_header("X-Frame-Options", "DENY")
    request.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
