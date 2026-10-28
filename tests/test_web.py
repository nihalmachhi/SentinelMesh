from __future__ import annotations

import http.client
import io
import json
import logging
import threading
from email.message import Message
from http.server import ThreadingHTTPServer

from sentinelmesh.api import http as web


def request(
    handler_type,
    path="/api/analyze",
    *,
    host="127.0.0.1:8000",
    origin="http://127.0.0.1:8000",
    token="secret",
    content_type="application/json",
    body=b"[]",
    length=None,
):
    handler = handler_type.__new__(handler_type)
    handler.path = path
    handler.headers = Message()
    handler.headers["Host"] = host
    if origin is not None:
        handler.headers["Origin"] = origin
    if token is not None:
        handler.headers["Authorization"] = f"Bearer {token}"
    if content_type is not None:
        handler.headers["Content-Type"] = content_type
    handler.headers["Content-Length"] = str(len(body) if length is None else length)
    handler.rfile = io.BytesIO(body)
    handler.server = type("Server", (), {"server_port": 8000})()
    result = []
    handler.reply = lambda payload, status=200, content_type="application/json; charset=utf-8": (
        result.append((payload, status, content_type))
    )
    handler.do_POST()
    return result[0]


def test_post_requires_token_json_loopback_and_same_origin():
    handler = web.create_handler("secret")
    assert request(handler, token=None)[1] == 403
    assert request(handler, host="attacker.example", origin="http://attacker.example")[1] == 403
    assert request(handler, origin="http://evil.example")[1] == 403
    assert request(handler, content_type="text/plain")[1] == 415


def test_post_rejects_empty_and_invalid_lengths():
    handler = web.create_handler("secret")
    assert request(handler, body=b"", length=0)[1] == 400
    assert request(handler, body=b"[]", length="-1")[1] == 400
    assert request(handler, body=b"[]", length="not-a-number")[1] == 400
    assert request(handler, body=b"x", length=2_000_001)[1] == 413


def test_non_dict_row_and_unexpected_errors_return_json(monkeypatch, tmp_path, flow_row):
    handler = web.create_handler("secret")
    monkeypatch.setattr(web, "DB_PATH", tmp_path / "db.sqlite3")
    payload, status, content = request(handler, body=json.dumps(["not an object"]).encode())
    assert status == 400 and content.startswith("application/json")
    assert "JSON object" in payload["error"]
    duplicate = request(handler, body=json.dumps([flow_row, flow_row]).encode())
    assert duplicate[1] == 400 and "unique" in duplicate[0]["error"]

    class BrokenStore:
        def __init__(self, path):
            raise RuntimeError("database unavailable")

    monkeypatch.setattr(web, "Store", BrokenStore)
    instance = handler.__new__(handler)
    instance.path = "/api/incidents"
    instance.headers = Message()
    instance.headers["Host"] = "127.0.0.1:8000"
    instance.server = type("Server", (), {"server_port": 8000})()
    result = []
    instance.reply = lambda payload, status=200, content_type="application/json; charset=utf-8": (
        result.append((payload, status, content_type))
    )
    instance.do_GET()
    assert result[0][1] == 500 and result[0][0]["error"] == "internal server error"
    failed_post = request(handler, body=json.dumps([flow_row]).encode())
    assert failed_post[1] == 500 and failed_post[0]["error"] == "internal server error"


def test_request_logging_uses_format_string(caplog):
    handler = web.create_handler("secret").__new__(web.create_handler("secret"))
    handler.address_string = lambda: "127.0.0.1"
    with caplog.at_level(logging.INFO, logger=web.__name__):
        handler.log_message("%s %s", "GET", "/api/health")
    assert "GET /api/health" in caplog.text


def test_real_loopback_server_enforces_auth_and_sets_security_headers():
    server = ThreadingHTTPServer(("127.0.0.1", 0), web.create_handler("integration-token"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_port
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        connection.request("GET", "/api/health")
        response = connection.getresponse()
        assert response.status == 200
        assert response.getheader("X-Frame-Options") == "DENY"
        assert "frame-ancestors 'none'" in response.getheader("Content-Security-Policy")
        response.read()

        headers = {"Content-Type": "application/json", "Authorization": "Bearer integration-token"}
        connection.request("POST", "/api/analyze", body="[]", headers=headers)
        response = connection.getresponse()
        assert response.status == 400
        response.read()

        connection.request(
            "POST", "/api/analyze", body="[]", headers={"Content-Type": "application/json"}
        )
        response = connection.getresponse()
        assert response.status == 403
        response.read()

        headers["Origin"] = "http://attacker.example"
        connection.request("POST", "/api/analyze", body="[]", headers=headers)
        response = connection.getresponse()
        assert response.status == 403
        response.read()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_server_refuses_non_loopback_bind():
    import pytest

    with pytest.raises(ValueError, match="loopback"):
        web.serve("0.0.0.0", 8000)
