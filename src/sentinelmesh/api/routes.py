"""Explicit HTTP route table and endpoint implementations."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from importlib.resources import files
from re import Match
from typing import Any
from urllib.parse import unquote

from sentinelmesh import __version__
from sentinelmesh.core.config import DB_PATH, SAMPLE_FLOWS
from sentinelmesh.core.models import Flow
from sentinelmesh.correlation.graph import graph_summary
from sentinelmesh.drift import drift_report
from sentinelmesh.ingest.flows import parse_flow, parse_flows
from sentinelmesh.investigation.tools import investigate, propose_simulated_action
from sentinelmesh.metrics import PROCESS_METRICS
from sentinelmesh.pipeline import run_pipeline
from sentinelmesh.storage.sqlite import Store

WEB = files("sentinelmesh.web")
FRONTEND = WEB.joinpath("index.html")
STATIC = {
    "/static/styles.css": (WEB.joinpath("static", "styles.css"), "text/css; charset=utf-8"),
    "/static/app.js": (WEB.joinpath("static", "app.js"), "text/javascript; charset=utf-8"),
}
Endpoint = Callable[[Any, Match[str], Any], None]


def home(request: Any, match: Match[str], body: Any) -> None:
    request.reply(WEB.joinpath("index.html").read_bytes(), content_type="text/html; charset=utf-8")


def asset(request: Any, match: Match[str], body: Any) -> None:
    resource, content_type = STATIC[request.route_path]
    request.reply(resource.read_bytes(), content_type=content_type)


def health(request: Any, match: Match[str], body: Any) -> None:
    request.reply({"status": "ok", "mode": "synthetic-defense-lab"})


def version(request: Any, match: Match[str], body: Any) -> None:
    request.reply({"name": "sentinelmesh", "version": __version__})


def sample(request: Any, match: Match[str], body: Any) -> None:
    request.reply(SAMPLE_FLOWS.read_bytes(), content_type="application/json; charset=utf-8")


def metrics(request: Any, match: Match[str], body: Any) -> None:
    with Store(DB_PATH) as store:
        data = PROCESS_METRICS.render(store.summary()).encode()
    request.reply(data, content_type="text/plain; version=0.0.4; charset=utf-8")


def summary(request: Any, match: Match[str], body: Any) -> None:
    with Store(DB_PATH) as store:
        request.reply(store.summary())


def graph(request: Any, match: Match[str], body: Any) -> None:
    with Store(DB_PATH) as store:
        try:
            request.reply(graph_summary([parse_flow(row) for row in store.list_flows()]))
        except RuntimeError as exc:
            request.reply({"error": str(exc)}, 503)


def flows(request: Any, match: Match[str], body: Any) -> None:
    with Store(DB_PATH) as store:
        request.reply(store.list_flows())


def flow(request: Any, match: Match[str], body: Any) -> None:
    with Store(DB_PATH) as store:
        item = store.get_flow(unquote(match[1]))
    request.reply(item or {"error": "flow not found"}, 200 if item else 404)


def drift(request: Any, match: Match[str], body: Any) -> None:
    with Store(DB_PATH) as store:
        request.reply(drift_report([Flow(**item) for item in store.list_flows()]))


def findings(request: Any, match: Match[str], body: Any) -> None:
    with Store(DB_PATH) as store:
        request.reply(store.list_findings())


def incidents(request: Any, match: Match[str], body: Any) -> None:
    with Store(DB_PATH) as store:
        request.reply(store.list_incidents())


def incident(request: Any, match: Match[str], body: Any) -> None:
    with Store(DB_PATH) as store:
        item = store.get_incident(unquote(match[1]))
    request.reply(item or {"error": "incident not found"}, 200 if item else 404)


def session(request: Any, match: Match[str], body: Any) -> None:
    """Successful token authorization acknowledges analyst mode for this run."""
    request.reply({"status": "authorized"})


def analyze(request: Any, match: Match[str], body: Any) -> None:
    flow_items = parse_flows(body)
    started = time.perf_counter()
    with Store(DB_PATH) as store:
        result = run_pipeline(flow_items, store)
        PROCESS_METRICS.analysis((time.perf_counter() - started) * 1000)
        request.reply(result, 201)


def investigate_incident(request: Any, match: Match[str], body: Any) -> None:
    with Store(DB_PATH) as store:
        request.reply(investigate(store, unquote(match[1])), 201)


def simulate_incident(request: Any, match: Match[str], body: Any) -> None:
    with Store(DB_PATH) as store:
        item = propose_simulated_action(
            store, unquote(match[1]), str(body.get("action", "")), body.get("approved_by")
        )
    request.reply(item, 201)


ROUTES: dict[str, tuple[tuple[re.Pattern[str], Endpoint], ...]] = {
    "GET": (
        (re.compile(r"^/$"), home),
        (re.compile(r"^/static/(?:styles\.css|app\.js)$"), asset),
        (re.compile(r"^/api/health$"), health),
        (re.compile(r"^/api/version$"), version),
        (re.compile(r"^/sample$"), sample),
        (re.compile(r"^/metrics$"), metrics),
        (re.compile(r"^/api/summary$"), summary),
        (re.compile(r"^/api/graph$"), graph),
        (re.compile(r"^/api/flows$"), flows),
        (re.compile(r"^/api/flows/(.+)$"), flow),
        (re.compile(r"^/api/drift$"), drift),
        (re.compile(r"^/api/findings$"), findings),
        (re.compile(r"^/api/incidents$"), incidents),
        (re.compile(r"^/api/incidents/(.+)$"), incident),
    ),
    "POST": (
        (re.compile(r"^/api/session$"), session),
        (re.compile(r"^/api/analyze$"), analyze),
        (re.compile(r"^/api/incidents/(.+)/investigate$"), investigate_incident),
        (re.compile(r"^/api/incidents/(.+)/simulate$"), simulate_incident),
    ),
}


def resolve_route(method: str, path: str) -> tuple[Endpoint, Match[str]] | None:
    for pattern, endpoint in ROUTES.get(method, ()):
        match = pattern.fullmatch(path)
        if match:
            return endpoint, match
    return None
