"""Correlate evidence-linked findings into deterministic incident stories."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from sentinelmesh.core.timeutil import epoch_seconds


def _proximity_default() -> float:
    raw = os.getenv("SENTINELMESH_CORRELATION_PROXIMITY_SECONDS", "300")
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError("SENTINELMESH_CORRELATION_PROXIMITY_SECONDS must be numeric") from exc
    if value < 0:
        raise ValueError("correlation proximity must be non-negative")
    return value


def _iso_utc(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, UTC).isoformat().replace("+00:00", "Z")


def correlate(
    findings: list[dict[str, Any]],
    flows_by_id: dict[str, dict[str, Any]],
    proximity_seconds: float | None = None,
) -> list[dict[str, Any]]:
    proximity = _proximity_default() if proximity_seconds is None else proximity_seconds
    if proximity < 0:
        raise ValueError("proximity_seconds must be non-negative")
    enriched: list[tuple[dict[str, Any], set[str], float, float]] = []
    for finding in findings:
        evidence = [flows_by_id[item] for item in finding["evidence_ids"] if item in flows_by_id]
        hosts = {flow[key] for flow in evidence for key in ("src_ip", "dst_ip")}
        times = [epoch_seconds(flow["timestamp"]) for flow in evidence]
        enriched.append((finding, hosts, min(times, default=0), max(times, default=0)))

    parent = list(range(len(enriched)))

    def root(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    for left, (_, left_hosts, left_start, left_end) in enumerate(enriched):
        for right in range(left + 1, len(enriched)):
            _, right_hosts, right_start, right_end = enriched[right]
            gap = max(0.0, max(left_start, right_start) - min(left_end, right_end))
            if left_hosts & right_hosts and gap <= proximity:
                parent[root(right)] = root(left)

    groups: dict[int, list[int]] = {}
    for index in range(len(enriched)):
        groups.setdefault(root(index), []).append(index)
    severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    incidents = []
    for indexes in groups.values():
        items = [enriched[index][0] for index in indexes]
        ids = sorted({flow_id for item in items for flow_id in item["evidence_ids"]})
        incident_hosts = sorted({host for index in indexes for host in enriched[index][1]})
        starts = [enriched[index][2] for index in indexes if enriched[index][2]]
        ends = [enriched[index][3] for index in indexes if enriched[index][3]]
        host = incident_hosts[0] if incident_hosts else "unknown"
        incident_id = "inc-" + sha256((host + "\0" + "\0".join(ids)).encode()).hexdigest()[:12]
        incidents.append(
            {
                "incident_id": incident_id,
                "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "host": host,
                "hosts": incident_hosts,
                "window_start": _iso_utc(min(starts)) if starts else None,
                "window_end": _iso_utc(max(ends)) if ends else None,
                "status": "open",
                "severity": max(
                    (item["severity"] for item in items),
                    key=lambda level: severity_rank.get(level, -1),
                ),
                "finding_count": len(items),
                "evidence_ids": ids,
                "findings": items,
                "summary": f"{len(items)} finding(s) correlated across {len(incident_hosts)} host(s).",
            }
        )
    return sorted(incidents, key=lambda item: item["incident_id"])
