"""Correlate evidence-linked findings into deterministic incident stories."""

from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from typing import Any


def _timestamp(value: str) -> float:
    parsed = datetime.fromisoformat(value)
    return parsed.astimezone(UTC).timestamp()


def correlate(
    findings: list[dict[str, Any]], flows_by_id: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    enriched: list[tuple[dict[str, Any], set[str], float, float]] = []
    for finding in findings:
        evidence = [flows_by_id[item] for item in finding["evidence_ids"] if item in flows_by_id]
        hosts = {flow[key] for flow in evidence for key in ("src_ip", "dst_ip")}
        times = [_timestamp(flow["timestamp"]) for flow in evidence]
        enriched.append((finding, hosts, min(times, default=0), max(times, default=0)))
    parent = list(range(len(enriched)))

    def root(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    for left in range(len(enriched)):
        _, left_hosts, left_start, left_end = enriched[left]
        for right in range(left + 1, len(enriched)):
            _, right_hosts, right_start, right_end = enriched[right]
            shared_host = bool(left_hosts & right_hosts)
            overlapping_window = max(left_start, right_start) <= min(left_end, right_end)
            if shared_host or overlapping_window:
                parent[root(right)] = root(left)
    groups: dict[int, list[int]] = {}
    for index in range(len(enriched)):
        groups.setdefault(root(index), []).append(index)
    severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    incidents = []
    for indexes in groups.values():
        items = [enriched[index][0] for index in indexes]
        ids = sorted({evidence_id for item in items for evidence_id in item["evidence_ids"]})
        incident_hosts = sorted({host for index in indexes for host in enriched[index][1]})
        host = incident_hosts[0] if incident_hosts else "unknown"
        starts = [enriched[index][2] for index in indexes if enriched[index][2]]
        ends = [enriched[index][3] for index in indexes if enriched[index][3]]
        incident_id = (
            "inc-" + sha256((host + "\0" + "\0".join(ids)).encode("utf-8")).hexdigest()[:12]
        )
        incidents.append(
            {
                "incident_id": incident_id,
                "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "host": host,
                "hosts": incident_hosts,
                "window_start": min(starts) if starts else None,
                "window_end": max(ends) if ends else None,
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
