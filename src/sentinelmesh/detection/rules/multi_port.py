"""Five-minute source port-diversity detector."""

from collections.abc import Sequence

from sentinelmesh.core.models import Finding, Flow
from sentinelmesh.detection.config import DetectionConfig


def detect(flows: Sequence[Flow], config: DetectionConfig) -> list[Finding]:
    by_source: dict[str, list[Flow]] = {}
    for flow in flows:
        if flow.direction in {"outbound", "internal"}:
            by_source.setdefault(flow.src_ip, []).append(flow)
    findings = []
    for source, records in by_source.items():
        ordered = sorted(records, key=lambda item: item.timestamp_seconds)
        left = 0
        active: dict[str, Flow] = {}
        active_end = float("-inf")
        for right, current in enumerate(ordered):
            stamp = current.timestamp_seconds
            while stamp - ordered[left].timestamp_seconds > config.multi_port_window_seconds:
                left += 1
            window = ordered[left : right + 1]
            if len({item.dst_port for item in window}) >= config.multi_port_minimum_ports:
                if active and ordered[left].timestamp_seconds > active_end:
                    findings.append(_finding(source, active, config))
                    active.clear()
                active.update((item.flow_id, item) for item in window)
                active_end = stamp
            elif active:
                findings.append(_finding(source, active, config))
                active.clear()
        if active:
            findings.append(_finding(source, active, config))
    return findings


def _finding(source: str, flows: dict[str, Flow], config: DetectionConfig) -> Finding:
    records = list(flows.values())
    return Finding(
        "multi_port_activity",
        "medium",
        0.70,
        "One source contacted many service ports",
        "Destination-port variety in a five-minute window can indicate scanning or routine administration; investigate context.",
        tuple(sorted(item.flow_id for item in records)),
        {
            "source_ip": source,
            "flow_count": len(records),
            "unique_ports": len({item.dst_port for item in records}),
            "window_seconds": config.multi_port_window_seconds,
        },
    )
