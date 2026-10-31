"""Detect low-variance repeated connections to the same peer."""

from collections import defaultdict
from collections.abc import Sequence
from itertools import pairwise
from statistics import fmean, pstdev

from sentinelmesh.core.models import Finding, Flow
from sentinelmesh.detection.config import DetectionConfig


def detect(flows: Sequence[Flow], config: DetectionConfig) -> list[Finding]:
    peers: dict[tuple[str, str, int, str], list[Flow]] = defaultdict(list)
    for flow in flows:
        if flow.direction in {"outbound", "internal"}:
            peers[(flow.src_ip, flow.dst_ip, flow.dst_port, flow.protocol)].append(flow)
    findings = []
    for (source, destination, port, protocol), records in peers.items():
        ordered = sorted(records, key=lambda item: item.timestamp_seconds)
        intervals = [b.timestamp_seconds - a.timestamp_seconds for a, b in pairwise(ordered)]
        if len(ordered) < config.beacon_min_flows or not intervals:
            continue
        mean = fmean(intervals)
        if not config.beacon_min_interval_seconds <= mean <= config.beacon_max_interval_seconds:
            continue
        deviation = pstdev(intervals)
        coefficient = deviation / mean if mean else float("inf")
        if coefficient <= config.beacon_max_coefficient_of_variation:
            findings.append(
                Finding(
                    "periodic_connection",
                    "medium",
                    0.66,
                    "Regularly spaced outbound connections",
                    "Repeated near-periodic flow timing may be a beacon or an expected scheduled client; verify host and destination context.",
                    tuple(sorted(item.flow_id for item in ordered)),
                    {
                        "source_ip": source,
                        "destination_ip": destination,
                        "destination_port": port,
                        "flow_count": len(ordered),
                        "mean_interval_seconds": round(mean, 3),
                        "interval_coefficient_of_variation": round(coefficient, 6),
                    },
                )
            )
    return findings
