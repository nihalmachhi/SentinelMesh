"""Compare flow volume with prior event-time records for its source."""

from collections import defaultdict, deque
from collections.abc import Sequence
from statistics import fmean, pstdev

from sentinelmesh.core.models import Finding, Flow
from sentinelmesh.detection.config import DetectionConfig


def detect(flows: Sequence[Flow], config: DetectionConfig) -> list[Finding]:
    by_source: dict[str, list[Flow]] = defaultdict(list)
    for flow in flows:
        if flow.direction in {"outbound", "internal"}:
            by_source[flow.src_ip].append(flow)
    findings = []
    for source, records in by_source.items():
        history: deque[Flow] = deque(maxlen=config.baseline_window_size)
        for flow in sorted(records, key=lambda item: item.timestamp_seconds):
            values = [item.bytes_sent for item in history]
            if len(values) >= config.baseline_min_history:
                mean, deviation = fmean(values), pstdev(values)
                z_score = (flow.bytes_sent - mean) / deviation if deviation else 0.0
                if z_score >= config.baseline_z_score_threshold:
                    findings.append(
                        Finding(
                            "host_egress_baseline",
                            "medium",
                            0.72,
                            "Flow volume exceeds its earlier host baseline",
                            "This flow is unusually large relative to earlier records for the same source; the baseline is a triage signal, not a verdict.",
                            tuple([item.flow_id for item in history] + [flow.flow_id]),
                            {
                                "source_ip": source,
                                "baseline_count": len(values),
                                "baseline_mean_bytes": round(mean, 3),
                                "baseline_std_bytes": round(deviation, 3),
                                "z_score": round(z_score, 3),
                                "history_window": config.baseline_window_size,
                            },
                        )
                    )
            history.append(flow)
    return findings
