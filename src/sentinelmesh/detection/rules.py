"""Explainable baseline rules for safe synthetic flow telemetry."""

from collections import defaultdict, deque
from datetime import UTC, datetime
from itertools import pairwise
from statistics import fmean, pstdev

from sentinelmesh.core.config import (
    BASELINE_MIN_HISTORY,
    BASELINE_WINDOW_SIZE,
    BASELINE_Z_SCORE_THRESHOLD,
    BEACON_MAX_COEFFICIENT_OF_VARIATION,
    BEACON_MAX_INTERVAL_SECONDS,
    BEACON_MIN_FLOWS,
    BEACON_MIN_INTERVAL_SECONDS,
    EGRESS_RATE_BYTES_PER_SECOND,
    MULTI_PORT_MINIMUM_PORTS,
    MULTI_PORT_WINDOW_SECONDS,
)
from sentinelmesh.core.models import Finding, Flow

SENSITIVE_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB", 1433: "MSSQL"}


def _seconds(flow: Flow) -> float:
    value = datetime.fromisoformat(flow.timestamp)
    return value.astimezone(UTC).timestamp()


def _multi_port_finding(source: str, window: list[Flow]) -> Finding:
    ports = {item.dst_port for item in window}
    return Finding(
        rule_id="multi_port_activity",
        severity="medium",
        score=0.70,
        title="One source contacted many service ports",
        summary="Destination-port variety in a five-minute window can indicate scanning or routine administration; investigate context.",
        evidence_ids=tuple(sorted(item.flow_id for item in window)),
        observed_features={
            "source_ip": source,
            "flow_count": len(window),
            "unique_ports": len(ports),
            "window_seconds": MULTI_PORT_WINDOW_SECONDS,
        },
    )


def _flush_multi_port(source: str, active_flows: dict[str, Flow], findings: list[Finding]) -> None:
    if active_flows:
        findings.append(_multi_port_finding(source, list(active_flows.values())))
        active_flows.clear()


def _beacon_findings(by_source: dict[str, list[Flow]]) -> list[Finding]:
    findings: list[Finding] = []
    for source, records in by_source.items():
        by_peer: dict[tuple[str, int, str], list[Flow]] = defaultdict(list)
        for flow in records:
            by_peer[(flow.dst_ip, flow.dst_port, flow.protocol)].append(flow)
        for (destination, port, protocol), peer_flows in by_peer.items():
            ordered = sorted(peer_flows, key=_seconds)
            intervals = [
                _seconds(current) - _seconds(previous) for previous, current in pairwise(ordered)
            ]
            if len(ordered) < BEACON_MIN_FLOWS or not intervals:
                continue
            mean_interval = fmean(intervals)
            if not BEACON_MIN_INTERVAL_SECONDS <= mean_interval <= BEACON_MAX_INTERVAL_SECONDS:
                continue
            deviation = pstdev(intervals)
            coefficient = deviation / mean_interval if mean_interval else float("inf")
            if coefficient > BEACON_MAX_COEFFICIENT_OF_VARIATION:
                continue
            findings.append(
                Finding(
                    rule_id="periodic_connection",
                    severity="medium",
                    score=0.66,
                    title="Regularly spaced outbound connections",
                    summary="Repeated near-periodic flow timing may be a beacon or an expected scheduled client; verify host and destination context.",
                    evidence_ids=tuple(sorted(flow.flow_id for flow in ordered)),
                    observed_features={
                        "source_ip": source,
                        "destination_ip": destination,
                        "destination_port": port,
                        "flow_count": len(ordered),
                        "mean_interval_seconds": round(mean_interval, 3),
                        "interval_coefficient_of_variation": round(coefficient, 6),
                    },
                )
            )
    return findings


def _baseline_findings(by_source: dict[str, list[Flow]]) -> list[Finding]:
    findings: list[Finding] = []
    for source, records in by_source.items():
        ordered = sorted(records, key=_seconds)
        history: deque[Flow] = deque(maxlen=BASELINE_WINDOW_SIZE)
        for flow in ordered:
            values = [item.bytes_sent for item in history]
            if len(values) >= BASELINE_MIN_HISTORY:
                mean_bytes = fmean(values)
                deviation = pstdev(values)
                z_score = (flow.bytes_sent - mean_bytes) / deviation if deviation else 0.0
                if z_score >= BASELINE_Z_SCORE_THRESHOLD:
                    findings.append(
                        Finding(
                            rule_id="host_egress_baseline",
                            severity="medium",
                            score=0.72,
                            title="Flow volume exceeds its earlier host baseline",
                            summary="This flow is unusually large relative to earlier records for the same source; the baseline is a triage signal, not a verdict.",
                            evidence_ids=tuple([item.flow_id for item in history] + [flow.flow_id]),
                            observed_features={
                                "source_ip": source,
                                "baseline_count": len(values),
                                "baseline_mean_bytes": round(mean_bytes, 3),
                                "baseline_std_bytes": round(deviation, 3),
                                "z_score": round(z_score, 3),
                                "history_window": BASELINE_WINDOW_SIZE,
                            },
                        )
                    )
            history.append(flow)
    return findings


def detect(flows: list[Flow]) -> list[Finding]:
    findings: list[Finding] = []
    by_source: dict[str, list[Flow]] = defaultdict(list)
    for flow in flows:
        if flow.direction in {"outbound", "internal"}:
            by_source[flow.src_ip].append(flow)
        if flow.dst_port in SENSITIVE_PORTS and flow.direction == "outbound":
            findings.append(
                Finding(
                    rule_id="outbound_sensitive_service",
                    severity="medium",
                    score=0.62,
                    title=f"Outbound connection to {SENSITIVE_PORTS[flow.dst_port]} service",
                    summary="A flow targets a commonly sensitive service port. This is a triage signal, not proof of compromise.",
                    evidence_ids=(flow.flow_id,),
                    observed_features={
                        "destination_port": flow.dst_port,
                        "protocol": flow.protocol,
                        "bytes_sent": flow.bytes_sent,
                    },
                )
            )
        if (
            flow.direction in {"outbound", "internal"}
            and flow.duration_ms > 0
            and flow.bytes_sent / (flow.duration_ms / 1000) >= EGRESS_RATE_BYTES_PER_SECOND
        ):
            findings.append(
                Finding(
                    rule_id="high_egress_rate",
                    severity="high",
                    score=0.84,
                    title="Unusually high outbound transfer rate",
                    summary="Observed byte rate exceeds the configurable demo threshold; validate against host role and baseline.",
                    evidence_ids=(flow.flow_id,),
                    observed_features={
                        "bytes_sent": flow.bytes_sent,
                        "duration_ms": flow.duration_ms,
                        "threshold_bytes_per_second": EGRESS_RATE_BYTES_PER_SECOND,
                    },
                )
            )
    for source, records in by_source.items():
        ordered = sorted(records, key=_seconds)
        left = 0
        active_flows: dict[str, Flow] = {}
        active_end = float("-inf")

        for right, current in enumerate(ordered):
            current_time = _seconds(current)
            while current_time - _seconds(ordered[left]) > MULTI_PORT_WINDOW_SECONDS:
                left += 1
            window = ordered[left : right + 1]
            ports = {item.dst_port for item in window}
            window_start = _seconds(window[0])
            if len(ports) >= MULTI_PORT_MINIMUM_PORTS:
                if active_flows and window_start > active_end:
                    _flush_multi_port(source, active_flows, findings)
                active_flows.update({item.flow_id: item for item in window})
                active_end = current_time
            else:
                _flush_multi_port(source, active_flows, findings)
        _flush_multi_port(source, active_flows, findings)
    findings.extend(_beacon_findings(by_source))
    findings.extend(_baseline_findings(by_source))
    return findings
