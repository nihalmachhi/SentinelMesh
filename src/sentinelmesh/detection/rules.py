"""Explainable baseline rules for safe synthetic flow telemetry."""

from collections import defaultdict
from datetime import UTC, datetime

from sentinelmesh.core.config import (
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
    return findings
