"""Single-flow sensitive-service and transfer-rate signals."""

from collections.abc import Sequence

from sentinelmesh.core.models import Finding, Flow
from sentinelmesh.detection.config import DetectionConfig

SENSITIVE_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB", 1433: "MSSQL"}


def detect(flows: Sequence[Flow], config: DetectionConfig) -> list[Finding]:
    findings: list[Finding] = []
    for flow in flows:
        if flow.dst_port in SENSITIVE_PORTS and flow.direction == "outbound":
            findings.append(
                Finding(
                    "outbound_sensitive_service",
                    "medium",
                    0.62,
                    f"Outbound connection to {SENSITIVE_PORTS[flow.dst_port]} service",
                    "A flow targets a commonly sensitive service port. This is a triage signal, not proof of compromise.",
                    (flow.flow_id,),
                    {
                        "destination_port": flow.dst_port,
                        "protocol": flow.protocol,
                        "bytes_sent": flow.bytes_sent,
                    },
                )
            )
        if (
            flow.direction in {"outbound", "internal"}
            and flow.duration_ms > 0
            and flow.bytes_sent / (flow.duration_ms / 1000) >= config.egress_rate_bytes_per_second
        ):
            findings.append(
                Finding(
                    "high_egress_rate",
                    "high",
                    0.84,
                    "Unusually high outbound transfer rate",
                    "Observed byte rate exceeds the configurable demo threshold; validate against host role and baseline.",
                    (flow.flow_id,),
                    {
                        "bytes_sent": flow.bytes_sent,
                        "duration_ms": flow.duration_ms,
                        "threshold_bytes_per_second": config.egress_rate_bytes_per_second,
                    },
                )
            )
    return findings
