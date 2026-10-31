"""Immutable domain contracts used across the analysis pipeline."""

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

from sentinelmesh.core.timeutil import epoch_seconds


@dataclass(frozen=True)
class Flow:
    flow_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    duration_ms: float
    packets: int
    bytes_sent: int
    direction: str = "unknown"
    timestamp_seconds: float = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "timestamp_seconds", epoch_seconds(self.timestamp))

    def to_dict(self) -> dict[str, Any]:
        return {
            name: getattr(self, name)
            for name in (
                "flow_id",
                "timestamp",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "protocol",
                "duration_ms",
                "packets",
                "bytes_sent",
                "direction",
            )
        }


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    score: float
    title: str
    summary: str
    evidence_ids: tuple[str, ...]
    observed_features: dict[str, Any]
    finding_id: str = field(init=False)

    def __post_init__(self) -> None:
        evidence = "\0".join(sorted(self.evidence_ids))
        digest = sha256(f"{self.rule_id}\0{evidence}".encode()).hexdigest()[:16]
        object.__setattr__(self, "finding_id", f"finding-{digest}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "score": self.score,
            "title": self.title,
            "summary": self.summary,
            "evidence_ids": list(self.evidence_ids),
            "observed_features": self.observed_features,
        }


@dataclass(frozen=True)
class Incident:
    incident_id: str
    created_at: str
    host: str
    hosts: tuple[str, ...]
    window_start: str | None
    window_end: str | None
    status: str
    severity: str
    finding_count: int
    evidence_ids: tuple[str, ...]
    findings: tuple[dict[str, Any], ...]
    summary: str


@dataclass(frozen=True)
class Report:
    report_id: str
    incident_id: str
    created_at: str
    content: dict[str, Any]


@dataclass(frozen=True)
class Approval:
    approval_id: str
    incident_id: str
    decision: str
    created_at: str


@dataclass(frozen=True)
class AttackMapping:
    technique_id: str
    technique: str
    tactic: str
    url: str
    interpretation: str
