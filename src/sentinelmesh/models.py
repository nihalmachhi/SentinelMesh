"""Small typed contracts shared by the pipeline."""
from dataclasses import asdict, dataclass
from typing import Any

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
    direction: str = "outbound"
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    score: float
    title: str
    summary: str
    evidence_ids: tuple[str, ...]
    observed_features: dict[str, Any]
    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["evidence_ids"] = list(self.evidence_ids)
        return value
