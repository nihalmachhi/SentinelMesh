"""Validate prepared flow JSON before it reaches storage."""

import ipaddress
import json
import math
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from sentinelmesh.core.config import MAX_IMPORT_BYTES
from sentinelmesh.core.models import Flow

REQUIRED = {
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
}
ALLOWED = REQUIRED | {"direction"}


def _ip(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an IP address string")
    return str(ipaddress.ip_address(value))


def parse_flow(item: Any) -> Flow:
    if not isinstance(item, dict):
        raise ValueError("each flow must be a JSON object")
    if not all(isinstance(key, str) for key in item):
        raise ValueError("flow field names must be strings")
    missing = REQUIRED - item.keys()
    if missing:
        raise ValueError(f"flow is missing fields: {', '.join(sorted(missing))}")
    extra = item.keys() - ALLOWED
    if extra:
        raise ValueError(f"flow has unknown fields: {', '.join(sorted(extra))}")
    if not isinstance(item["flow_id"], str) or not item["flow_id"].strip():
        raise ValueError("flow_id must be a non-empty string")
    protocol = str(item["protocol"]).upper()
    if protocol not in {"TCP", "UDP", "ICMP"}:
        raise ValueError(f"unsupported protocol: {protocol}")

    def integer(field: str, minimum: int, maximum: int) -> int:
        value = item[field]
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ValueError(f"{field} must be an integer in [{minimum}, {maximum}]")
        return cast(int, value)

    duration = item["duration_ms"]
    if (
        isinstance(duration, bool)
        or not isinstance(duration, (int, float))
        or not math.isfinite(duration)
        or not 0 <= duration <= 86_400_000
    ):
        raise ValueError("duration_ms must be a non-negative finite-range number")
    direction = str(item.get("direction", "unknown"))
    if direction not in {"inbound", "outbound", "internal", "unknown"}:
        raise ValueError("direction must be inbound, outbound, internal, or unknown")
    timestamp = item["timestamp"]
    if not isinstance(timestamp, str):
        raise ValueError("timestamp must be an ISO-8601 string with a timezone")
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise ValueError("timestamp must be an ISO-8601 string with a timezone") from exc
    if parsed_timestamp.tzinfo is None or parsed_timestamp.utcoffset() is None:
        raise ValueError("timestamp must include a timezone offset")
    normalized_timestamp = parsed_timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return Flow(
        flow_id=item["flow_id"].strip(),
        timestamp=normalized_timestamp,
        src_ip=_ip(item["src_ip"], "src_ip"),
        dst_ip=_ip(item["dst_ip"], "dst_ip"),
        src_port=integer("src_port", 0, 65535),
        dst_port=integer("dst_port", 0, 65535),
        protocol=protocol,
        duration_ms=float(duration),
        packets=integer("packets", 0, 100_000_000),
        bytes_sent=integer("bytes_sent", 0, 10**12),
        direction=direction,
    )


def parse_flows(raw: Any) -> list[Flow]:
    if not isinstance(raw, list) or not raw or len(raw) > 20_000:
        raise ValueError("input must be a non-empty JSON array with at most 20,000 flows")
    flows = [parse_flow(row) for row in raw]
    if len({flow.flow_id for flow in flows}) != len(flows):
        raise ValueError("flow_id values must be unique within an upload")
    return flows


def load_flows(path: Path) -> list[Flow]:
    if path.suffix.lower() != ".json":
        raise ValueError("MVP accepts JSON flow records only; PCAP parsing is not enabled")
    if path.stat().st_size > MAX_IMPORT_BYTES:
        raise ValueError(f"input exceeds {MAX_IMPORT_BYTES} byte limit")
    raw = json.loads(path.read_text(encoding="utf-8"))
    return parse_flows(raw)
