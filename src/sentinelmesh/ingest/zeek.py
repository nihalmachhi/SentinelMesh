"""Read Zeek conn.log metadata into the common validated flow contract."""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import math
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinelmesh.core.config import MAX_IMPORT_BYTES
from sentinelmesh.ingest.flows import parse_flows

PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)
REQUIRED_FIELDS = {
    "ts",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "duration",
    "orig_bytes",
}


def _is_private(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return any(
        address in network for network in PRIVATE_NETWORKS if address.version == network.version
    )


def infer_direction(source: str, destination: str) -> str:
    source_private = _is_private(source)
    destination_private = _is_private(destination)
    if source_private and destination_private:
        return "internal"
    if source_private:
        return "outbound"
    if destination_private:
        return "inbound"
    return "unknown"


def _number(value: str, field: str, *, integer: bool = False) -> int | float:
    if value == "-":
        return 0
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ValueError(f"Zeek {field} must be numeric") from exc
    if integer:
        if not parsed.is_integer():
            raise ValueError(f"Zeek {field} must be an integer")
        return int(parsed)
    return parsed


def load_zeek_conn(path: Path) -> list[Any]:
    """Load Zeek tab-separated conn.log; payload fields are not read."""
    if path.stat().st_size > MAX_IMPORT_BYTES:
        raise ValueError(f"input exceeds {MAX_IMPORT_BYTES} byte limit")
    fields: list[str] | None = None
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8", newline="") as source:
        for line_number, row in enumerate(csv.reader(source, delimiter="\t"), start=1):
            if not row or row == [""]:
                continue
            if row[0].startswith("#fields"):
                fields = (
                    row[1:]
                    if row[0] == "#fields"
                    else row[0].split(" ", 1)[1].split("\t") + row[1:]
                )
                missing = REQUIRED_FIELDS - set(fields)
                if missing:
                    raise ValueError(f"Zeek conn.log missing fields: {', '.join(sorted(missing))}")
                continue
            if row[0].startswith("#"):
                continue
            if fields is None:
                raise ValueError("Zeek conn.log is missing its #fields header")
            if len(rows) >= 20_000:
                raise ValueError("input must contain at most 20,000 flows")
            if len(row) != len(fields):
                raise ValueError(f"Zeek row {line_number} has an unexpected number of fields")
            record = dict(zip(fields, row, strict=True))
            try:
                epoch_seconds = float(record["ts"])
                if not math.isfinite(epoch_seconds):
                    raise ValueError
                timestamp = datetime.fromtimestamp(epoch_seconds, UTC)
            except (ValueError, OverflowError, OSError) as exc:
                raise ValueError("Zeek ts must be finite Unix seconds") from exc
            source_ip = record["id.orig_h"]
            destination_ip = record["id.resp_h"]
            protocol = record["proto"].upper()
            if protocol == "ICMP6":
                protocol = "ICMP"
            digest = hashlib.sha256(f"{line_number}\0{row!r}".encode()).hexdigest()[:20]
            rows.append(
                {
                    "flow_id": f"zeek-{digest}",
                    "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                    "src_ip": source_ip,
                    "dst_ip": destination_ip,
                    "src_port": _number(record["id.orig_p"], "id.orig_p", integer=True),
                    "dst_port": _number(record["id.resp_p"], "id.resp_p", integer=True),
                    "protocol": protocol,
                    "duration_ms": _number(record["duration"], "duration") * 1000,
                    "packets": _number(record.get("orig_pkts", "0"), "orig_pkts", integer=True)
                    + _number(record.get("resp_pkts", "0"), "resp_pkts", integer=True),
                    "bytes_sent": _number(record["orig_bytes"], "orig_bytes", integer=True),
                    "direction": infer_direction(source_ip, destination_ip),
                }
            )
    return parse_flows(rows)
