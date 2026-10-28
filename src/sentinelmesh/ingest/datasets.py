"""Bounded, label-preserving adapters for public research flow CSV files."""

from __future__ import annotations

import csv
import hashlib
import math
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sentinelmesh.core.models import Flow
from sentinelmesh.ingest.flows import parse_flow
from sentinelmesh.ingest.zeek import infer_direction

DEFAULT_DATASET_LIMIT = 20_000
MAX_DATASET_LIMIT = 100_000


@dataclass(frozen=True)
class LabeledFlowDataset:
    name: str
    flows: list[Flow]
    labels: list[int]


def _cells(row: dict[str | None, str | None]) -> dict[str, str]:
    return {
        key.strip().casefold(): (value or "").strip()
        for key, value in row.items()
        if key is not None
    }


def _get(cells: dict[str, str], *names: str) -> str:
    for name in names:
        value = cells.get(name.casefold())
        if value is not None and value not in {"", "-"}:
            return value
    raise ValueError(f"required dataset column missing: {names[0]}")


def _number(cells: dict[str, str], name: str, *aliases: str, integer: bool = False) -> int | float:
    raw = _get(cells, name, *aliases)
    try:
        number = float(raw)
    except ValueError as exc:
        raise ValueError(f"dataset field {name} must be numeric") from exc
    if not math.isfinite(number) or number < 0 or (integer and not number.is_integer()):
        raise ValueError(f"dataset field {name} must be a non-negative finite number")
    return int(number) if integer else number


def _timestamp_cic(value: str, timezone_name: str | None) -> str:
    if timezone_name is None:
        raise ValueError("CIC timestamps are naive; pass --timezone explicitly")
    try:
        timezone = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"unknown timezone: {timezone_name}") from exc
    parsed: datetime | None = None
    for pattern in ("%d/%m/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(value, pattern)
            break
        except ValueError:
            continue
    if parsed is None:
        raise ValueError("CIC Timestamp has an unsupported format")
    return parsed.replace(tzinfo=timezone).astimezone(UTC).isoformat().replace("+00:00", "Z")


def _timestamp_epoch(value: str) -> str:
    try:
        timestamp = float(value)
        if not math.isfinite(timestamp):
            raise ValueError
        return datetime.fromtimestamp(timestamp, UTC).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError) as exc:
        raise ValueError("dataset timestamp must be finite Unix seconds") from exc


def _protocol(value: str) -> str:
    protocols = {
        "6": "TCP",
        "tcp": "TCP",
        "17": "UDP",
        "udp": "UDP",
        "1": "ICMP",
        "icmp": "ICMP",
        "icmp6": "ICMP",
    }
    result = protocols.get(value.casefold())
    if result is None:
        raise ValueError(f"unsupported dataset protocol: {value}")
    return result


def _identity(row_number: int, cells: dict[str, str]) -> str:
    original_id = cells.get("flow id") or cells.get("id")
    material = f"{row_number}\0{original_id or ''}\0{sorted(cells.items())}"
    return "dataset-" + hashlib.sha256(material.encode()).hexdigest()[:20]


def _flow(
    row_number: int,
    cells: dict[str, str],
    *,
    timestamp: str,
    duration_ms: float,
    packets: int,
    bytes_sent: int,
) -> Flow:
    src_ip = _get(cells, "source ip", "srcip")
    dst_ip = _get(cells, "destination ip", "dstip")
    return parse_flow(
        {
            "flow_id": _identity(row_number, cells),
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": _number(cells, "source port", "srcport", "sport", integer=True),
            "dst_port": _number(cells, "destination port", "dstport", "dsport", integer=True),
            "protocol": _protocol(_get(cells, "protocol", "proto")),
            "duration_ms": duration_ms,
            "packets": packets,
            "bytes_sent": bytes_sent,
            "direction": infer_direction(src_ip, dst_ip),
        }
    )


def _label(cells: dict[str, str], *, cic: bool) -> int:
    if cic:
        label = _get(cells, "label").strip().casefold()
        return 0 if label in {"benign", "normal"} else 1
    raw = cells.get("label")
    if raw is not None and raw != "":
        if raw not in {"0", "1"}:
            raise ValueError("UNSW label must be 0 or 1")
        return int(raw)
    category = cells.get("attack_cat", "").strip().casefold()
    if category:
        return int(category not in {"normal", "benign", "-", "nan"})
    raise ValueError("UNSW dataset must contain label or attack_cat")


def _read_csv(path: Path, limit: int) -> Iterator[tuple[int, dict[str, str]]]:
    if not 1 <= limit <= MAX_DATASET_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_DATASET_LIMIT}")
    with path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        for row_number, row in enumerate(reader, start=2):
            if row_number - 1 > limit:
                break
            yield row_number, _cells(row)


def load_cic_ids2017(
    path: Path, *, timezone_name: str | None, limit: int = DEFAULT_DATASET_LIMIT
) -> LabeledFlowDataset:
    flows: list[Flow] = []
    labels: list[int] = []
    for row_number, cells in _read_csv(path, limit):
        duration_ms = float(_number(cells, "flow duration")) / 1000
        packet_count = int(
            _number(cells, "total fwd packets", "tot fwd pkts", integer=True)
            + _number(cells, "total backward packets", "tot bwd pkts", integer=True)
        )
        bytes_sent = int(
            _number(cells, "total length of fwd packets", "totlen fwd pkts", integer=True)
        )
        flow = _flow(
            row_number,
            cells,
            timestamp=_timestamp_cic(_get(cells, "timestamp"), timezone_name),
            duration_ms=duration_ms,
            packets=packet_count,
            bytes_sent=bytes_sent,
        )
        flows.append(flow)
        labels.append(_label(cells, cic=True))
    if not flows:
        raise ValueError("CIC-IDS2017 CSV contains no data rows")
    ordered = sorted(zip(flows, labels, strict=True), key=lambda row: row[0].timestamp)
    return LabeledFlowDataset(
        "CIC-IDS2017", [row[0] for row in ordered], [row[1] for row in ordered]
    )


def load_unsw_nb15(path: Path, *, limit: int = DEFAULT_DATASET_LIMIT) -> LabeledFlowDataset:
    flows: list[Flow] = []
    labels: list[int] = []
    for row_number, cells in _read_csv(path, limit):
        duration_ms = float(_number(cells, "dur")) * 1000
        packets = int(_number(cells, "spkts", integer=True) + _number(cells, "dpkts", integer=True))
        flow = _flow(
            row_number,
            cells,
            timestamp=_timestamp_epoch(_get(cells, "stime")),
            duration_ms=duration_ms,
            packets=packets,
            bytes_sent=int(_number(cells, "sbytes", integer=True)),
        )
        flows.append(flow)
        labels.append(_label(cells, cic=False))
    if not flows:
        raise ValueError("UNSW-NB15 CSV contains no data rows")
    ordered = sorted(zip(flows, labels, strict=True), key=lambda row: row[0].timestamp)
    return LabeledFlowDataset("UNSW-NB15", [row[0] for row in ordered], [row[1] for row in ordered])
