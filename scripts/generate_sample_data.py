"""Create repeatable synthetic network-flow scenarios for local testing."""

from __future__ import annotations

import argparse
import csv
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "data" / "samples"
DEFAULT_OUTPUT = SAMPLES / "sample_flows.json"
DEFAULT_LABELS = SAMPLES / "scenario_labels.csv"
BASE_TIME = datetime(2025, 1, 1, tzinfo=UTC)
NORMAL_PORTS = (53, 80, 443)
SCAN_PORTS = (21, 22, 23, 25, 53, 80, 445, 3389)


def _flow(
    index: int,
    when: datetime,
    source: str,
    destination: str,
    destination_port: int,
    protocol: str,
    duration_ms: int,
    packets: int,
    bytes_sent: int,
    direction: str = "outbound",
    source_port: int = 50_000,
) -> dict[str, Any]:
    return {
        "flow_id": f"sample-{index + 1:05d}",
        "timestamp": when.isoformat().replace("+00:00", "Z"),
        "src_ip": source,
        "dst_ip": destination,
        "src_port": source_port,
        "dst_port": destination_port,
        "protocol": protocol,
        "duration_ms": duration_ms,
        "packets": packets,
        "bytes_sent": bytes_sent,
        "direction": direction,
    }


def build_dataset(count: int, seed: int) -> tuple[list[dict[str, Any]], list[str]]:
    """Return rows and scenario labels in the same deterministic row order."""
    if count < 500:
        raise ValueError("count must be at least 500 synthetic rows")
    rng = random.Random(seed)
    flows: list[dict[str, Any]] = []
    labels: list[str] = []

    for index in range(count):
        when = BASE_TIME + timedelta(hours=2, seconds=index * 3)
        port = rng.choice(NORMAL_PORTS)
        flows.append(
            _flow(
                index,
                when,
                f"10.20.1.{index % 200 + 1}",
                f"203.0.113.{index % 250 + 1}",
                port,
                "UDP" if port == 53 else "TCP",
                rng.randint(100, 8_000),
                rng.randint(1, 80),
                rng.randint(250, 100_000),
                source_port=rng.randint(32_768, 60_000),
            )
        )
        labels.append("benign")

    for offset, port in enumerate(SCAN_PORTS):
        flows[offset] = _flow(
            offset,
            BASE_TIME + timedelta(seconds=offset * 20),
            "10.20.0.250",
            "198.51.100.10",
            port,
            "TCP",
            300,
            3,
            300,
            source_port=51_000 + offset,
        )
        labels[offset] = "port_scan"

    index = len(SCAN_PORTS)
    flows[index] = _flow(
        index,
        BASE_TIME + timedelta(minutes=5),
        "10.20.0.251",
        "203.0.113.40",
        443,
        "TCP",
        1_000,
        50_000,
        60_000_000,
    )
    labels[index] = "large_egress"

    index += 1
    for attempt in range(10):
        row = index + attempt
        flows[row] = _flow(
            row,
            BASE_TIME + timedelta(minutes=6, seconds=attempt * 10),
            "10.20.0.252",
            "198.51.100.22",
            22,
            "TCP",
            500,
            2,
            256,
            source_port=52_000 + attempt,
        )
        labels[row] = "repeated_ssh"

    index += 10
    for interval in range(12):
        row = index + interval
        flows[row] = _flow(
            row,
            BASE_TIME + timedelta(minutes=10 + interval),
            "10.20.0.253",
            "203.0.113.80",
            443,
            "TCP",
            1_000,
            12,
            4_096,
            source_port=53_000 + interval,
        )
        labels[row] = "beaconing"
    return flows, labels


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=600)
    parser.add_argument("--seed", type=int, default=41)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--labels-output", type=Path, default=DEFAULT_LABELS)
    args = parser.parse_args()
    rows, labels = build_dataset(args.count, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.labels_output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    with args.labels_output.open("w", newline="", encoding="utf-8") as output:
        writer = csv.writer(output)
        writer.writerow(("flow_id", "scenario"))
        writer.writerows((row["flow_id"], label) for row, label in zip(rows, labels, strict=True))
    print(f"Wrote {len(rows)} synthetic flows and scenario labels under {args.output.parent}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
