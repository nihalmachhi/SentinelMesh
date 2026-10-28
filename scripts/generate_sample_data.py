"""Create the deterministic synthetic flow sample used by the demo."""

from __future__ import annotations

import argparse
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "data" / "generated" / "sample_flows.json"
BASE_TIME = datetime(2025, 1, 1, tzinfo=UTC)
PORTS = (443, 53, 8080, 8443, 22, 445, 3389, 123, 5000)


def build_flows(count: int, seed: int) -> list[dict[str, Any]]:
    """Build repeatable benign and deliberately suspicious lab scenarios."""
    if count < 1:
        raise ValueError("count must be positive")
    rng = random.Random(seed)
    flows: list[dict[str, Any]] = []
    for index in range(count):
        host_number = index % 12 + 1
        round_number = index // 12
        scan_pattern = round_number % 50 < 5
        dst_port = (
            PORTS[round_number % 5] if scan_pattern else rng.choice((443, 443, 443, 53, 8443))
        )
        direction = "internal" if dst_port in {445, 5000} else "outbound"
        timestamp = BASE_TIME + timedelta(seconds=round_number * 20 + host_number)
        bytes_sent = rng.randint(300, 80_000)
        duration_ms = rng.randint(50, 8_000)
        if round_number % 53 == 0 and host_number == 1:
            bytes_sent = 60_000_000
            duration_ms = 1_000
        flows.append(
            {
                "flow_id": f"sample-{index + 1:05d}",
                "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                "src_ip": f"10.20.{(host_number - 1) // 254}.{(host_number - 1) % 254 + 1}",
                "dst_ip": f"198.51.100.{index % 200 + 1}",
                "src_port": rng.randint(32_768, 60_000),
                "dst_port": dst_port,
                "protocol": "UDP" if dst_port in {53, 123} else "TCP",
                "duration_ms": duration_ms,
                "packets": rng.randint(1, 120),
                "bytes_sent": bytes_sent,
                "direction": direction,
            }
        )
    return flows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=600, help="number of synthetic flow rows")
    parser.add_argument("--seed", type=int, default=41, help="stable random seed")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    records = build_flows(args.count, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(records)} synthetic flows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
