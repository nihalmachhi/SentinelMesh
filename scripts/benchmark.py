"""Measure validation, detection, and correlation on the locally generated sample."""

from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path
from typing import Any

from sentinelmesh.core.config import SAMPLE_FLOWS
from sentinelmesh.correlation.incidents import correlate
from sentinelmesh.detection.rules import detect
from sentinelmesh.ingest.flows import load_flows


def measure(path: Path, repeats: int) -> dict[str, Any]:
    if repeats < 1:
        raise ValueError("repeats must be positive")
    flows = load_flows(path)
    records = [flow.to_dict() for flow in flows]
    timings: dict[str, list[float]] = {"parse": [], "detect": [], "correlate": []}
    finding_count = 0
    incident_count = 0
    for _ in range(repeats):
        start = time.perf_counter_ns()
        parsed = load_flows(path)
        timings["parse"].append((time.perf_counter_ns() - start) / 1_000_000)

        start = time.perf_counter_ns()
        findings = detect(parsed)
        timings["detect"].append((time.perf_counter_ns() - start) / 1_000_000)

        finding_records = [finding.to_dict() for finding in findings]
        start = time.perf_counter_ns()
        incidents = correlate(finding_records, {row["flow_id"]: row for row in records})
        timings["correlate"].append((time.perf_counter_ns() - start) / 1_000_000)
        finding_count = len(findings)
        incident_count = len(incidents)

    return {
        "input_rows": len(flows),
        "findings": finding_count,
        "incidents": incident_count,
        "repeats": repeats,
        "median_ms": {
            name: round(statistics.median(values), 3) for name, values in timings.items()
        },
        "scope": "local synthetic fixture; stage timings exclude SQLite and HTTP",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=SAMPLE_FLOWS)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    print(json.dumps(measure(args.input, args.repeats), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
