"""Distribution drift summaries for validated flow metadata."""

from __future__ import annotations

import bisect
import math
from collections.abc import Callable
from typing import Any

from sentinelmesh.core.models import Flow

FEATURES: dict[str, Callable[[Flow], float]] = {
    "bytes_sent": lambda flow: float(flow.bytes_sent),
    "duration_ms": lambda flow: flow.duration_ms,
    "packets": lambda flow: float(flow.packets),
}


def _psi(baseline: list[float], current: list[float], bins: int = 10) -> float:
    ordered = sorted(baseline)
    boundaries = [
        ordered[min(len(ordered) - 1, math.ceil(i * len(ordered) / bins) - 1)]
        for i in range(1, bins)
    ]
    baseline_counts = [0] * bins
    current_counts = [0] * bins
    for value in baseline:
        baseline_counts[bisect.bisect_left(boundaries, value)] += 1
    for value in current:
        current_counts[bisect.bisect_left(boundaries, value)] += 1
    score = 0.0
    for expected_count, actual_count in zip(baseline_counts, current_counts, strict=True):
        expected = max(expected_count / len(baseline), 1e-6)
        actual = max(actual_count / len(current), 1e-6)
        score += (actual - expected) * math.log(actual / expected)
    return score


def _ks(baseline: list[float], current: list[float]) -> float:
    first = sorted(baseline)
    second = sorted(current)
    values = sorted(set(first + second))
    return max(
        abs(
            bisect.bisect_right(first, value) / len(first)
            - bisect.bisect_right(second, value) / len(second)
        )
        for value in values
    )


def drift_report(flows: list[Flow]) -> dict[str, Any]:
    ordered = sorted(flows, key=lambda flow: flow.timestamp)
    if len(ordered) < 20:
        return {"status": "insufficient", "minimum_rows": 20, "rows": len(ordered)}
    split = len(ordered) // 2
    baseline, current = ordered[:split], ordered[split:]
    features = {}
    for name, getter in FEATURES.items():
        expected = [getter(flow) for flow in baseline]
        observed = [getter(flow) for flow in current]
        features[name] = {
            "psi": round(_psi(expected, observed), 6),
            "ks_statistic": round(_ks(expected, observed), 6),
        }
    return {
        "status": "ok",
        "baseline_rows": len(baseline),
        "current_rows": len(current),
        "split": "chronological 50/50",
        "features": features,
        "caveat": "Drift scores identify distribution change, not a security incident or model failure.",
    }
