"""Low-cardinality process-local metrics for the local API."""

from __future__ import annotations

import math
import threading
from collections import defaultdict, deque


class ProcessMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: dict[str, int] = defaultdict(int)
        self._analysis_ms: deque[float] = deque(maxlen=1_000)

    def request(self, method: str) -> None:
        if method not in {"GET", "POST"}:
            method = "OTHER"
        with self._lock:
            self._requests[method] += 1

    def analysis(self, duration_ms: float) -> None:
        with self._lock:
            self._analysis_ms.append(max(0.0, duration_ms))

    def render(self, counts: dict[str, int]) -> str:
        with self._lock:
            requests = dict(self._requests)
            timings = sorted(self._analysis_ms)
        lines = [
            "# HELP sentinelmesh_http_requests_total HTTP responses emitted by method.",
            "# TYPE sentinelmesh_http_requests_total counter",
        ]
        lines.extend(
            f'sentinelmesh_http_requests_total{{method="{method}"}} {count}'
            for method, count in sorted(requests.items())
        )
        lines.extend(
            [
                "# TYPE sentinelmesh_flows gauge",
                f"sentinelmesh_flows {counts['flow_count']}",
                "# TYPE sentinelmesh_findings gauge",
                f"sentinelmesh_findings {counts['finding_count']}",
                "# TYPE sentinelmesh_incidents gauge",
                f"sentinelmesh_incidents {counts['incident_count']}",
                "# TYPE sentinelmesh_analysis_duration_ms summary",
            ]
        )
        if timings:
            for quantile in (0.5, 0.95):
                index = max(0, math.ceil(quantile * len(timings)) - 1)
                lines.append(
                    f'sentinelmesh_analysis_duration_ms{{quantile="{quantile}"}} {timings[index]:.3f}'
                )
            lines.append(f"sentinelmesh_analysis_duration_ms_count {len(timings)}")
        else:
            lines.extend(
                [
                    'sentinelmesh_analysis_duration_ms{quantile="0.5"} 0',
                    'sentinelmesh_analysis_duration_ms{quantile="0.95"} 0',
                    "sentinelmesh_analysis_duration_ms_count 0",
                ]
            )
        return "\n".join(lines) + "\n"


PROCESS_METRICS = ProcessMetrics()
