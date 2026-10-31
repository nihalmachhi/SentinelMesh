"""Immutable, environment-overridable detection thresholds."""

import os
from dataclasses import dataclass


def _number(name: str, default: float, cast: type[int] | type[float]) -> int | float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = cast(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


@dataclass(frozen=True)
class DetectionConfig:
    egress_rate_bytes_per_second: float = 25_000_000
    multi_port_window_seconds: int = 300
    multi_port_minimum_ports: int = 5
    baseline_window_size: int = 50
    baseline_min_history: int = 5
    baseline_z_score_threshold: float = 3.0
    beacon_min_flows: int = 6
    beacon_min_interval_seconds: int = 30
    beacon_max_interval_seconds: int = 3600
    beacon_max_coefficient_of_variation: float = 0.05

    @classmethod
    def from_env(cls) -> "DetectionConfig":
        defaults = cls()
        return cls(
            egress_rate_bytes_per_second=float(
                _number(
                    "SENTINELMESH_EGRESS_RATE_BYTES_PER_SECOND",
                    defaults.egress_rate_bytes_per_second,
                    float,
                )
            ),
            multi_port_window_seconds=int(
                _number(
                    "SENTINELMESH_MULTI_PORT_WINDOW_SECONDS",
                    defaults.multi_port_window_seconds,
                    int,
                )
            ),
            multi_port_minimum_ports=int(
                _number(
                    "SENTINELMESH_MULTI_PORT_MINIMUM_PORTS", defaults.multi_port_minimum_ports, int
                )
            ),
            baseline_window_size=int(
                _number("SENTINELMESH_BASELINE_WINDOW_SIZE", defaults.baseline_window_size, int)
            ),
            baseline_min_history=int(
                _number("SENTINELMESH_BASELINE_MIN_HISTORY", defaults.baseline_min_history, int)
            ),
            baseline_z_score_threshold=float(
                _number(
                    "SENTINELMESH_BASELINE_Z_SCORE_THRESHOLD",
                    defaults.baseline_z_score_threshold,
                    float,
                )
            ),
            beacon_min_flows=int(
                _number("SENTINELMESH_BEACON_MIN_FLOWS", defaults.beacon_min_flows, int)
            ),
            beacon_min_interval_seconds=int(
                _number(
                    "SENTINELMESH_BEACON_MIN_INTERVAL_SECONDS",
                    defaults.beacon_min_interval_seconds,
                    int,
                )
            ),
            beacon_max_interval_seconds=int(
                _number(
                    "SENTINELMESH_BEACON_MAX_INTERVAL_SECONDS",
                    defaults.beacon_max_interval_seconds,
                    int,
                )
            ),
            beacon_max_coefficient_of_variation=float(
                _number(
                    "SENTINELMESH_BEACON_MAX_COEFFICIENT_OF_VARIATION",
                    defaults.beacon_max_coefficient_of_variation,
                    float,
                )
            ),
        )


DEFAULT_CONFIG = DetectionConfig.from_env()
