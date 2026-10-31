"""Ordered detection registry; register each detector once."""

from collections.abc import Callable, Sequence

from sentinelmesh.core.models import Finding, Flow
from sentinelmesh.detection.config import DEFAULT_CONFIG, DetectionConfig
from sentinelmesh.detection.rules import host_baseline, multi_port, periodic, single_flow

Rule = Callable[[Sequence[Flow], DetectionConfig], list[Finding]]
RULES: tuple[Rule, ...] = (
    single_flow.detect,
    multi_port.detect,
    periodic.detect,
    host_baseline.detect,
)


def detect(flows: Sequence[Flow], config: DetectionConfig = DEFAULT_CONFIG) -> list[Finding]:
    return [finding for rule in RULES for finding in rule(flows, config)]
