"""Orchestrate validation, detection, correlation, and persistence."""

from typing import Any

from sentinelmesh.core.models import Flow
from sentinelmesh.correlation.incidents import correlate
from sentinelmesh.detection.rules import detect
from sentinelmesh.storage.sqlite import Store


def run_pipeline(flows: list[Flow], store: Store) -> dict[str, Any]:
    flow_dicts = [f.to_dict() for f in flows]
    findings = [f.to_dict() for f in detect(flows)]
    by_id = {f["flow_id"]: f for f in flow_dicts}
    incidents = correlate(findings, by_id)
    store.import_batch(flow_dicts, findings, incidents)
    return {
        "flows": len(flow_dicts),
        "findings": len(findings),
        "incidents": len(incidents),
        "severity_counts": {
            level: sum(1 for item in findings if item["severity"] == level)
            for level in ("low", "medium", "high")
        },
        "note": "Rule scores are triage signals, not calibrated probabilities.",
    }
