"""Application services shared by CLI and dashboard."""

from pathlib import Path
from typing import Any

from sentinelmesh.assistant import investigate
from sentinelmesh.config import DB_PATH, SAMPLE_FLOWS
from sentinelmesh.ingest import load_flows
from sentinelmesh.pipeline import run_pipeline
from sentinelmesh.store import Store


def analyze(path: Path = SAMPLE_FLOWS) -> dict[str, Any]:
    flows = load_flows(path)
    with Store(DB_PATH) as store:
        result = run_pipeline(flows, store)
        incidents = store.list_incidents()
        if incidents:
            result["sample_report"] = investigate(store, incidents[0]["incident_id"])
        result["summary"] = store.summary()
        return result
