"""Application services shared by CLI and dashboard."""

from pathlib import Path
from typing import Any

from sentinelmesh.core.config import DB_PATH, SAMPLE_FLOWS
from sentinelmesh.ingest.flows import load_flows
from sentinelmesh.pipeline import run_pipeline
from sentinelmesh.storage.sqlite import Store


def analyze(path: Path = SAMPLE_FLOWS) -> dict[str, Any]:
    flows = load_flows(path)
    with Store(DB_PATH) as store:
        result = run_pipeline(flows, store)
        result["summary"] = store.summary()
        return result
