"""Application services shared by CLI and dashboard."""

from pathlib import Path
from typing import Any

from sentinelmesh.core.config import DB_PATH, SAMPLE_FLOWS
from sentinelmesh.ingest.flows import load_flows
from sentinelmesh.ingest.netflow import load_netflow_csv
from sentinelmesh.ingest.zeek import load_zeek_conn
from sentinelmesh.pipeline import run_pipeline
from sentinelmesh.storage.sqlite import Store


def analyze(path: Path = SAMPLE_FLOWS, input_format: str = "json") -> dict[str, Any]:
    if input_format == "json":
        flows = load_flows(path)
    elif input_format == "zeek-conn":
        flows = load_zeek_conn(path)
    elif input_format == "netflow-csv":
        flows = load_netflow_csv(path)
    else:
        raise ValueError("input_format must be json, zeek-conn, or netflow-csv")
    with Store(DB_PATH) as store:
        result = run_pipeline(flows, store)
        result["summary"] = store.summary()
        return result
