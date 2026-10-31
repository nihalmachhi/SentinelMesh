"""Tests for public CSV normalization and chronological metrics."""

import csv
from pathlib import Path

import pytest

from sentinelmesh.evaluation import evaluate_dataset
from sentinelmesh.ingest.datasets import load_cic_ids2017, load_unsw_nb15


def _write_csv(path: Path, columns: list[str], rows: list[list[str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.writer(output)
        writer.writerow(columns)
        writer.writerows(rows)


def test_cic_loader_maps_labels_and_requires_explicit_timezone(tmp_path: Path) -> None:
    path = tmp_path / "cic.csv"
    columns = [
        "Flow ID",
        "Source IP",
        "Source Port",
        "Destination IP",
        "Destination Port",
        "Protocol",
        "Timestamp",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Label",
    ]
    rows = [
        [
            f"flow-{i}",
            "10.0.0.1",
            "50000",
            "198.51.100.2",
            "443",
            "6",
            f"01/01/2025 10:00:{i:02d} AM",
            "1000",
            "2",
            "1",
            "100",
            "BENIGN" if i < 8 else "DoS",
        ]
        for i in range(10)
    ]
    _write_csv(path, columns, rows)
    with pytest.raises(ValueError, match="pass --timezone"):
        load_cic_ids2017(path, timezone_name=None)

    dataset = load_cic_ids2017(path, timezone_name="UTC")
    assert dataset.name == "CIC-IDS2017"
    assert len(dataset.flows) == 10
    assert dataset.labels == [0] * 8 + [1] * 2
    assert dataset.flows[0].duration_ms == 1
    assert dataset.flows[0].packets == 3
    assert dataset.flows[0].direction == "outbound"


def test_unsw_loader_and_chronological_benchmark(tmp_path: Path) -> None:
    path = tmp_path / "unsw.csv"
    columns = [
        "id",
        "dur",
        "proto",
        "spkts",
        "dpkts",
        "sbytes",
        "stime",
        "srcip",
        "sport",
        "dstip",
        "dsport",
        "label",
        "attack_cat",
    ]
    rows = [
        [
            str(i),
            "0.5",
            "tcp",
            "2",
            "1",
            "200",
            str(1735689600 + i * 60),
            "10.0.0.1",
            "50000",
            "203.0.113.2",
            "443",
            "0" if i < 8 else "1",
            "Normal" if i < 8 else "Generic",
        ]
        for i in range(10)
    ]
    _write_csv(path, columns, rows)
    dataset = load_unsw_nb15(path)
    assert dataset.labels == [0] * 8 + [1] * 2
    assert dataset.flows[0].duration_ms == 500
    result = evaluate_dataset(dataset)
    assert result["split"] == "chronological 80/20"
    assert result["train_rows"] == 8
    assert result["test_rows"] == 2
    assert result["data_kind"] == "public labeled research dataset"
    assert "precision" in result and "average_precision_pr_auc" in result


def test_dataset_loader_enforces_row_limit(tmp_path: Path) -> None:
    path = tmp_path / "unsw.csv"
    _write_csv(path, ["id"], [["1"]])
    with pytest.raises(ValueError, match="limit must be between"):
        load_unsw_nb15(path, limit=100_001)


def test_evaluation_rejects_invalid_threshold(tmp_path: Path) -> None:
    from sentinelmesh.core.models import Flow
    from sentinelmesh.ingest.datasets import LabeledFlowDataset

    flow = Flow(
        flow_id="only-flow",
        timestamp="2025-01-01T00:00:00Z",
        src_ip="10.0.0.1",
        dst_ip="203.0.113.3",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        duration_ms=10,
        packets=1,
        bytes_sent=10,
        direction="outbound",
    )
    with pytest.raises(ValueError, match="threshold must be"):
        evaluate_dataset(LabeledFlowDataset("fixture", [flow] * 5, [0] * 5), threshold=1.2)
