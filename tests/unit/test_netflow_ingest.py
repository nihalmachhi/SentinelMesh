"""Tests for normalized NetFlow/IPFIX CSV input."""

from pathlib import Path

from sentinelmesh.ingest.netflow import load_netflow_csv


def test_netflow_csv_maps_aliases_and_keeps_unknown_direction(tmp_path: Path) -> None:
    path = tmp_path / "flows.csv"
    path.write_text(
        "timestamp,srcaddr,sport,dstaddr,dport,proto,duration_ms,in_pkts,in_bytes\n"
        "2025-01-01T00:00:00Z,198.51.100.2,50000,203.0.113.4,443,6,250,3,1200\n",
        encoding="utf-8",
    )

    flows = load_netflow_csv(path)

    assert len(flows) == 1
    assert flows[0].protocol == "TCP"
    assert flows[0].direction == "unknown"
    assert flows[0].bytes_sent == 1200
