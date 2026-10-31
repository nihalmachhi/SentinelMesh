"""Regression tests for Zeek conn.log normalization."""

from pathlib import Path

import pytest

from sentinelmesh.ingest.zeek import load_zeek_conn

HEADER = (
    "#separator \\x09\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\t"
    "duration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\n"
)
ROW = "1704067200.5\tC1\t10.0.0.4\t51500\t198.51.100.9\t443\ttcp\t0.25\t1200\t800\t4\t3\n"


def test_zeek_conn_records_normalize_into_common_flow_contract(tmp_path: Path) -> None:
    path = tmp_path / "conn.log"
    path.write_text(HEADER + ROW, encoding="utf-8")

    flows = load_zeek_conn(path)

    assert len(flows) == 1
    flow = flows[0]
    assert flow.timestamp == "2024-01-01T00:00:00.500000Z"
    assert flow.duration_ms == 250
    assert flow.packets == 7
    assert flow.bytes_sent == 1200
    assert flow.direction == "outbound"
    assert flow.flow_id.startswith("zeek-")


def test_zeek_public_to_public_direction_stays_unknown(tmp_path: Path) -> None:
    path = tmp_path / "conn.log"
    row = ROW.replace("10.0.0.4", "198.51.100.4")
    path.write_text(HEADER + row, encoding="utf-8")
    assert load_zeek_conn(path)[0].direction == "unknown"


@pytest.mark.parametrize("timestamp", ["nan", "inf", "not-a-number"])
def test_zeek_rejects_invalid_timestamps(tmp_path: Path, timestamp: str) -> None:
    path = tmp_path / "conn.log"
    path.write_text(HEADER + ROW.replace("1704067200.5", timestamp), encoding="utf-8")
    with pytest.raises(ValueError, match="finite Unix seconds"):
        load_zeek_conn(path)


def test_zeek_requires_supported_fields(tmp_path: Path) -> None:
    path = tmp_path / "conn.log"
    path.write_text("#fields\tts\tid.orig_h\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing fields"):
        load_zeek_conn(path)
