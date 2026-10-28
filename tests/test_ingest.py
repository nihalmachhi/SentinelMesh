from __future__ import annotations

from pathlib import Path

import pytest

from sentinelmesh.ingest import load_flows, parse_flow


def test_parse_flow_normalizes_timezone_to_utc(flow_row):
    parsed = parse_flow(flow_row)
    assert parsed.timestamp == "2026-10-10T02:30:00Z"


@pytest.mark.parametrize("timestamp", ["", "2026-10-10T08:00:00", "yesterday", None, 123])
def test_timestamp_requires_iso8601_timezone(flow_row, timestamp):
    flow_row["timestamp"] = timestamp
    with pytest.raises(ValueError, match="timestamp"):
        parse_flow(flow_row)


@pytest.mark.parametrize("value", [None, [], "flow", 1, True])
def test_parse_flow_rejects_non_objects(value):
    with pytest.raises(ValueError, match="JSON object"):
        parse_flow(value)


def test_parse_flow_rejects_unknown_fields(flow_row):
    flow_row["command"] = "must not be ignored"
    with pytest.raises(ValueError, match="unknown fields"):
        parse_flow(flow_row)


def test_load_flows_rejects_empty_array(tmp_path: Path):
    file = tmp_path / "empty.json"
    file.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="non-empty"):
        load_flows(file)


def test_property_bad_shapes_never_escape_as_attribute_error(flow_row):
    for value in [None, [], "abc", 2, {**flow_row, "src_ip": []}]:
        try:
            parse_flow(value)
        except ValueError:
            continue
        except (
            AttributeError,
            TypeError,
            KeyError,
        ) as exc:  # validation boundary must normalize malformed input
            pytest.fail(f"unexpected {type(exc).__name__}")
