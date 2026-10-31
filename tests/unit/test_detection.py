from __future__ import annotations

from dataclasses import replace

from sentinelmesh.detection.rules import detect
from sentinelmesh.ingest.flows import parse_flow


def test_multi_port_rule_uses_five_minute_window_and_expected_directions(flow_row):
    flows = []
    for index in range(5):
        row = {
            **flow_row,
            "flow_id": f"f-{index}",
            "dst_port": 1000 + index,
            "timestamp": f"2026-10-10T08:0{index}:00Z",
        }
        flows.append(parse_flow(row))
    assert any(item.rule_id == "multi_port_activity" for item in detect(flows))
    outside_window = [
        replace(flow, timestamp=f"2026-10-10T08:{index * 10:02d}:00Z")
        for index, flow in enumerate(flows)
    ]
    assert not any(item.rule_id == "multi_port_activity" for item in detect(outside_window))
    inbound = [replace(flow, direction="inbound") for flow in flows]
    assert not any(item.rule_id == "multi_port_activity" for item in detect(inbound))


def test_egress_signal_is_direction_gated_and_finding_id_is_stable(flow_row):
    flow_row.update(bytes_sent=100_000_000, duration_ms=1000)
    flow = parse_flow(flow_row)
    finding = next(item for item in detect([flow]) if item.rule_id == "high_egress_rate")
    assert (
        finding.finding_id
        == next(item for item in detect([flow]) if item.rule_id == "high_egress_rate").finding_id
    )
    assert not any(
        item.rule_id == "high_egress_rate" for item in detect([replace(flow, direction="inbound")])
    )


def _flow_at(flow_row, index: int, timestamp: str, bytes_sent: int = 1_000):
    return parse_flow(
        {
            **flow_row,
            "flow_id": f"history-{index}",
            "timestamp": timestamp,
            "src_ip": "10.0.0.8",
            "dst_ip": "203.0.113.10",
            "dst_port": 443,
            "bytes_sent": bytes_sent,
            "duration_ms": 1_000,
            "direction": "outbound",
        }
    )


def test_periodic_detector_flags_fixed_interval_but_not_irregular(flow_row):
    periodic = [_flow_at(flow_row, i, f"2026-10-10T08:{i:02d}:00Z") for i in range(0, 12, 2)]
    assert any(item.rule_id == "periodic_connection" for item in detect(periodic))
    irregular = [
        _flow_at(flow_row, i, f"2026-10-10T08:{minute:02d}:00Z")
        for i, minute in enumerate((0, 1, 5, 9, 20, 22))
    ]
    assert not any(item.rule_id == "periodic_connection" for item in detect(irregular))


def test_host_baseline_uses_only_prior_event_time_rows(flow_row):
    history = [_flow_at(flow_row, i, f"2026-10-10T08:0{i}:00Z", 1_000 + i * 10) for i in range(5)]
    spike = _flow_at(flow_row, 5, "2026-10-10T08:05:00Z", 50_000)
    result = detect([*history, spike])
    finding = next(item for item in result if item.rule_id == "host_egress_baseline")
    assert finding.evidence_ids[-1] == spike.flow_id
    assert finding.observed_features["baseline_count"] == 5

    future_only = [spike] + [
        _flow_at(flow_row, i + 6, f"2026-10-10T08:{i + 6:02d}:00Z", 1_000) for i in range(5)
    ]
    assert not any(item.rule_id == "host_egress_baseline" for item in detect(future_only))
