from __future__ import annotations

from dataclasses import replace

from sentinelmesh.detection import detect
from sentinelmesh.ingest import parse_flow


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
