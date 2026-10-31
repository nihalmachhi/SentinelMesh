"""Tests for optional NetworkX graph features."""

from dataclasses import replace

import pytest

from sentinelmesh.correlation.graph import graph_summary
from sentinelmesh.ingest.flows import parse_flow


@pytest.mark.parametrize("networkx_available", [True])
def test_graph_summary_reports_components_hubs_and_internal_chains(
    flow_row, networkx_available: bool
):
    pytest.importorskip("networkx")
    first = parse_flow(
        {
            **flow_row,
            "flow_id": "g-1",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "direction": "internal",
        }
    )
    second = replace(first, flow_id="g-2", src_ip="10.0.0.2", dst_ip="10.0.0.3")
    third = replace(first, flow_id="g-3", src_ip="10.0.0.1", dst_ip="10.0.0.3")

    result = graph_summary([first, second, third])

    assert result["host_count"] == 3
    assert result["communication_edge_count"] == 3
    assert result["connected_component_count"] == 1
    assert result["fan_out_hubs"][0] == {"host": "10.0.0.1", "connections": 2}
    assert ["10.0.0.1", "10.0.0.2", "10.0.0.3"] in result["lateral_movement_candidates"]
