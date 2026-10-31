"""Tests for local process metrics and feature-distribution drift."""

from dataclasses import replace

from sentinelmesh.drift import drift_report
from sentinelmesh.ingest.flows import parse_flow
from sentinelmesh.metrics import ProcessMetrics


def test_metrics_have_only_low_cardinality_labels():
    metrics = ProcessMetrics()
    metrics.request("GET")
    metrics.request("POST")
    metrics.analysis(12.5)
    output = metrics.render({"flow_count": 10, "finding_count": 2, "incident_count": 1})
    assert 'method="GET"' in output and 'method="POST"' in output
    assert 'quantile="0.5"' in output and 'quantile="0.95"' in output
    assert "flow_id" not in output and "src_ip" not in output


def test_drift_reports_distribution_change_and_small_sample_state(flow_row):
    baseline = [
        parse_flow(
            {
                **flow_row,
                "flow_id": f"d-{i}",
                "timestamp": f"2026-10-10T08:{i:02d}:00Z",
                "bytes_sent": 100,
            }
        )
        for i in range(10)
    ]
    shifted = [
        replace(
            flow, flow_id=f"shift-{i}", timestamp=f"2026-10-10T09:{i:02d}:00Z", bytes_sent=100_000
        )
        for i, flow in enumerate(baseline)
    ]
    result = drift_report(baseline + shifted)
    assert result["status"] == "ok"
    assert result["features"]["bytes_sent"]["psi"] > 0
    assert result["features"]["bytes_sent"]["ks_statistic"] == 1
    assert drift_report(baseline)["status"] == "insufficient"
    assert drift_report(baseline[:5])["status"] == "insufficient"
