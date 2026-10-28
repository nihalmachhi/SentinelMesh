from __future__ import annotations

from sentinelmesh.correlation.incidents import correlate
from sentinelmesh.investigation.tools import call_tool, propose_simulated_action
from sentinelmesh.storage.sqlite import Store


def test_incident_ids_are_deterministic_and_source_destination_correlate(flow_row):
    flow = {**flow_row, "flow_id": "f1"}
    finding = {
        "finding_id": "finding-a",
        "severity": "high",
        "summary": "signal",
        "evidence_ids": ["f1"],
    }
    first = correlate([finding], {"f1": flow})
    second = correlate([finding], {"f1": flow})
    assert first[0]["incident_id"] == second[0]["incident_id"]
    assert first[0]["hosts"] == ["10.0.0.1", "198.51.100.4"]


def test_unknown_investigator_tool_is_rejected(tmp_path):
    with Store(tmp_path / "db.sqlite3") as store:
        try:
            call_tool(store, "run_shell")
        except ValueError as exc:
            assert "allow-listed" in str(exc)
        else:
            raise AssertionError("unknown tool was accepted")


def test_simulated_action_requires_existing_report(tmp_path):
    with Store(tmp_path / "db.sqlite3") as store:
        store.db.execute(
            "INSERT INTO incidents VALUES(?,?,?)",
            ("inc-1", "open", '{"severity":"low"}'),
        )
        try:
            propose_simulated_action(store, "inc-1", "mark_for_review", "analyst")
        except ValueError as exc:
            assert "report" in str(exc)
        else:
            raise AssertionError("action was accepted without a report")


def test_correlation_merges_shared_hosts_and_overlapping_windows(flow_row):
    first = {**flow_row, "flow_id": "first"}
    second = {**flow_row, "flow_id": "second", "src_ip": "10.0.0.2", "dst_ip": "198.51.100.9"}
    items = [
        {"finding_id": "a", "severity": "medium", "summary": "a", "evidence_ids": ["first"]},
        {"finding_id": "b", "severity": "high", "summary": "b", "evidence_ids": ["second"]},
    ]
    merged = correlate(items, {"first": first, "second": second})
    assert len(merged) == 1
    assert merged[0]["severity"] == "high"
    assert merged[0]["finding_count"] == 2
