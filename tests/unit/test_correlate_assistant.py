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


def test_unrelated_hosts_with_overlapping_times_stay_separate(flow_row):
    first = {**flow_row, "flow_id": "first", "src_ip": "10.0.0.1", "dst_ip": "198.51.100.1"}
    second = {**flow_row, "flow_id": "second", "src_ip": "10.0.0.2", "dst_ip": "198.51.100.2"}
    items = [
        {"finding_id": "a", "severity": "medium", "evidence_ids": ["first"]},
        {"finding_id": "b", "severity": "high", "evidence_ids": ["second"]},
    ]
    assert len(correlate(items, {"first": first, "second": second})) == 2


def test_same_host_findings_within_proximity_merge(flow_row):
    first = {
        **flow_row,
        "flow_id": "first",
        "src_ip": "10.0.0.1",
        "timestamp": "2026-10-10T08:00:00Z",
    }
    second = {
        **flow_row,
        "flow_id": "second",
        "src_ip": "10.0.0.1",
        "timestamp": "2026-10-10T08:04:00Z",
    }
    items = [
        {"finding_id": "a", "severity": "medium", "evidence_ids": ["first"]},
        {"finding_id": "b", "severity": "high", "evidence_ids": ["second"]},
    ]
    merged = correlate(items, {"first": first, "second": second})
    assert len(merged) == 1
    assert merged[0]["severity"] == "high"
    assert merged[0]["window_start"].endswith("Z")
    assert merged[0]["window_end"].endswith("Z")


def test_same_host_findings_far_apart_stay_separate(flow_row):
    first = {
        **flow_row,
        "flow_id": "first",
        "src_ip": "10.0.0.1",
        "timestamp": "2026-10-10T08:00:00Z",
    }
    second = {
        **flow_row,
        "flow_id": "second",
        "src_ip": "10.0.0.1",
        "timestamp": "2026-10-10T08:06:00Z",
    }
    items = [
        {"finding_id": "a", "severity": "medium", "evidence_ids": ["first"]},
        {"finding_id": "b", "severity": "high", "evidence_ids": ["second"]},
    ]
    assert len(correlate(items, {"first": first, "second": second})) == 2


def test_simulated_approval_is_linked_to_latest_report_and_expires(tmp_path):
    import json
    from datetime import datetime

    with Store(tmp_path / "db.sqlite3") as store:
        store.db.execute(
            "INSERT INTO incidents VALUES(?,?,?)",
            ("inc-2", "open", json.dumps({"incident_id": "inc-2", "severity": "low"})),
        )
        report = {
            "report_id": "report-2",
            "incident_id": "inc-2",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        store.record_report(report)
        approval = propose_simulated_action(store, "inc-2", "mark_for_review", "Nihal")
    assert approval["report_id"] == "report-2"
    assert approval["role"] == "analyst"
    expires = datetime.fromisoformat(approval["expires_at"])
    created = datetime.fromisoformat(approval["created_at"])
    assert (expires - created).total_seconds() == 1800
