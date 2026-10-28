from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from sentinelmesh.models import Finding
from sentinelmesh.store import Store


def test_findings_sort_by_severity_rank(tmp_path: Path):
    with Store(tmp_path / "db.sqlite3") as store:
        for severity in ("low", "critical", "medium", "high"):
            item = Finding("rule-" + severity, severity, 0.1, severity, "summary", (severity,), {})
            store.db.execute(
                "INSERT INTO findings VALUES(?,?,?,?)",
                (item.finding_id, item.rule_id, severity, json.dumps(item.to_dict())),
            )
        assert [item["severity"] for item in store.list_findings()] == [
            "critical",
            "high",
            "medium",
            "low",
        ]


def test_import_batch_is_idempotent_and_does_not_erase_reports_or_audit(tmp_path: Path):
    with Store(tmp_path / "db.sqlite3") as store:
        flow = {"flow_id": "flow-1"}
        store.import_batch([flow], [], [], "batch-1")
        before = store.db.execute("SELECT count(*) FROM audit_events").fetchone()[0]
        store.db.execute(
            "INSERT INTO incidents VALUES(?,?,?)", ("inc-1", "open", '{"severity":"low"}')
        )
        store.record_report(
            {"report_id": "rep-1", "incident_id": "inc-1", "created_at": "2026-01-01T00:00:00Z"}
        )
        store.import_batch([{"flow_id": "flow-2"}], [], [], "batch-2")
        assert store.summary()["flow_count"] == 2
        assert store.summary()["report_count"] == 1
        assert store.db.execute("SELECT count(*) FROM audit_events").fetchone()[0] == before + 2
        assert store.import_batch([], [], [], "batch-2") == "batch-2"
        assert store.summary()["flow_count"] == 2


def test_audit_log_blocks_update_and_delete_and_hashes_are_chained(tmp_path: Path):
    with Store(tmp_path / "db.sqlite3") as store:
        store.import_batch([], [], [], "batch-1")
        store.reset_demo()
        events = store.db.execute("SELECT * FROM audit_events ORDER BY rowid").fetchall()
        assert len(events) == 2
        assert events[0]["previous_hash"] == "0" * 64
        assert events[1]["previous_hash"] == events[0]["event_hash"]
        assert store.verify_audit_chain()
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store.db.execute("DELETE FROM audit_events")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store.db.execute("UPDATE audit_events SET event_type='tampered'")


def test_reset_clears_demo_tables_but_preserves_audit(tmp_path: Path):
    with Store(tmp_path / "db.sqlite3") as store:
        store.import_batch([{"flow_id": "f"}], [], [], "batch")
        store.db.execute(
            "INSERT INTO incidents VALUES(?,?,?)", ("inc-1", "open", '{"severity":"low"}')
        )
        store.record_report(
            {"report_id": "rep-1", "incident_id": "inc-1", "created_at": "2026-01-01T00:00:00Z"}
        )
        store.record_approval(
            {
                "approval_id": "approval-1",
                "incident_id": "inc-1",
                "decision": "approved",
                "created_at": "2026-01-01T00:00:00Z",
            }
        )
        store.reset_demo()
        assert store.summary() == {
            "flow_count": 0,
            "finding_count": 0,
            "incident_count": 0,
            "report_count": 0,
            "approval_count": 0,
        }
        assert store.db.execute("SELECT count(*) FROM audit_events").fetchone()[0] == 4


def test_legacy_audit_history_is_anchored_and_detectable(tmp_path: Path):
    database = tmp_path / "legacy.sqlite3"
    raw = sqlite3.connect(database)
    raw.execute(
        "CREATE TABLE audit_events(event_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, event_type TEXT NOT NULL, payload TEXT NOT NULL)"
    )
    raw.execute(
        "INSERT INTO audit_events VALUES(?,?,?,?)",
        ("old-1", "2026-01-01T00:00:00Z", "old_event", '{"detail":"kept"}'),
    )
    raw.commit()
    raw.close()

    with Store(database) as store:
        assert store.verify_audit_chain()
        assert store.db.execute("SELECT count(*) FROM audit_events").fetchone()[0] == 2
        store.db.execute("DROP TRIGGER audit_events_no_update")
        store.db.execute("UPDATE audit_events SET payload='tampered' WHERE event_id='old-1'")
        assert not store.verify_audit_chain()
