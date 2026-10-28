"""SQLite persistence with append-only, hash-chained audit events."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS flows(flow_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings(finding_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, severity TEXT NOT NULL, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS incidents(incident_id TEXT PRIMARY KEY, status TEXT NOT NULL, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reports(report_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL, FOREIGN KEY(incident_id) REFERENCES incidents(incident_id));
CREATE TABLE IF NOT EXISTS approvals(approval_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, decision TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS import_batches(batch_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, flow_count INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit_events(event_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, event_type TEXT NOT NULL, payload TEXT NOT NULL, previous_hash TEXT NOT NULL DEFAULT '', event_hash TEXT NOT NULL DEFAULT '');
"""


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        columns = {row["name"] for row in self.db.execute("PRAGMA table_info(audit_events)")}
        if "previous_hash" not in columns:
            self.db.execute(
                "ALTER TABLE audit_events ADD COLUMN previous_hash TEXT NOT NULL DEFAULT ''"
            )
        if "event_hash" not in columns:
            self.db.execute(
                "ALTER TABLE audit_events ADD COLUMN event_hash TEXT NOT NULL DEFAULT ''"
            )
        self.db.executescript("""
        CREATE TRIGGER IF NOT EXISTS audit_events_no_update
        BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
        CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
        BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
        """)
        self._anchor_legacy_audit()

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _append_audit(self, event_id: str, created_at: str, event_type: str, payload: Any) -> None:
        previous = self.db.execute(
            "SELECT event_hash FROM audit_events WHERE event_hash != '' ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else "0" * 64
        encoded_payload = _json(payload)
        signed = f"{previous_hash}\0{event_id}\0{created_at}\0{event_type}\0{encoded_payload}"
        event_hash = hashlib.sha256(signed.encode("utf-8")).hexdigest()
        self.db.execute(
            "INSERT INTO audit_events(event_id,created_at,event_type,payload,previous_hash,event_hash) VALUES(?,?,?,?,?,?)",
            (
                event_id,
                created_at,
                event_type,
                encoded_payload,
                previous_hash,
                event_hash,
            ),
        )

    def _anchor_legacy_audit(self) -> None:
        legacy = self.db.execute(
            "SELECT event_id,created_at,event_type,payload FROM audit_events WHERE event_hash='' ORDER BY rowid"
        ).fetchall()
        if not legacy:
            return
        legacy_values = [
            [row[key] for key in ("event_id", "created_at", "event_type", "payload")]
            for row in legacy
        ]
        legacy_digest = hashlib.sha256(_json(legacy_values).encode("utf-8")).hexdigest()
        event_id = "legacy-baseline-" + legacy_digest[:24]
        if self.db.execute("SELECT 1 FROM audit_events WHERE event_id=?", (event_id,)).fetchone():
            return
        stamp = datetime.now(UTC).isoformat()
        with self.db:
            self._append_audit(
                event_id,
                stamp,
                "legacy_audit_baseline",
                {
                    "legacy_count": len(legacy_values),
                    "legacy_digest": legacy_digest,
                },
            )

    def verify_audit_chain(self) -> bool:
        previous_hash = "0" * 64
        legacy_values: list[list[str]] = []
        baseline_seen = False
        rows = self.db.execute(
            "SELECT event_id,created_at,event_type,payload,previous_hash,event_hash FROM audit_events ORDER BY rowid"
        )
        for row in rows:
            if not row["event_hash"] and not row["previous_hash"]:
                legacy_values.append(
                    [row[key] for key in ("event_id", "created_at", "event_type", "payload")]
                )
                continue
            try:
                payload = json.loads(row["payload"])
            except json.JSONDecodeError:
                return False
            if row["event_type"] == "legacy_audit_baseline":
                actual_digest = hashlib.sha256(_json(legacy_values).encode("utf-8")).hexdigest()
                if payload != {"legacy_count": len(legacy_values), "legacy_digest": actual_digest}:
                    return False
                baseline_seen = True
            elif legacy_values and not baseline_seen:
                return False
            signed = "\0".join(
                (
                    previous_hash,
                    row["event_id"],
                    row["created_at"],
                    row["event_type"],
                    row["payload"],
                )
            )
            expected = hashlib.sha256(signed.encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous_hash or row["event_hash"] != expected:
                return False
            previous_hash = row["event_hash"]
        return not legacy_values or baseline_seen

    def import_batch(
        self,
        flows: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        incidents: list[dict[str, Any]],
        batch_id: str | None = None,
    ) -> str:
        stamp = datetime.now(UTC).isoformat()
        batch_id = batch_id or hashlib.sha256(_json(flows).encode()).hexdigest()[:24]
        with self.db:
            inserted = self.db.execute(
                "INSERT OR IGNORE INTO import_batches VALUES(?,?,?)",
                (batch_id, stamp, len(flows)),
            ).rowcount
            if not inserted:
                return batch_id
            for flow in flows:
                existing = self.db.execute(
                    "SELECT payload FROM flows WHERE flow_id=?", (flow["flow_id"],)
                ).fetchone()
                if existing and json.loads(existing["payload"]) != flow:
                    raise ValueError(
                        f"flow_id already exists with different content: {flow['flow_id']}"
                    )
                if not existing:
                    self.db.execute("INSERT INTO flows VALUES(?,?)", (flow["flow_id"], _json(flow)))
            self.db.executemany(
                "INSERT OR IGNORE INTO findings VALUES(?,?,?,?)",
                [
                    (item["finding_id"], item["rule_id"], item["severity"], _json(item))
                    for item in findings
                ],
            )
            self.db.executemany(
                "INSERT OR IGNORE INTO incidents VALUES(?,?,?)",
                [(item["incident_id"], item["status"], _json(item)) for item in incidents],
            )
            self._append_audit(batch_id, stamp, "import_batch", {"flow_count": len(flows)})
        return batch_id

    def reset_demo(self) -> None:
        stamp = datetime.now(UTC).isoformat()
        event_id = "reset-" + uuid.uuid4().hex
        with self.db:
            self.db.execute("DELETE FROM reports")
            self.db.execute("DELETE FROM approvals")
            self.db.execute("DELETE FROM incidents")
            self.db.execute("DELETE FROM findings")
            self.db.execute("DELETE FROM flows")
            self.db.execute("DELETE FROM import_batches")
            self._append_audit(event_id, stamp, "reset_demo", {})

    def list_flows(self) -> list[dict[str, Any]]:
        return [
            json.loads(row["payload"])
            for row in self.db.execute("SELECT payload FROM flows ORDER BY flow_id")
        ]

    def list_findings(self) -> list[dict[str, Any]]:
        return [
            json.loads(row["payload"])
            for row in self.db.execute(
                "SELECT payload FROM findings ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, finding_id"
            )
        ]

    def list_incidents(self) -> list[dict[str, Any]]:
        return [
            json.loads(row["payload"])
            for row in self.db.execute("SELECT payload FROM incidents ORDER BY rowid DESC")
        ]

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        row = self.db.execute(
            "SELECT payload FROM incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        return json.loads(row["payload"]) if row else None

    def get_flow(self, flow_id: str) -> dict[str, Any] | None:
        row = self.db.execute("SELECT payload FROM flows WHERE flow_id=?", (flow_id,)).fetchone()
        return json.loads(row["payload"]) if row else None

    def has_report(self, incident_id: str) -> bool:
        return (
            self.db.execute(
                "SELECT 1 FROM reports WHERE incident_id=? LIMIT 1", (incident_id,)
            ).fetchone()
            is not None
        )

    def record_report(self, report: dict[str, Any]) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO reports VALUES(?,?,?,?)",
                (
                    report["report_id"],
                    report["incident_id"],
                    report["created_at"],
                    _json(report),
                ),
            )
            self._append_audit(
                report["report_id"],
                report["created_at"],
                "agent_report",
                {"incident_id": report["incident_id"]},
            )

    def record_approval(self, item: dict[str, Any]) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO approvals VALUES(?,?,?,?,?)",
                (
                    item["approval_id"],
                    item["incident_id"],
                    item["decision"],
                    item["created_at"],
                    _json(item),
                ),
            )
            self._append_audit(
                item["approval_id"],
                item["created_at"],
                "simulated_action_decision",
                item,
            )

    def summary(self) -> dict[str, int]:
        return {
            key: self.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for key, table in (
                ("flow_count", "flows"),
                ("finding_count", "findings"),
                ("incident_count", "incidents"),
                ("report_count", "reports"),
                ("approval_count", "approvals"),
            )
        }
