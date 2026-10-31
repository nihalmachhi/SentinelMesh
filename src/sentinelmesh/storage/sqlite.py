"""SQLite persistence with append-only, hash-chained audit events."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, Self

from sentinelmesh.storage.schema import SCHEMA


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class Store:
    _initialized: ClassVar[set[Path]] = set()
    _schema_lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(self, path: Path):
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        with self._schema_lock:
            if self.path not in self._initialized:
                self._initialize_schema()
                self._initialized.add(self.path)

    def _initialize_schema(self) -> None:
        self.db.executescript(SCHEMA)
        columns = {row["name"] for row in self.db.execute("PRAGMA table_info(audit_events)")}
        for column in ("previous_hash", "event_hash"):
            if column not in columns:
                self.db.execute(
                    f"ALTER TABLE audit_events ADD COLUMN {column} TEXT NOT NULL DEFAULT ''"
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
        from sentinelmesh.storage.audit import append_audit

        append_audit(self.db, event_id, created_at, event_type, payload)

    def _anchor_legacy_audit(self) -> None:
        from sentinelmesh.storage.audit import anchor_legacy_audit

        anchor_legacy_audit(self.db)

    def verify_audit_chain(self) -> bool:
        from sentinelmesh.storage.audit import verify_audit_chain

        return verify_audit_chain(self.db)

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

    def latest_report(self, incident_id: str) -> dict[str, Any] | None:
        row = self.db.execute(
            "SELECT payload FROM reports WHERE incident_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (incident_id,),
        ).fetchone()
        return json.loads(row["payload"]) if row else None

    def export_audit(self, path: Path) -> int:
        if not self.verify_audit_chain():
            raise ValueError("audit chain verification failed; refusing export")
        rows = self.db.execute(
            "SELECT event_id,created_at,event_type,payload,previous_hash,event_hash FROM audit_events ORDER BY rowid"
        ).fetchall()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "".join(
                json.dumps(dict(row), sort_keys=True, separators=(",", ":")) + "\n" for row in rows
            ),
            encoding="utf-8",
        )
        return len(rows)

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
