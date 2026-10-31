"""Hash-chained append-only audit event operations."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from typing import Any


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def append_audit(
    db: sqlite3.Connection, event_id: str, created_at: str, event_type: str, payload: Any
) -> None:
    previous = db.execute(
        "SELECT event_hash FROM audit_events WHERE event_hash != '' ORDER BY rowid DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous["event_hash"] if previous else "0" * 64
    encoded = _json(payload)
    signed = f"{previous_hash}\0{event_id}\0{created_at}\0{event_type}\0{encoded}"
    digest = hashlib.sha256(signed.encode()).hexdigest()
    db.execute(
        "INSERT INTO audit_events(event_id,created_at,event_type,payload,previous_hash,event_hash) VALUES(?,?,?,?,?,?)",
        (event_id, created_at, event_type, encoded, previous_hash, digest),
    )


def anchor_legacy_audit(db: sqlite3.Connection) -> None:
    rows = db.execute(
        "SELECT event_id,created_at,event_type,payload FROM audit_events WHERE event_hash='' ORDER BY rowid"
    ).fetchall()
    if not rows:
        return
    values = [
        [row[key] for key in ("event_id", "created_at", "event_type", "payload")] for row in rows
    ]
    digest = hashlib.sha256(_json(values).encode()).hexdigest()
    event_id = "legacy-baseline-" + digest[:24]
    if db.execute("SELECT 1 FROM audit_events WHERE event_id=?", (event_id,)).fetchone():
        return
    with db:
        append_audit(
            db,
            event_id,
            datetime.now(UTC).isoformat(),
            "legacy_audit_baseline",
            {"legacy_count": len(values), "legacy_digest": digest},
        )


def verify_audit_chain(db: sqlite3.Connection) -> bool:
    previous_hash = "0" * 64
    legacy: list[list[str]] = []
    baseline_seen = False
    rows = db.execute(
        "SELECT event_id,created_at,event_type,payload,previous_hash,event_hash FROM audit_events ORDER BY rowid"
    )
    for row in rows:
        if not row["event_hash"] and not row["previous_hash"]:
            legacy.append([row[key] for key in ("event_id", "created_at", "event_type", "payload")])
            continue
        try:
            payload = json.loads(row["payload"])
        except json.JSONDecodeError:
            return False
        if row["event_type"] == "legacy_audit_baseline":
            digest = hashlib.sha256(_json(legacy).encode()).hexdigest()
            if payload != {"legacy_count": len(legacy), "legacy_digest": digest}:
                return False
            baseline_seen = True
        elif legacy and not baseline_seen:
            return False
        signed = "\0".join(
            (previous_hash, row["event_id"], row["created_at"], row["event_type"], row["payload"])
        )
        expected = hashlib.sha256(signed.encode()).hexdigest()
        if row["previous_hash"] != previous_hash or row["event_hash"] != expected:
            return False
        previous_hash = row["event_hash"]
    return not legacy or baseline_seen
