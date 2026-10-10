"""SQLite persistence with parameterized statements and explicit transactions."""
import json
import sqlite3
from pathlib import Path

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS flows(flow_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings(finding_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, severity TEXT NOT NULL, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS incidents(incident_id TEXT PRIMARY KEY, status TEXT NOT NULL, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reports(report_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL, FOREIGN KEY(incident_id) REFERENCES incidents(incident_id));
CREATE TABLE IF NOT EXISTS approvals(approval_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, decision TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_events(event_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, event_type TEXT NOT NULL, payload TEXT NOT NULL);
"""
class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True,exist_ok=True)
        self.db=sqlite3.connect(path)
        self.db.row_factory=sqlite3.Row
        self.db.executescript(SCHEMA)
    def close(self): self.db.close()
    def __enter__(self): return self
    def __exit__(self,*exc): self.close()
    def replace_demo(self, flows, findings, incidents):
        with self.db:
            self.db.execute("DELETE FROM reports"); self.db.execute("DELETE FROM approvals")
            self.db.execute("DELETE FROM audit_events"); self.db.execute("DELETE FROM incidents")
            self.db.execute("DELETE FROM findings"); self.db.execute("DELETE FROM flows")
            self.db.executemany("INSERT INTO flows VALUES(?,?)",[(f["flow_id"],json.dumps(f)) for f in flows])
            self.db.executemany("INSERT INTO findings VALUES(?,?,?,?)",[(x["finding_id"],x["rule_id"],x["severity"],json.dumps(x)) for x in findings])
            self.db.executemany("INSERT INTO incidents VALUES(?,?,?)",[(x["incident_id"],x["status"],json.dumps(x)) for x in incidents])
    def list_flows(self): return [json.loads(r["payload"]) for r in self.db.execute("SELECT payload FROM flows ORDER BY flow_id")]
    def list_findings(self): return [json.loads(r["payload"]) for r in self.db.execute("SELECT payload FROM findings ORDER BY severity DESC")]
    def list_incidents(self): return [json.loads(r["payload"]) for r in self.db.execute("SELECT payload FROM incidents ORDER BY rowid DESC")]
    def get_incident(self, incident_id):
        row=self.db.execute("SELECT payload FROM incidents WHERE incident_id=?",(incident_id,)).fetchone()
        return json.loads(row["payload"]) if row else None
    def get_flow(self, flow_id):
        row=self.db.execute("SELECT payload FROM flows WHERE flow_id=?",(flow_id,)).fetchone()
        return json.loads(row["payload"]) if row else None
    def record_report(self, report):
        with self.db:
            self.db.execute("INSERT INTO reports VALUES(?,?,?,?)",(report["report_id"],report["incident_id"],report["created_at"],json.dumps(report)))
            self.db.execute("INSERT INTO audit_events VALUES(?,?,?,?)",(report["report_id"],report["created_at"],"agent_report",json.dumps({"incident_id":report["incident_id"]})))
    def record_approval(self, item):
        with self.db:
            self.db.execute("INSERT INTO approvals VALUES(?,?,?,?,?)",(item["approval_id"],item["incident_id"],item["decision"],item["created_at"],json.dumps(item)))
            self.db.execute("INSERT INTO audit_events VALUES(?,?,?,?)",(item["approval_id"],item["created_at"],"simulated_action_decision",json.dumps(item)))
    def summary(self):
        return {"flow_count":self.db.execute("SELECT count(*) FROM flows").fetchone()[0],
                "finding_count":self.db.execute("SELECT count(*) FROM findings").fetchone()[0],
                "incident_count":self.db.execute("SELECT count(*) FROM incidents").fetchone()[0],
                "report_count":self.db.execute("SELECT count(*) FROM reports").fetchone()[0],
                "approval_count":self.db.execute("SELECT count(*) FROM approvals").fetchone()[0]}
