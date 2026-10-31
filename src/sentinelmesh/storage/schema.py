"""SQLite tables required by the local investigation store."""

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
