"""Group related findings into human-readable investigations."""
from datetime import datetime
from uuid import uuid4

def correlate(findings: list[dict], flows_by_id: dict[str,dict]) -> list[dict]:
    groups: dict[str,list[dict]] = {}
    for finding in findings:
        sources = {flows_by_id[eid]["src_ip"] for eid in finding["evidence_ids"] if eid in flows_by_id}
        key = sorted(sources)[0] if sources else "unknown"
        groups.setdefault(key,[]).append(finding)
    incidents=[]
    for host, items in sorted(groups.items()):
        ids=sorted({eid for item in items for eid in item["evidence_ids"]})
        incidents.append({
            "incident_id":"inc-"+uuid4().hex[:12],
            "created_at":datetime.now().astimezone().isoformat(timespec="seconds"),
            "host":host,"status":"open",
            "severity":max((x["severity"] for x in items),key={"low":0,"medium":1,"high":2}.get),
            "finding_count":len(items),"evidence_ids":ids,"findings":items,
            "summary":f"{len(items)} finding(s) correlated around source {host}.",
        })
    return incidents
