"""Evidence-only local investigator with allow-listed read tools."""
from datetime import datetime
from uuid import uuid4
from sentinelmesh.store import Store

TOOLS=("get_incident","get_flow","list_incidents","list_findings")
def investigate(store: Store, incident_id: str):
    incident=store.get_incident(incident_id)
    if not incident: raise KeyError("incident not found")
    evidence=[]
    for flow_id in incident["evidence_ids"]:
        flow=store.get_flow(flow_id)
        if flow:
            evidence.append({"evidence_id":flow_id,"kind":"observed_flow",
                "facts":{"src_ip":flow["src_ip"],"dst_ip":flow["dst_ip"],"dst_port":flow["dst_port"],"protocol":flow["protocol"],"bytes_sent":flow["bytes_sent"]}})
    report={"report_id":"report-"+uuid4().hex[:12],"incident_id":incident_id,
        "created_at":datetime.now().astimezone().isoformat(timespec="seconds"),
        "assessment":"Needs analyst review" if incident["severity"]!="low" else "Low-priority review",
        "observed_facts":evidence,"hypotheses":[f["summary"] for f in incident["findings"]],
        "uncertainty":"Rule-based synthetic demo; these findings do not establish malicious intent.",
        "recommended_next_steps":["Confirm asset owner and expected service behavior.","Review linked flow evidence and nearby timeline.","Validate only in an approved lab; do not block or isolate automatically."],
        "allowed_tools":list(TOOLS),"action_taken":False}
    store.record_report(report)
    return report

def propose_simulated_action(store: Store, incident_id: str, action: str, approved_by: str | None = None):
    if action not in {"mark_for_review","simulate_host_isolation"}:
        raise ValueError("action is not in the simulated-action allow-list")
    if not store.get_incident(incident_id): raise KeyError("incident not found")
    if not approved_by or not approved_by.strip():
        raise PermissionError("an analyst name is required to approve a simulated action")
    item={"approval_id":"approval-"+uuid4().hex[:12],"incident_id":incident_id,
        "decision":"approved_simulation","action":action,"approved_by":approved_by.strip(),
        "created_at":datetime.now().astimezone().isoformat(timespec="seconds"),
        "result":"simulated_only","network_changed":False}
    store.record_approval(item)
    return item
