"""Orchestrate validation, detection, correlation, and persistence."""
from sentinelmesh.correlate import correlate
from sentinelmesh.detection import detect
from sentinelmesh.store import Store

def run_pipeline(flows, store: Store):
    flow_dicts=[f.to_dict() for f in flows]
    findings=[f.to_dict() for f in detect(flows)]
    for index,item in enumerate(findings,1): item["finding_id"]=f"finding-{index:04d}"
    by_id={f["flow_id"]:f for f in flow_dicts}
    incidents=correlate(findings,by_id)
    store.replace_demo(flow_dicts,findings,incidents)
    return {"flows":len(flow_dicts),"findings":len(findings),"incidents":len(incidents),
        "severity_counts":{level:sum(1 for item in findings if item["severity"]==level) for level in ("low","medium","high")},
        "note":"Rule scores are triage signals, not calibrated probabilities."}
