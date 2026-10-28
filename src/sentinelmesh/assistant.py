"""Evidence-only local investigator with allow-listed read tools."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sentinelmesh.store import Store


def _get_incident(store: Store, key: str | None = None) -> Any:
    return store.get_incident(str(key))


def _get_flow(store: Store, key: str | None = None) -> Any:
    return store.get_flow(str(key))


def _list_incidents(store: Store, key: str | None = None) -> Any:
    return store.list_incidents()


def _list_findings(store: Store, key: str | None = None) -> Any:
    return store.list_findings()


TOOL_REGISTRY: dict[str, Callable[[Store, str | None], Any]] = {
    "get_incident": _get_incident,
    "get_flow": _get_flow,
    "list_incidents": _list_incidents,
    "list_findings": _list_findings,
}
TOOLS = tuple(TOOL_REGISTRY)


def call_tool(store: Store, name: str, key: str | None = None) -> Any:
    tool = TOOL_REGISTRY.get(name)
    if tool is None:
        raise ValueError("investigator tool is not allow-listed")
    return tool(store, key)


def investigate(store: Store, incident_id: str) -> dict[str, Any]:
    incident = store.get_incident(incident_id)
    if not incident:
        raise KeyError("incident not found")
    evidence = []
    for flow_id in incident["evidence_ids"]:
        flow = call_tool(store, "get_flow", flow_id)
        if flow:
            evidence.append(
                {
                    "evidence_id": flow_id,
                    "kind": "observed_flow",
                    "facts": {
                        "src_ip": flow["src_ip"],
                        "dst_ip": flow["dst_ip"],
                        "dst_port": flow["dst_port"],
                        "protocol": flow["protocol"],
                        "bytes_sent": flow["bytes_sent"],
                    },
                }
            )
    report = {
        "report_id": "report-" + uuid4().hex[:12],
        "incident_id": incident_id,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "assessment": "Needs analyst review"
        if incident["severity"] != "low"
        else "Low-priority review",
        "observed_facts": evidence,
        "hypotheses": [f["summary"] for f in incident["findings"]],
        "uncertainty": "Rule-based synthetic demo; these findings do not establish malicious intent.",
        "recommended_next_steps": [
            "Confirm asset owner and expected service behavior.",
            "Review linked flow evidence and nearby timeline.",
            "Validate only in an approved lab; do not block or isolate automatically.",
        ],
        "allowed_tools": list(TOOLS),
        "action_taken": False,
    }
    store.record_report(report)
    return report


def propose_simulated_action(
    store: Store, incident_id: str, action: str, approved_by: str | None = None
) -> dict[str, Any]:
    if action not in {"mark_for_review", "simulate_host_isolation"}:
        raise ValueError("action is not in the simulated-action allow-list")
    if not store.get_incident(incident_id):
        raise KeyError("incident not found")
    if not store.has_report(incident_id):
        raise ValueError("generate an investigation report before proposing an action")
    if not approved_by or not approved_by.strip():
        raise PermissionError("an analyst name is required to approve a simulated action")
    item = {
        "approval_id": "approval-" + uuid4().hex[:12],
        "incident_id": incident_id,
        "decision": "approved_simulation",
        "action": action,
        "approved_by": approved_by.strip(),
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "result": "simulated_only",
        "network_changed": False,
    }
    store.record_approval(item)
    return item
