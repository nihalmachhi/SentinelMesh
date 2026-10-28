"""Context-only mappings from flow rules to MITRE ATT&CK techniques."""

from typing import TypedDict


class AttackMapping(TypedDict):
    technique_id: str
    technique: str
    tactic: str
    url: str
    interpretation: str


MAPPINGS: dict[str, AttackMapping] = {
    "outbound_sensitive_service": {
        "technique_id": "T1021",
        "technique": "Remote Services",
        "tactic": "Lateral Movement",
        "url": "https://attack.mitre.org/techniques/T1021/",
        "interpretation": "Contextual candidate only: a service port is observed; successful authentication or lateral movement is not shown.",
    },
    "multi_port_activity": {
        "technique_id": "T1046",
        "technique": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "interpretation": "Contextual candidate only: port diversity can also result from routine administration or health checks.",
    },
    "periodic_connection": {
        "technique_id": "T1071",
        "technique": "Application Layer Protocol",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/",
        "interpretation": "Contextual candidate only: periodicity is metadata; the application protocol and intent are not established.",
    },
    "high_egress_rate": {
        "technique_id": "T1041",
        "technique": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1041/",
        "interpretation": "Contextual candidate only: a large transfer is not proof of exfiltration or command and control.",
    },
    "host_egress_baseline": {
        "technique_id": "T1041",
        "technique": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1041/",
        "interpretation": "Contextual candidate only: an unusual byte count does not identify intent or destination ownership.",
    },
}


def mapping_for(rule_id: str) -> AttackMapping | None:
    return MAPPINGS.get(rule_id)
