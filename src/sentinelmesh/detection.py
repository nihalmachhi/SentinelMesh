"""Explainable baseline rules for safe synthetic flow telemetry."""
from collections import defaultdict
from sentinelmesh.models import Finding, Flow

SENSITIVE_PORTS = {22:"SSH",23:"Telnet",3389:"RDP",445:"SMB",1433:"MSSQL"}
def detect(flows: list[Flow]) -> list[Finding]:
    findings: list[Finding] = []
    by_source: dict[str,list[Flow]] = defaultdict(list)
    for flow in flows:
        by_source[flow.src_ip].append(flow)
        if flow.dst_port in SENSITIVE_PORTS and flow.direction == "outbound":
            findings.append(Finding(
                rule_id="outbound_sensitive_service", severity="medium", score=0.62,
                title=f"Outbound connection to {SENSITIVE_PORTS[flow.dst_port]} service",
                summary="A flow targets a commonly sensitive service port. This is a triage signal, not proof of compromise.",
                evidence_ids=(flow.flow_id,),
                observed_features={"destination_port":flow.dst_port,"protocol":flow.protocol,"bytes_sent":flow.bytes_sent},
            ))
        if flow.bytes_sent >= 5_000_000 and flow.duration_ms > 0 and flow.bytes_sent / flow.duration_ms > 20_000:
            findings.append(Finding(
                rule_id="high_egress_rate", severity="high", score=0.84,
                title="Unusually high outbound transfer rate",
                summary="The observed byte rate exceeds the demo rule threshold; validate against host role and baseline.",
                evidence_ids=(flow.flow_id,),
                observed_features={"bytes_sent":flow.bytes_sent,"duration_ms":flow.duration_ms},
            ))
    for source, records in by_source.items():
        destinations = {f.dst_ip for f in records}
        ports = {f.dst_port for f in records}
        if len(records) >= 5 and len(ports) >= 5:
            findings.append(Finding(
                rule_id="multi_port_activity",severity="medium",score=0.70,
                title="One source contacted many service ports",
                summary="Repeated destination-port variety can indicate scanning or routine administration; investigate context.",
                evidence_ids=tuple(sorted(f.flow_id for f in records)),
                observed_features={"source_ip":source,"flow_count":len(records),"unique_ports":len(ports),"unique_destinations":len(destinations)},
            ))
    return findings
