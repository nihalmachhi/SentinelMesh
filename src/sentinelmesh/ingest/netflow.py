"""Import normalized NetFlow/IPFIX-derived CSV without binding to a vendor schema."""

from __future__ import annotations

import csv
from pathlib import Path

from sentinelmesh.core.models import Flow
from sentinelmesh.ingest.datasets import (
    DEFAULT_DATASET_LIMIT,
    MAX_DATASET_LIMIT,
    _cells,
    _get,
)
from sentinelmesh.ingest.flows import parse_flow
from sentinelmesh.ingest.zeek import infer_direction

PROTOCOLS = {"6": "TCP", "tcp": "TCP", "17": "UDP", "udp": "UDP", "1": "ICMP", "icmp": "ICMP"}


def load_netflow_csv(path: Path, *, limit: int = DEFAULT_DATASET_LIMIT) -> list[Flow]:
    """Load a normalized flow CSV with timezone-aware event timestamps."""
    if not 1 <= limit <= MAX_DATASET_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_DATASET_LIMIT}")
    flows = []
    with path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        for row_number, row in enumerate(reader, start=2):
            if row_number - 1 > limit:
                break
            cells = _cells(row)
            protocol_text = _get(cells, "protocol", "proto").casefold()
            protocol = PROTOCOLS.get(protocol_text)
            if protocol is None:
                raise ValueError(f"unsupported NetFlow protocol: {protocol_text}")
            src_ip = _get(cells, "src_ip", "source_ip", "srcaddr")
            dst_ip = _get(cells, "dst_ip", "destination_ip", "dstaddr")
            flows.append(
                parse_flow(
                    {
                        "flow_id": f"netflow-{row_number:08d}",
                        "timestamp": _get(cells, "timestamp", "start_time", "flow_start"),
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": int(
                            _get(cells, "src_port", "source_port", "sport", "l4_src_port")
                        ),
                        "dst_port": int(
                            _get(cells, "dst_port", "destination_port", "dport", "l4_dst_port")
                        ),
                        "protocol": protocol,
                        "duration_ms": float(_get(cells, "duration_ms", "flow_duration_ms")),
                        "packets": int(_get(cells, "packets", "packet_count", "in_pkts")),
                        "bytes_sent": int(_get(cells, "bytes_sent", "bytes", "in_bytes")),
                        "direction": infer_direction(src_ip, dst_ip),
                    }
                )
            )
    if not flows:
        raise ValueError("NetFlow CSV contains no data rows")
    return flows
