"""Optional host communication graph helpers (requires the graph extra)."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any

from sentinelmesh.core.models import Flow

_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


def _is_internal(address: str) -> bool:
    value = ipaddress.ip_address(address)
    return any(value in net for net in _PRIVATE_NETWORKS if value.version == net.version)


def graph_summary(flows: list[Flow]) -> dict[str, Any]:
    """Summarize communication links, hubs, components, and candidate paths."""
    try:
        import networkx as nx  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError("install the optional graph extra: pip install -e '.[graph]'") from exc

    graph = nx.DiGraph()
    internal = nx.DiGraph()
    for flow in flows:
        source = flow.src_ip
        destination = flow.dst_ip
        stamp = flow.timestamp_seconds
        if graph.has_edge(source, destination):
            edge = graph[source][destination]
            edge["flow_count"] += 1
            edge["first_seen"] = min(edge["first_seen"], stamp)
            edge["last_seen"] = max(edge["last_seen"], stamp)
        else:
            graph.add_edge(source, destination, flow_count=1, first_seen=stamp, last_seen=stamp)
        if _is_internal(source) and _is_internal(destination):
            internal.add_edge(source, destination)

    components = [sorted(component) for component in nx.weakly_connected_components(graph)]
    components.sort(key=lambda component: (component[0] if component else "", len(component)))
    fan_out = sorted(graph.out_degree(), key=lambda item: (-item[1], item[0]))[:10]
    fan_in = sorted(graph.in_degree(), key=lambda item: (-item[1], item[0]))[:10]
    chains: list[list[str]] = []
    for source in sorted(internal.nodes):
        for middle in sorted(internal.successors(source)):
            for destination in sorted(internal.successors(middle)):
                if destination != source and len(chains) < 50:
                    chains.append([source, middle, destination])
    timeline = [
        {
            "source": source,
            "destination": destination,
            "flow_count": edge["flow_count"],
            "first_seen": datetime.fromtimestamp(edge["first_seen"], UTC).isoformat(),
            "last_seen": datetime.fromtimestamp(edge["last_seen"], UTC).isoformat(),
        }
        for source, destination, edge in graph.edges(data=True)
    ]
    timeline.sort(key=lambda edge: (edge["first_seen"], edge["source"], edge["destination"]))
    return {
        "host_count": graph.number_of_nodes(),
        "communication_edge_count": graph.number_of_edges(),
        "connected_component_count": len(components),
        "connected_components": components[:50],
        "fan_out_hubs": [
            {"host": host, "connections": count} for host, count in fan_out if count > 1
        ],
        "fan_in_hubs": [
            {"host": host, "connections": count} for host, count in fan_in if count > 1
        ],
        "lateral_movement_candidates": chains,
        "timeline": timeline[:200],
        "caveat": "Graph structures are metadata-based investigation leads, not confirmed lateral movement.",
    }
