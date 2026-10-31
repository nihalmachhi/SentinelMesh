/** Transparent examples drawn from the seeded repository fixture. */

const examples = [
    {
        flow_id: "sample-00001",
        timestamp: "2025-01-01T00:00:00Z",
        src_ip: "10.20.0.250",
        dst_ip: "198.51.100.10",
        src_port: 51000,
        dst_port: 21,
        protocol: "TCP",
        bytes_sent: 300,
        direction: "outbound",
        severity: "medium",
        rule_id: "multi_port_activity",
        mode: "port scan",
    },
    {
        flow_id: "sample-00002",
        timestamp: "2025-01-01T00:00:20Z",
        src_ip: "10.20.0.250",
        dst_ip: "198.51.100.10",
        src_port: 51001,
        dst_port: 22,
        protocol: "TCP",
        bytes_sent: 300,
        direction: "outbound",
        severity: "medium",
        rule_id: "outbound_sensitive_service",
        mode: "mixed",
    },
    {
        flow_id: "sample-00008",
        timestamp: "2025-01-01T00:02:20Z",
        src_ip: "10.20.0.250",
        dst_ip: "198.51.100.10",
        src_port: 51007,
        dst_port: 3389,
        protocol: "TCP",
        bytes_sent: 300,
        direction: "outbound",
        severity: "medium",
        rule_id: "multi_port_activity",
        mode: "port scan",
    },
    {
        flow_id: "sample-00009",
        timestamp: "2025-01-01T00:05:00Z",
        src_ip: "10.20.0.251",
        dst_ip: "203.0.113.40",
        src_port: 50000,
        dst_port: 443,
        protocol: "TCP",
        bytes_sent: 60000000,
        direction: "outbound",
        severity: "high",
        rule_id: "high_egress_rate",
        mode: "high egress",
    },
    {
        flow_id: "sample-00020",
        timestamp: "2025-01-01T00:10:00Z",
        src_ip: "10.20.0.253",
        dst_ip: "203.0.113.80",
        src_port: 53000,
        dst_port: 443,
        protocol: "TCP",
        bytes_sent: 4096,
        direction: "outbound",
        severity: "medium",
        rule_id: "periodic_connection",
        mode: "beacon",
    },
];

export function flowExamples(mode = "mixed") {
    const matching =
        mode === "mixed"
            ? examples
            : examples.filter((item) => item.mode === mode);
    return matching.length ? matching : examples;
}
