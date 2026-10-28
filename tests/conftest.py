from __future__ import annotations

import pytest


@pytest.fixture
def flow_row():
    return {
        "flow_id": "f-1",
        "timestamp": "2026-10-10T08:00:00+05:30",
        "src_ip": "10.0.0.1",
        "dst_ip": "198.51.100.4",
        "src_port": 50000,
        "dst_port": 443,
        "protocol": "TCP",
        "duration_ms": 1000,
        "packets": 5,
        "bytes_sent": 1200,
        "direction": "outbound",
    }
