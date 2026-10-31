from dataclasses import FrozenInstanceError

import pytest

from sentinelmesh.core.models import Flow
from sentinelmesh.detection.config import DetectionConfig
from sentinelmesh.ingest.flows import parse_flow


def test_flow_caches_utc_epoch_without_serializing_it(flow_row):
    flow = parse_flow(flow_row)
    assert flow.timestamp_seconds > 0
    assert "timestamp_seconds" not in flow.to_dict()
    with pytest.raises(FrozenInstanceError):
        flow.flow_id = "changed"


def test_detection_config_reads_environment_overrides(monkeypatch):
    monkeypatch.setenv("SENTINELMESH_MULTI_PORT_MINIMUM_PORTS", "7")
    config = DetectionConfig.from_env()
    assert config.multi_port_minimum_ports == 7
    assert config.egress_rate_bytes_per_second == 25_000_000
