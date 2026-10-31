import json

from scripts.generate_sample_data import build_dataset
from sentinelmesh.ingest.flows import load_flows


def test_generator_is_deterministic_and_meets_demo_size():
    first = build_dataset(600, 41)
    second = build_dataset(600, 41)
    assert first == second
    rows, labels = first
    assert len(rows) == 600
    assert {"benign", "port_scan", "large_egress", "repeated_ssh", "beaconing"}.issubset(
        set(labels)
    )


def test_generated_sample_is_valid_and_large_enough(tmp_path):
    output = tmp_path / "sample_flows.json"
    flows_data, _ = build_dataset(600, 41)
    output.write_text(json.dumps(flows_data), encoding="utf-8")
    flows = load_flows(output)
    assert len(flows) == 600
