"""Tests for CLI-facing analysis orchestration."""

from pathlib import Path
from typing import Any, Self

from sentinelmesh import service


class FakeStore:
    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def summary(self) -> dict[str, int]:
        return {"flow_count": 600}


def test_analyze_returns_pipeline_summary_without_implicit_report(
    monkeypatch: Any, tmp_path: Path
) -> None:
    monkeypatch.setattr(service, "load_flows", lambda _: [])
    monkeypatch.setattr(service, "Store", lambda _: FakeStore())
    monkeypatch.setattr(
        service,
        "run_pipeline",
        lambda flows, store: {"flows": 0, "findings": 0, "incidents": 0},
    )
    result = service.analyze(tmp_path / "fixture.json")
    assert result == {
        "flows": 0,
        "findings": 0,
        "incidents": 0,
        "summary": {"flow_count": 600},
    }
