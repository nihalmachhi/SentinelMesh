"""Tests for command-line routing and safe error handling."""

from __future__ import annotations

import sys

from sentinelmesh import cli


def test_analyze_command_prints_service_result(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(
        sys, "argv", ["sentinelmesh", "analyze", "--input", str(tmp_path / "flows.json")]
    )
    monkeypatch.setattr(cli, "analyze", lambda path, format: {"flows": 2, "format": format})

    assert cli.main() == 0
    assert '"flows": 2' in capsys.readouterr().out


def test_benchmark_requires_timezone_for_cic(tmp_path, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sentinelmesh",
            "benchmark",
            "--dataset",
            "cic-ids2017",
            "--input",
            str(tmp_path / "missing.csv"),
        ],
    )
    try:
        cli.main()
    except SystemExit as error:
        assert error.code == 2
    else:
        raise AssertionError("missing CIC input was accepted")
