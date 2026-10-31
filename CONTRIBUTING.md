# Contributing

Use Python 3.11+, create a virtual environment, and install `.[dev]`. Before opening a pull request, run Ruff lint and format checks, strict mypy, and pytest with coverage. Add tests for behavior changes and update documentation when public behavior changes. Do not commit generated telemetry, downloaded datasets, credentials, or real network captures. Preserve the local-only API and simulated-action safety boundaries.
