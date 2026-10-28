.PHONY: install lint format typecheck test run bench

install:
	python -m pip install -e ".[dev]"

lint:
	python -m ruff check src tests scripts

format:
	python -m ruff format src tests scripts

typecheck:
	python -m mypy src/sentinelmesh

test:
	python -m pytest -q

run:
	python scripts/generate_sample_data.py
	python -m sentinelmesh.cli analyze

bench:
	python scripts/generate_sample_data.py
	python scripts/benchmark.py --repeats 5
