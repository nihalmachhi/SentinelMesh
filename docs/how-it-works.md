# How it works

1. **Start with flow JSON.** The deterministic fixture generator creates 600 synthetic rows under ignored `data/generated/`. Records contain metadata only; packet payloads are rejected.
2. **Validate the boundary.** The parser enforces a 2 MB file size, a 20,000-row limit, unique flow IDs, known fields, timezone-aware timestamps, valid addresses, supported protocols, and bounded numeric values.
3. **Apply explainable rules.** The current rules flag selected outbound service ports, configured high byte rates, and repeated destination-port activity within a five-minute window. They are heuristics, not a learned model.
4. **Keep evidence attached.** Every finding references the source flow IDs and includes the observed values used by its rule. Correlation produces stable incident IDs from the evidence and endpoint information.
5. **Persist a replayable import.** SQLite records each batch and prevents a changed record from silently reusing an existing flow ID. The audit log is append-only and hash chained.
6. **Review locally.** The dashboard calls a loopback-only API. Read actions show stored evidence; write actions require the per-run bearer token and record simulated decisions only.

Run `python scripts/generate_sample_data.py` to create the sample, then `python -m sentinelmesh.cli analyze` to process it, then `python -m sentinelmesh.cli serve` to inspect it in the browser. See [architecture](architecture.md), [data contract](data-contract.md), and [safety](safety-and-data.md) for implementation boundaries.

## Evaluation limits

The bundled fixture is synthetic and designed to exercise code paths. It is not a benchmark, production traffic sample, or basis for an accuracy claim. No real labeled data has been evaluated, and no operational latency or throughput benchmark is reported.
