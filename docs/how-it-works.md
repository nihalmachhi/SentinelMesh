# How it works

1. **Prepare metadata.** The seeded fixture generator produces 600 synthetic rows under ignored `data/samples/`. Inputs can also be Zeek `conn.log`, normalized NetFlow/IPFIX-derived CSV, or a public dataset CSV used only for evaluation. Packet payloads are not parsed.
2. **Validate the boundary.** JSON and Zeek enforce file-size and row-count bounds, timestamps, addresses, supported protocols, and numeric limits. Dataset adapters normalize known CSV schemas and preserve labels separately.
3. **Detect using past context.** Port activity, high egress, periodic connections, and rolling host-egress baselines produce explainable findings. The baseline for an event uses only earlier event-time records for that host. Optional Isolation Forest is evaluated on the final chronological partition after fitting on the first partition.
4. **Attach evidence and context.** Findings retain source flow IDs and observed values. ATT&CK technique tags are contextual candidates, not conclusions. Correlation groups overlapping findings into stable evidence-linked incidents.
5. **Persist and audit.** SQLite rejects changed content reusing a flow ID. Audit events are append-only and hash chained; `sentinelmesh audit-export` verifies the chain before export.
6. **Review safely.** The dashboard uses a loopback-only API. GET routes are viewer-readable; writes require the per-run token. A simulated approval requires an investigation report and analyst name, links to that report, expires after 30 minutes, and does not execute a control action.

## Evaluation and observability

`sentinelmesh benchmark` evaluates labels on a chronological 80/20 split and reports precision, recall, F1, average precision, and false alerts per observed day. The repository does not include public dataset files or claim results on them. Dataset terms and schema assumptions are in [datasets.md](datasets.md).

`sentinelmesh drift` and `/api/drift` compare early and later metadata distributions with PSI and a two-sample KS statistic. They indicate possible distribution change only. `/metrics` exports low-cardinality process-local request counts, flow/finding/incident counts, and analysis latency p50/p95. No per-flow labels are emitted.

Run `python scripts/generate_sample_data.py`, `python -m sentinelmesh.cli analyze`, and `python -m sentinelmesh.cli serve`. For data-changing fixture revisions, clear only the demo records with `python -m sentinelmesh.cli reset-demo`; the audit log is retained. See [architecture](architecture.md), [data contract](data-contract.md), [safety](safety-and-data.md), and [threat model](THREAT_MODEL.md).

## Optional settings

`.env.example` lists supported environment names but is not loaded automatically. Set `SENTINELMESH_DB_PATH` before starting a command to use an isolated database. LLM assistance stays disabled unless `SENTINELMESH_LLM_ENABLED=true` and an HTTPS endpoint, model, and API key are supplied. When enabled, evidence leaves the local machine for that configured provider; the investigator receives no callable tools and accepts only claims citing IDs in the report.
