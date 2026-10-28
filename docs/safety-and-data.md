# Safety and data handling

- The seeded sample is synthetic. The dashboard and API bind to loopback only; startup rejects non-loopback bind addresses.
- Inputs are flow metadata. JSON, Zeek connection logs, normalized CSV, and selected public-dataset CSVs are supported; PCAP must be converted offline with Zeek. SentinelMesh never captures live packets or parses payload contents.
- Import size/row counts, IPs, protocols, ports, timestamps, and counters are validated before persistence. Public dataset files remain outside Git and their terms are summarized in `docs/datasets.md`.
- Detection scores and ATT&CK mappings are contextual triage signals, not calibrated probabilities or evidence of intent.
- The default investigator uses only stored read-only evidence. Optional LLM assistance is disabled by default; if enabled, evidence is sent over HTTPS to the endpoint you configure. It has no callable tools and validates cited evidence IDs. Do not send sensitive data without authorization.
- Simulated actions require an investigation report and named analyst. They link to the report, expire after 30 minutes, and record `network_changed=false`; no response control is connected.
- SQLite can contain sensitive host metadata when real files are supplied. Keep it local and control filesystem access. `python -m sentinelmesh.cli reset-demo` removes demo records but retains the append-only, hash-chained audit history.
- Every dashboard POST requires a random per-run bearer token. The API checks Host and same-origin headers, requires JSON, and emits a restrictive CSP and security headers. Keep the startup terminal private because it prints the active token.
