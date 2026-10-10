# Architecture

## Request path

1. CLI or local dashboard receives prepared JSON flow records.
2. Ingestion validates type, IP syntax, protocol, ports, counters, record count, and input size.
3. Explainable rules emit findings with observed feature values and evidence flow IDs.
4. Correlation groups findings by source host into an incident timeline.
5. SQLite persists flow evidence, findings, incidents, analyst reports, simulated approvals, and audit events.
6. The evidence-only investigator reads a narrow allow-list and labels evidence as observed facts and rule outputs as hypotheses.
7. A loopback-only HTTP server exposes the dashboard API. Simulated actions require a named analyst and never change the network.

## Component map

```text
JSON flow input -> validation -> baseline rules -> correlation -> SQLite
                                                  |             |
                                                  +-> investigator -> report
                                                                |
Dashboard <-------------- loopback API <------------------------+
Analyst approval -> audit record (simulation only)
```

## Technology decisions

Python standard library and SQLite keep the MVP reproducible without API keys, package installation, or service containers. The rule baseline makes each alert explainable. Prepared flow JSON provides a smaller and safer initial parsing surface than arbitrary packet capture. PostgreSQL, PCAP parsers, queues, external LLMs, and graph databases are future options only when measurable needs justify them.
