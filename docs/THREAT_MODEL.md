# Threat model

## Scope

SentinelMesh is a local network-flow investigation demo. It validates prepared metadata, derives explainable findings, stores evidence in SQLite, serves a loopback dashboard, and records simulated analyst decisions. It is not a production detection or response platform.

## Assets

- Integrity and provenance of imported flow records.
- Integrity of reports, approvals, and append-only audit history.
- The random per-run API bearer token.
- Local database contents and the analyst browser session.
- Confidentiality of evidence sent to an explicitly configured LLM provider.

## Threats and controls

| Threat | Control | Remaining limit |
| --- | --- | --- |
| Malformed or oversized flow input | File/row bounds, strict JSON schema, address/protocol/counter validation; bounded CSV row reads | The application does not inspect packet payloads or capture live traffic |
| Browser-originated unauthorized writes | Random token, same-origin and loopback host checks, CSP and security headers | A local machine compromise or token disclosure is out of scope |
| Audit history modification through application code | Append-only SQLite triggers and SHA-256 hash-chain verification | A local administrator able to replace the database and code can bypass application-level controls |
| Prompt or tool misuse | LLM disabled by default, no callable tools, JSON schema validation, evidence-ID validation | When enabled, evidence is transmitted to the configured provider; provider handling is outside this repository's control |
| Misinterpreting rules or ATT&CK tags | Evidence IDs and explicit candidate/heuristic language | No public dataset has been evaluated; no real-world efficacy or false-positive rate is known |
| Accidental real-world response | Allow-listed records marked simulated-only, linked report, expiry, no control integration | Do not expose the demo as an operational response service |
| Misuse of downloaded datasets | No automatic download or redistribution; source and terms documented separately | Users must confirm current dataset terms and authorization before use |

## Safe operation

Bind only to `127.0.0.1`, keep the startup token private, use benign authorized lab data, and back up the local database before maintenance. Synthetic records use reserved/private example IP ranges and have no third-party dataset terms. Public dataset files are not included in this repository; review [dataset sources and terms](datasets.md) before obtaining them.

## Reporting

This repository is a non-production demonstration. Report suspected security issues through the repository owner's private contact channel; do not include sensitive traffic captures in public issues.
