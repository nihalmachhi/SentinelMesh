# How it works

## Start

Create a Python virtual environment, activate it, run `scripts/run.ps1 analyze`, then start the dashboard with `scripts/run.ps1 serve`. Open http://127.0.0.1:8000. The analyze command validates the bundled sample and repopulates the local SQLite evidence store.

## Pipeline

A JSON array becomes typed flow records. Input validation rejects malformed IPs, unsupported protocols, out-of-range ports, repeated IDs, and oversized inputs. The rules flag selected outbound sensitive service ports, high egress rate, and repeated multi-port activity. Every finding carries evidence flow IDs and observed feature values.

Findings are grouped by source host. The incident explorer links directly to the original flows. The report helper uses a narrow, local read-only tool list and returns observed facts separately from hypotheses and recommended checks.

## Human approval

The dashboard can record a simulated mark-for-review or host-isolation action. It requires an analyst name and records the decision in an audit table. No packet, endpoint, firewall, or network state is modified.

## Evaluation and limits

Use the synthetic sample to inspect rules and output. To evaluate a model later, split captures by session/time, preserve label provenance, report precision/recall/F1 and PR-AUC where appropriate, and measure false positives at the stated threshold. This MVP has no labeled benchmark, learned classifier, LLM, production deployment, or performance claim. Do not infer real-world security efficacy from the demo.
