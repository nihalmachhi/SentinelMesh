"""Command-line entry point for the local defensive demo."""

import argparse
import json
from pathlib import Path

from sentinelmesh.api.http import serve
from sentinelmesh.core.config import DB_PATH, SAMPLE_FLOWS
from sentinelmesh.service import analyze
from sentinelmesh.storage.sqlite import Store


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="sentinelmesh",
        description="Local, defensive network-flow investigation demo",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser(
        "analyze", help="validate and analyze flow JSON, Zeek conn.log, or NetFlow CSV"
    )
    run.add_argument("--input", type=Path, default=SAMPLE_FLOWS)
    run.add_argument("--format", choices=("json", "zeek-conn", "netflow-csv"), default="json")
    benchmark = sub.add_parser(
        "benchmark", help="evaluate one public labeled dataset chronologically"
    )
    benchmark.add_argument("--dataset", choices=("cic-ids2017", "unsw-nb15"), required=True)
    benchmark.add_argument("--input", type=Path, required=True)
    benchmark.add_argument(
        "--timezone", help="required for CIC-IDS2017 naive timestamps, e.g. Asia/Kolkata"
    )
    benchmark.add_argument("--limit", type=int, default=20_000)
    benchmark.add_argument("--model", choices=("rules", "isolation-forest"), default="rules")
    benchmark.add_argument("--threshold", type=float, default=0.5)
    benchmark.add_argument("--contamination", type=float, default=0.01)
    graph = sub.add_parser("graph", help="summarize host communication (install the graph extra)")
    graph.add_argument("--input", type=Path, default=SAMPLE_FLOWS)
    graph.add_argument("--format", choices=("json", "zeek-conn", "netflow-csv"), default="json")
    drift = sub.add_parser("drift", help="compare early and later flow-feature distributions")
    drift.add_argument("--input", type=Path, default=SAMPLE_FLOWS)
    drift.add_argument("--format", choices=("json", "zeek-conn", "netflow-csv"), default="json")
    audit = sub.add_parser("audit-export", help="verify and export the append-only audit log")
    audit.add_argument("--output", type=Path, required=True)
    sub.add_parser(
        "reset-demo",
        help="explicitly clear stored demo data while retaining the append-only audit log",
    )
    web = sub.add_parser("serve", help="start local dashboard")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if args.command == "serve":
        serve(args.host, args.port)
        return 0
    if args.command == "benchmark":
        try:
            from sentinelmesh.evaluation import evaluate_dataset
            from sentinelmesh.ingest.datasets import load_cic_ids2017, load_unsw_nb15

            if args.dataset == "cic-ids2017":
                dataset = load_cic_ids2017(
                    args.input, timezone_name=args.timezone, limit=args.limit
                )
            else:
                dataset = load_unsw_nb15(args.input, limit=args.limit)
            result = evaluate_dataset(
                dataset,
                model=args.model,
                threshold=args.threshold,
                contamination=args.contamination,
            )
            print(json.dumps(result, indent=2))
            return 0
        except (OSError, ValueError, RuntimeError) as exc:
            parser.error(str(exc))
    if args.command == "graph":
        try:
            if args.format == "json":
                from sentinelmesh.ingest.flows import load_flows

                flows = load_flows(args.input)
            elif args.format == "zeek-conn":
                from sentinelmesh.ingest.zeek import load_zeek_conn

                flows = load_zeek_conn(args.input)
            else:
                from sentinelmesh.ingest.netflow import load_netflow_csv

                flows = load_netflow_csv(args.input)
            from sentinelmesh.correlation.graph import graph_summary

            print(json.dumps(graph_summary(flows), indent=2))
            return 0
        except (OSError, ValueError, RuntimeError) as exc:
            parser.error(str(exc))
    if args.command == "drift":
        try:
            from sentinelmesh.drift import drift_report
            from sentinelmesh.ingest.flows import load_flows
            from sentinelmesh.ingest.netflow import load_netflow_csv
            from sentinelmesh.ingest.zeek import load_zeek_conn

            loaders = {
                "json": load_flows,
                "zeek-conn": load_zeek_conn,
                "netflow-csv": load_netflow_csv,
            }
            print(json.dumps(drift_report(loaders[args.format](args.input)), indent=2))
            return 0
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
    if args.command == "audit-export":
        try:
            with Store(DB_PATH) as store:
                count = store.export_audit(args.output)
            print(json.dumps({"events_exported": count, "output": str(args.output)}, indent=2))
            return 0
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
    if args.command == "reset-demo":
        with Store(DB_PATH) as store:
            store.reset_demo()
        print("Demo data cleared; audit history retained.")
        return 0
    try:
        print(json.dumps(analyze(args.input, args.format), indent=2))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
