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
    run = sub.add_parser("analyze", help="validate and analyze prepared flow JSON")
    run.add_argument("--input", type=Path, default=SAMPLE_FLOWS)
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
    if args.command == "reset-demo":
        with Store(DB_PATH) as store:
            store.reset_demo()
        print("Demo data cleared; audit history retained.")
        return 0
    try:
        print(json.dumps(analyze(args.input), indent=2))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
