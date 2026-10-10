"""Command-line entry point for the local defensive demo."""
import argparse,json
from pathlib import Path
from sentinelmesh.config import SAMPLE_FLOWS
from sentinelmesh.service import analyze
from sentinelmesh.web import serve

def main():
    parser=argparse.ArgumentParser(prog="sentinelmesh",description="Local, defensive network-flow investigation demo")
    sub=parser.add_subparsers(dest="command",required=True)
    run=sub.add_parser("analyze",help="validate and analyze prepared flow JSON")
    run.add_argument("--input",type=Path,default=SAMPLE_FLOWS)
    web=sub.add_parser("serve",help="start local dashboard")
    web.add_argument("--host",default="127.0.0.1")
    web.add_argument("--port",type=int,default=8000)
    args=parser.parse_args()
    if args.command=="serve":serve(args.host,args.port);return 0
    try:print(json.dumps(analyze(args.input),indent=2));return 0
    except (OSError,ValueError,json.JSONDecodeError) as exc:
        parser.error(str(exc))
if __name__=="__main__":raise SystemExit(main())
