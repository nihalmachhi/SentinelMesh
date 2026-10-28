"""Project paths and safe demo defaults."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
GENERATED = DATA / "generated"
DB_PATH = GENERATED / "sentinelmesh.sqlite3"
SAMPLE_FLOWS = DATA / "sample_flows.json"
MAX_IMPORT_BYTES = 2_000_000
EGRESS_RATE_BYTES_PER_SECOND = 25_000_000
MULTI_PORT_WINDOW_SECONDS = 300
MULTI_PORT_MINIMUM_PORTS = 5
