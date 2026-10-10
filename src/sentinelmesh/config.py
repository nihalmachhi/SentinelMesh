"""Project paths and safe demo defaults."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
GENERATED = DATA / "generated"
DB_PATH = GENERATED / "sentinelmesh.sqlite3"
SAMPLE_FLOWS = DATA / "sample_flows.json"
MAX_IMPORT_BYTES = 2_000_000
