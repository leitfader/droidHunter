from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
JOBS_DIR = DATA_DIR / "jobs"
APKS_DIR = DATA_DIR / "apks"
RESULTS_DIR = DATA_DIR / "results"

DEFAULT_SCAN_RATE = 1.0
DEFAULT_PROCESSES = 3
