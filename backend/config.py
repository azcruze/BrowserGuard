import os
import secrets
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_DIR = PROJECT_ROOT / "database"


class Config:
    SECRET_KEY = os.environ.get("BROWSERGUARD_SECRET_KEY") or secrets.token_hex(32)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "BROWSERGUARD_DATABASE_URL",
        f"sqlite:///{(DATABASE_DIR / 'browserguard.sqlite3').as_posix()}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    JSON_SORT_KEYS = False
    SCORE_THRESHOLDS = {"low": 24, "moderate": 49, "high": 74}
    SEED_BENCHMARK_DATA = True
