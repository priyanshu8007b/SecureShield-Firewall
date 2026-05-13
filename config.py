import os
from pathlib import Path

BASE_DIR = Path(__file__).parent

MODELS_DIR = BASE_DIR / "models"
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"

DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", 5000))

RATE_LIMIT_MAX_REQUESTS = 100
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_BLOCK_DURATION = 300

ML_THRESHOLD = 0.5
MODEL_PATH = MODELS_DIR / "model.pkl"
VECTORIZER_PATH = MODELS_DIR / "vectorizer.pkl"

for d in [MODELS_DIR, DATA_DIR, LOGS_DIR]:
    d.mkdir(exist_ok=True)
