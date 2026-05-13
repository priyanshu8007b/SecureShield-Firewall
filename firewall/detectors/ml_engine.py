"""Machine learning detection layer."""
import joblib
from pathlib import Path
from typing import Tuple, Optional


class MLEngine:
    def __init__(self, model_path: Path, vectorizer_path: Path,
                 threshold: float = 0.5):
        self.model = None
        self.vectorizer = None
        self.threshold = threshold
        self.model_path = model_path
        self.vectorizer_path = vectorizer_path
        self._load()

    def _load(self):
        try:
            if self.model_path.exists() and self.vectorizer_path.exists():
                self.model = joblib.load(self.model_path)
                self.vectorizer = joblib.load(self.vectorizer_path)
        except Exception as e:
            print(f"[MLEngine] Could not load model: {e}")

    def is_ready(self) -> bool:
        return self.model is not None and self.vectorizer is not None

    def check(self, payload: str) -> Tuple[bool, Optional[str]]:
        if not self.is_ready():
            return False, None
        try:
            features = self.vectorizer.transform([payload])
            if hasattr(self.model, "predict_proba"):
                proba = self.model.predict_proba(features)[0][1]
                if proba >= self.threshold:
                    return True, f"ML score: {proba:.3f}"
            else:
                pred = self.model.predict(features)[0]
                if pred == 1:
                    return True, "ML predicted malicious"
        except Exception as e:
            print(f"[MLEngine] Error: {e}")
        return False, None
