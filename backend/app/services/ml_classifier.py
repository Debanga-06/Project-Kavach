"""
Loads the trained baseline classifier and scores URLs at request time.

Fails gracefully: if the model file doesn't exist (not trained yet) or fails
to load, predict() returns None rather than raising — the risk engine already
treats a None ml_score as "source unavailable" and redistributes its weight
onto the remaining signals (see risk_engine.py), so the API keeps working
with rules-only scoring until a model is trained.
"""
import logging
from functools import lru_cache
from pathlib import Path

from app.services.ml_features import vectorize
from app.services.url_analyzer import URLFeatures

logger = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).resolve().parents[3] / "ml" / "models" / "url_baseline_v1.joblib"


@lru_cache(maxsize=1)
def _load_model():
    try:
        import joblib
        model = joblib.load(MODEL_PATH)
        logger.info("Loaded ML model from %s", MODEL_PATH)
        return model
    except FileNotFoundError:
        logger.warning("ML model not found at %s — falling back to rules-only scoring. "
                        "Run ml/training/train_baseline.py to train it.", MODEL_PATH)
        return None
    except Exception:
        logger.exception("Failed to load ML model — falling back to rules-only scoring.")
        return None


def predict(features: URLFeatures) -> float | None:
    """Returns phishing probability scaled 0-100, or None if the model is unavailable."""
    model = _load_model()
    if model is None:
        return None
    try:
        vector = [vectorize(features)]
        proba = model.predict_proba(vector)[0][1]  # P(class=1=phishing)
        return round(float(proba) * 100, 2)
    except Exception:
        logger.exception("ML inference failed for this request — falling back to rules-only scoring.")
        return None
