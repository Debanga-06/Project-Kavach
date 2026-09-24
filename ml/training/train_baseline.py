"""
Trains the baseline phishing classifier (Logistic Regression, per TRD §6
"Model Strategy"). Imports the SAME feature extraction and vectorization
code the live API uses, so there's no train/serve skew.

Run from the ml/ directory:
    python training/train_baseline.py
"""
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix, classification_report,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# Reuse the backend's own feature extraction so training matches inference exactly.
BACKEND_ROOT = Path(__file__).resolve().parents[2] / "backend"
sys.path.insert(0, str(BACKEND_ROOT))

from app.services.url_analyzer import normalize_url, extract_features, InvalidURLError  # noqa: E402
from app.services.ml_features import vectorize, FEATURE_NAMES  # noqa: E402

DATASET_PATH = Path(__file__).resolve().parents[1] / "datasets" / "urls.csv"
MODEL_DIR = Path(__file__).resolve().parents[1] / "models"


def load_dataset() -> tuple[np.ndarray, np.ndarray]:
    X, y = [], []
    with open(DATASET_PATH) as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                normalized = normalize_url(row["url"])
                features = extract_features(normalized)
            except InvalidURLError:
                continue
            X.append(vectorize(features))
            y.append(int(row["label"]))
    return np.array(X), np.array(y)


def main():
    if not DATASET_PATH.exists():
        print(f"Dataset not found at {DATASET_PATH}. Run generate_dataset.py first.")
        sys.exit(1)

    X, y = load_dataset()
    print(f"Loaded {len(X)} labeled examples ({y.sum()} phishing / {len(y) - y.sum()} legit)")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
    ])
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    metrics = {
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "f1": round(f1_score(y_test, y_pred), 4),
        "roc_auc": round(roc_auc_score(y_test, y_proba), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),  # [[TN, FP], [FN, TP]]
        "n_train": len(X_train),
        "n_test": len(X_test),
    }

    print("\n--- Evaluation (held-out test set) ---")
    print(json.dumps(metrics, indent=2))
    print("\n", classification_report(y_test, y_pred, target_names=["legit", "phishing"]))

    MODEL_DIR.mkdir(exist_ok=True)
    model_path = MODEL_DIR / "url_baseline_v1.joblib"
    joblib.dump(pipeline, model_path)

    metadata = {
        "model": "LogisticRegression",
        "feature_names": FEATURE_NAMES,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset": str(DATASET_PATH.name),
        "n_examples": len(X),
        "metrics": metrics,
        "data_source": "SYNTHETIC — bootstrap dataset, not a real labeled phishing corpus. "
                        "Retrain on real data (PhishTank/OpenPhish/internal) before production use.",
    }
    with open(MODEL_DIR / "metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"\nSaved model to {model_path}")
    print(f"Saved metadata to {MODEL_DIR / 'metadata.json'}")


if __name__ == "__main__":
    main()
