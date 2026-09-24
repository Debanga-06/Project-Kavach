# KavachAI ML

## Setup
Uses the same Python environment as `backend/` (scikit-learn, joblib, numpy,
pandas are already in `backend/requirements.txt`).

## Train the baseline classifier
```bash
cd ml/datasets
python3 generate_dataset.py      # writes urls.csv (synthetic bootstrap data)

cd ../training
python3 train_baseline.py        # trains + evaluates, saves to ../models/
```

This writes:
- `models/url_baseline_v1.joblib` — the trained sklearn Pipeline (StandardScaler + LogisticRegression)
- `models/metadata.json` — feature names, training timestamp, held-out metrics

The backend (`app/services/ml_classifier.py`) loads this file automatically
on first scan request. If it's missing, scoring falls back to rules-only —
nothing crashes.

## IMPORTANT: synthetic data caveat
`datasets/generate_dataset.py` produces **synthetic bootstrap data**, not a
real labeled phishing corpus. It exists to stand up the full training →
eval → serving pipeline end-to-end. The ~98% precision/recall you'll see is
a reflection of that synthetic data being cleanly separable — it is NOT a
real-world performance guarantee.

Before trusting this model for real scoring: replace `datasets/urls.csv`
with real labeled data (PhishTank, OpenPhish, or an internal labeled
corpus) in the same `url,label` CSV format, then re-run `train_baseline.py`.
No other code changes needed — feature extraction, vectorization, and the
serving path are already wired to whatever the retrained model produces.
