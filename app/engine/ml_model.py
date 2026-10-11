"""
ScamShield AI — ML Model Loader & Predictor
Loads GWO-optimized Random Forest or fallback classifiers on URL feature vectors.
"""
from __future__ import annotations
import os, time
from pathlib import Path
import numpy as np
import joblib

from app.engine.url_features import extract_features, FEATURE_NAMES

ARTIFACTS_DIR = Path(__file__).resolve().parent.parent.parent / "ml" / "artifacts"
MODEL_PATH = ARTIFACTS_DIR / "gwo_rf_model.joblib"

_cached_model = None


def load_model():
    """Lazy loads the trained Random Forest classifier."""
    global _cached_model
    if _cached_model is None and MODEL_PATH.exists():
        try:
            _cached_model = joblib.load(str(MODEL_PATH))
        except Exception as e:
            print(f"[ScamShield ML] Model load error: {e}")
            _cached_model = None
    return _cached_model


def predict_url_features(features: np.ndarray) -> tuple[float, float]:
    """
    Given a 16-dim feature vector, returns (probability_phishing, latency_ms).
    Fast hot path targeting <0.05ms inference.
    """
    start = time.perf_counter()
    model = load_model()

    if model is None:
        # Fallback heuristic calculation if model not yet trained
        score = 0.0
        # Check entropy (index 11)
        if features[11] > 4.0:
            score += 0.3
        # Check min levenshtein (index 12)
        if features[12] <= 2:
            score += 0.4
        # Check abuse tld (index 13)
        if features[13] > 0.5:
            score += 0.4
        # Check punycode (index 14)
        if features[14] > 0.5:
            score += 0.3
        # Check https (index 15)
        if features[15] < 0.5:
            score += 0.15
        latency = (time.perf_counter() - start) * 1000
        return min(1.0, score), latency

    try:
        prob = model.predict_proba(features.reshape(1, -1))[0][1]
    except Exception:
        prob = 0.0

    latency = (time.perf_counter() - start) * 1000
    return float(prob), latency
