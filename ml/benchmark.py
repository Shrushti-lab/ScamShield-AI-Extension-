"""
ScamShield AI — Model Benchmark Suite
Compares:
  1. GWO-Random Forest (tuned via Grey Wolf Optimizer)
  2. Linear SVM
  3. CART Decision Tree
Metrics evaluated:
  Accuracy, Precision, Recall, F1, MCC (Matthews Correlation Coefficient), ROC-AUC, Inference Latency (ms).
Generates:
  - ml/artifacts/benchmark.json
  - ml/artifacts/confusion_matrix.png
"""
from __future__ import annotations
import sys, os, time, json
from pathlib import Path
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, matthews_corrcoef, roc_auc_score, confusion_matrix
)
import joblib
from PIL import Image, ImageDraw, ImageFont

# Add project root to sys.path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.engine.url_features import extract_features
from app.engine.gwo import GreyWolfOptimizer
from ml.dataset_builder import build_dataset


def run_benchmark(dataset_size: int = 5000):
    print("=" * 65)
    print("ScamShield AI — Machine Learning Benchmark Suite")
    print("=" * 65)

    print(f"[*] Generating dataset ({dataset_size} samples)...")
    urls, labels = build_dataset(total_count=dataset_size, seed=42)

    print("[*] Extracting 16-dim lexical features...")
    X = np.array([extract_features(u) for u in urls], dtype=np.float64)
    y = np.array(labels, dtype=np.int32)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    print(f"[*] Split: {len(X_train)} train, {len(X_test)} test.")

    # 1. GWO Hyperparameter Optimization for Random Forest
    print("\n[*] Running Grey Wolf Optimizer (GWO) hyperparameter search...")
    # Fast search subset to ensure quick run time
    gwo_subset_size = min(1200, len(X_train))
    idx = np.random.RandomState(42).choice(len(X_train), gwo_subset_size, replace=False)
    gwo = GreyWolfOptimizer(num_wolves=6, max_iter=6, bounds=[(30, 150), (6, 20), (2, 8)], random_state=42)
    gwo_results = gwo.optimize(X_train[idx], y_train[idx])
    best_params = gwo_results["best_params"]
    print(f"[*] GWO Best Parameters: {best_params} (Best CV MCC: {gwo_results['best_mcc']})")

    models = {
        "GWO-Random Forest": RandomForestClassifier(
            n_estimators=best_params["n_estimators"],
            max_depth=best_params["max_depth"],
            min_samples_split=best_params["min_samples_split"],
            random_state=42,
            n_jobs=-1,
        ),
        "CART Decision Tree": DecisionTreeClassifier(
            max_depth=best_params["max_depth"],
            min_samples_split=best_params["min_samples_split"],
            random_state=42,
        ),
        "Linear SVM": CalibratedClassifierCV(
            LinearSVC(dual=False, random_state=42, max_iter=2000)
        ),
    }

    results = {}
    best_cm = None

    for name, clf in models.items():
        print(f"\n[*] Training and benchmarking: {name}...")
        t0 = time.perf_counter()
        clf.fit(X_train, y_train)
        fit_time = time.perf_counter() - t0

        # Predictions
        y_pred = clf.predict(X_test)
        if hasattr(clf, "predict_proba"):
            y_prob = clf.predict_proba(X_test)[:, 1]
        elif hasattr(clf, "decision_function"):
            y_prob = clf.decision_function(X_test)
        else:
            y_prob = y_pred

        # Latency benchmark (hot path inference over test set)
        t_bench_start = time.perf_counter()
        _ = clf.predict(X_test[:200])
        latency_ms = ((time.perf_counter() - t_bench_start) / 200.0) * 1000.0

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        mcc = float(matthews_corrcoef(y_test, y_pred))
        try:
            auc = float(roc_auc_score(y_test, y_prob))
        except Exception:
            auc = acc

        results[name] = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "mcc": round(mcc, 4),
            "roc_auc": round(auc, 4),
            "inference_latency_ms": round(latency_ms, 4),
            "train_time_seconds": round(fit_time, 3),
        }

        print(f"    Accuracy:  {acc*100:.2f}% | F1: {f1:.4f} | MCC: {mcc:.4f} | Latency: {latency_ms:.4f} ms")

        if name == "GWO-Random Forest":
            best_cm = confusion_matrix(y_test, y_pred)

    # Save artifacts
    artifacts_dir = ROOT / "ml" / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    # Save best model
    gwo_rf = models["GWO-Random Forest"]
    joblib.dump(gwo_rf, str(artifacts_dir / "gwo_rf_model.joblib"))
    print(f"\n[+] Saved primary model to {artifacts_dir / 'gwo_rf_model.joblib'}")

    benchmark_data = {
        "models": results,
        "gwo_optimization": {
            "best_hyperparameters": best_params,
            "convergence_curve": gwo_results["convergence_curve"],
            "best_mcc": gwo_results["best_mcc"],
            "num_wolves": gwo.num_wolves,
            "iterations": gwo.max_iter,
        },
        "dataset_info": {
            "total_samples": len(y),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "features_dim": 16,
        },
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    benchmark_file = artifacts_dir / "benchmark.json"
    with open(benchmark_file, "w", encoding="utf-8") as f:
        json.dump(benchmark_data, f, indent=2)
    print(f"[+] Saved benchmark report to {benchmark_file}")

    # Generate Confusion Matrix image via Pillow
    if best_cm is not None:
        _draw_confusion_matrix(best_cm, artifacts_dir / "confusion_matrix.png")
        print(f"[+] Saved confusion matrix to {artifacts_dir / 'confusion_matrix.png'}")

    return benchmark_data


def _draw_confusion_matrix(cm: np.ndarray, output_path: Path):
    """Draws a clean, presentation-ready confusion matrix PNG."""
    w, h = 600, 480
    img = Image.new("RGB", (w, h), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)

    # Background header
    draw.rectangle([(0, 0), (w, 60)], fill=(37, 99, 235))
    draw.text((20, 20), "ScamShield AI — Confusion Matrix (GWO-Random Forest)", fill=(255, 255, 255))

    # Grid parameters
    gx, gy = 140, 120
    cell_size = 140
    tn, fp = cm[0][0], cm[0][1]
    fn, tp = cm[1][0], cm[1][1]

    # Cells
    # TN (top-left) - Soft green
    draw.rectangle([(gx, gy), (gx + cell_size, gy + cell_size)], fill=(236, 253, 245), outline=(16, 185, 129), width=2)
    draw.text((gx + 20, gy + 30), "True Benign", fill=(6, 95, 70))
    draw.text((gx + 40, gy + 70), f"{tn:,}", fill=(15, 23, 42))

    # FP (top-right) - Soft amber
    draw.rectangle([(gx + cell_size + 15, gy), (gx + 2*cell_size + 15, gy + cell_size)], fill=(255, 251, 235), outline=(245, 158, 11), width=2)
    draw.text((gx + cell_size + 30, gy + 30), "False Phish (FP)", fill=(146, 64, 14))
    draw.text((gx + cell_size + 55, gy + 70), f"{fp:,}", fill=(15, 23, 42))

    # FN (bottom-left) - Soft red
    draw.rectangle([(gx, gy + cell_size + 15), (gx + cell_size, gy + 2*cell_size + 15)], fill=(254, 242, 242), outline=(220, 38, 38), width=2)
    draw.text((gx + 20, gy + cell_size + 45), "False Benign (FN)", fill=(153, 27, 27))
    draw.text((gx + 40, gy + cell_size + 85), f"{fn:,}", fill=(15, 23, 42))

    # TP (bottom-right) - Vibrant trust green
    draw.rectangle([(gx + cell_size + 15, gy + cell_size + 15), (gx + 2*cell_size + 15, gy + 2*cell_size + 15)], fill=(209, 250, 229), outline=(16, 185, 129), width=2)
    draw.text((gx + cell_size + 30, gy + cell_size + 45), "True Phishing", fill=(6, 95, 70))
    draw.text((gx + cell_size + 55, gy + cell_size + 85), f"{tp:,}", fill=(15, 23, 42))

    # Axes labels
    draw.text((20, gy + cell_size - 10), "Actual Class", fill=(71, 85, 105))
    draw.text((gx + 60, gy - 30), "Predicted Benign", fill=(71, 85, 105))
    draw.text((gx + cell_size + 60, gy - 30), "Predicted Phish", fill=(71, 85, 105))

    # Footer metrics
    acc = (tp + tn) / (tp + tn + fp + fn)
    draw.rectangle([(0, h - 50), (w, h)], fill=(248, 250, 252))
    draw.text((20, h - 35), f"Overall Accuracy: {acc*100:.2f}%  |  Total Evaluated: {cm.sum():,} URLs", fill=(15, 23, 42))

    img.save(str(output_path))


if __name__ == "__main__":
    run_benchmark(dataset_size=6000)
