"""
ScamShield AI — ML Model Trainer
Trains a GWO-optimized RandomForest on URL features.
Generates: ml/artifacts/gwo_rf_model.joblib, benchmark.json, and confusion_matrix.png
"""
import sys, os
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ml.benchmark import run_benchmark

def train():
    return run_benchmark(dataset_size=6000)

if __name__ == '__main__':
    train()
