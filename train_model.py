"""
ScamShield AI — Master Training & Optimization Script
Trains the GWO-tuned Random Forest and generates benchmark artifacts.
Run: python train_model.py
"""
import sys, os
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from ml.benchmark import run_benchmark

if __name__ == "__main__":
    print("[*] Starting ScamShield AI Model Optimization & Training Pipeline...")
    results = run_benchmark(dataset_size=6000)
    print("\n[+] Training, Optimization, and Benchmarking successfully completed!")
    print(f"[+] Artifacts saved in: {ROOT / 'ml' / 'artifacts'}")
