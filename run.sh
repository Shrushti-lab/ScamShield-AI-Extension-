#!/usr/bin/env bash
set -e

echo "===================================================================="
echo "  ScamShield AI — Starting Enterprise Backend & Web Portal"
echo "  Target URL: http://127.0.0.1:8000"
echo "===================================================================="

command -v python3 >/dev/null 2>&1 || { echo >&2 "[ERROR] Python 3 is required. Aborting."; exit 1; }

echo "[1/3] Checking and installing dependencies..."
python3 -m pip install -r requirements.txt || echo "[WARNING] Continuing..."

echo "[2/3] Checking trained ML artifacts..."
if [ ! -f "ml/artifacts/gwo_rf_model.joblib" ]; then
    echo "Training GWO-tuned model and generating benchmark artifacts..."
    python3 train_model.py
else
    echo "ML artifacts verified in ml/artifacts/"
fi

echo "[3/3] Starting ScamShield AI FastAPI Server on http://127.0.0.1:8000 ..."
echo "Portal accessible at: http://127.0.0.1:8000/"
echo "Demos accessible at:   http://127.0.0.1:8000/demo/fake_messenger.html"
echo "API Docs at:          http://127.0.0.1:8000/docs"
echo "===================================================================="
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
