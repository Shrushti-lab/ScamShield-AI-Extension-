@echo off
echo ====================================================================
echo   ScamShield AI — Starting Enterprise Backend & Web Portal
echo   Target URL: http://127.0.0.1:8000
echo ====================================================================

REM Check if Python 3.11 is available via path or py launcher
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed or not in PATH. Please install Python 3.11+.
    pause
    exit /b 1
)

echo [1/3] Checking and installing dependencies...
python -m pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] Pip install returned non-zero code. Attempting to continue...
)

echo [2/3] Checking trained ML artifacts...
if not exist "ml\artifacts\gwo_rf_model.joblib" (
    echo Training GWO-tuned model and generating benchmark artifacts...
    python train_model.py
) else (
    echo ML artifacts found in ml\artifacts\
)

echo [3/3] Starting ScamShield AI FastAPI Server on http://127.0.0.1:8000 ...
echo Portal accessible at: http://127.0.0.1:8000/
echo Demos accessible at:   http://127.0.0.1:8000/demo/fake_messenger.html
echo API Docs at:          http://127.0.0.1:8000/docs
echo ====================================================================
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
