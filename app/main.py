"""
ScamShield AI — FastAPI Application
Serves the enterprise web portal + REST API for the Chrome extension.
"""
from __future__ import annotations
import json, os
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.db import init_db, SessionLocal, Scan, Settings, seed_demo_scans
from app.routers.scan import router as scan_router
from app.routers.blocklist import router as blocklist_router
from app.routers.reports import router as reports_router
from app.routers.stats import router as stats_router
from app.routers.settings import router as settings_router

PORTAL_DIR = Path(__file__).resolve().parent.parent / "portal"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed_demo_scans()
    yield


app = FastAPI(
    title="ScamShield AI",
    description="Enterprise Real-Time Browser Security Suite",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_origin_regex=r"chrome-extension://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan_router)
app.include_router(blocklist_router)
app.include_router(reports_router)
app.include_router(stats_router)
app.include_router(settings_router)


# ── Model benchmark endpoint ──────────────────────────────────
@app.get("/api/model/benchmark")
async def get_benchmark():
    benchmark_path = Path(__file__).resolve().parent.parent / "ml" / "artifacts" / "benchmark.json"
    if benchmark_path.exists():
        try:
            return json.loads(benchmark_path.read_text(encoding="utf-8"))
        except Exception as e:
            return {"error": f"Error loading benchmark: {str(e)}"}
    return {"error": "Benchmark not yet generated. Run train_model.py first."}


# ── Reset seed data ───────────────────────────────────────────
@app.post("/api/reset-demo-data")
async def reset_demo():
    seed_demo_scans(force=True)
    return {"status": "reset", "message": "Demo data restored."}


# ── Static portal serving ─────────────────────────────────────
@app.get("/")
async def serve_index():
    index = PORTAL_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return {"error": "Portal not found. Ensure portal/index.html exists."}


# Mount static files (CSS, JS, etc.)
if PORTAL_DIR.exists():
    app.mount("/", StaticFiles(directory=str(PORTAL_DIR), html=True), name="portal")
