"""Settings and Extension Heartbeat API router."""
from __future__ import annotations
import time
from fastapi import APIRouter
from app.db import SessionLocal, Settings
from app.schemas import SettingsUpdate

router = APIRouter(prefix="/api", tags=["settings"])

_last_heartbeat = {"time": 0}


@router.get("/settings")
async def get_settings():
    db = SessionLocal()
    try:
        s = db.query(Settings).first()
        if not s:
            return {
                "chime_enabled": True,
                "hud_enabled": True,
                "facebook_enabled": True,
                "telegram_enabled": True,
                "web_enabled": True,
                "cardguard_enabled": True,
            }
        return {
            "chime_enabled": s.chime_enabled,
            "hud_enabled": s.hud_enabled,
            "facebook_enabled": s.facebook_enabled,
            "telegram_enabled": s.telegram_enabled,
            "web_enabled": s.web_enabled,
            "cardguard_enabled": s.cardguard_enabled,
        }
    finally:
        db.close()


@router.put("/settings")
async def update_settings(req: SettingsUpdate):
    db = SessionLocal()
    try:
        s = db.query(Settings).first()
        if not s:
            s = Settings(id=1)
            db.add(s)
        for field in [
            "chime_enabled",
            "hud_enabled",
            "facebook_enabled",
            "telegram_enabled",
            "web_enabled",
            "cardguard_enabled",
        ]:
            val = getattr(req, field, None)
            if val is not None:
                setattr(s, field, val)
        db.commit()
        return {"status": "updated"}
    finally:
        db.close()


@router.post("/extension/heartbeat")
async def post_heartbeat():
    _last_heartbeat["time"] = time.time()
    return {"status": "ok"}


@router.get("/extension/heartbeat")
async def get_heartbeat():
    elapsed = time.time() - _last_heartbeat["time"]
    connected = elapsed < 60
    return {"connected": connected, "last_seen_seconds_ago": round(elapsed, 1)}
