"""Stats API router."""
from __future__ import annotations
from fastapi import APIRouter
from app.db import SessionLocal, Scan

router = APIRouter(prefix="/api", tags=["stats"])


@router.get("/stats")
async def get_stats():
    db = SessionLocal()
    try:
        total = db.query(Scan).count()
        warnings = db.query(Scan).filter(Scan.verdict == "Proceed Carefully").count()
        high_risk = db.query(Scan).filter(Scan.verdict == "High Risk").count()

        platforms = {}
        for p in ["Messenger", "Telegram", "Marketplace", "Web"]:
            platforms[p] = db.query(Scan).filter(Scan.platform == p).count()

        categories = {}
        for c in ["Conversations", "Marketplace", "Links", "Payments"]:
            categories[c] = db.query(Scan).filter(Scan.category == c).count()

        for s in db.query(Scan).filter(Scan.risk_score >= 35).all():
            cat = s.category or "General"
            categories[cat] = categories.get(cat, 0)

        return {
            "status": "Active",
            "items_checked": total,
            "warnings": warnings,
            "high_risk": high_risk,
            "by_platform": platforms,
            "by_category": categories,
        }
    finally:
        db.close()
