"""Reports API router."""
from __future__ import annotations
from fastapi import APIRouter
from app.db import SessionLocal, Report
from app.schemas import ReportReq

router = APIRouter(prefix="/api", tags=["reports"])


@router.get("/reports")
async def get_reports():
    db = SessionLocal()
    try:
        items = db.query(Report).order_by(Report.created_at.desc()).all()
        return {
            "reports": [
                {
                    "id": r.id,
                    "platform": r.platform,
                    "handle_or_url": r.handle_or_url,
                    "category": r.category,
                    "note": r.note,
                    "created_at": r.created_at.strftime("%Y-%m-%d %H:%M") if r.created_at else "",
                }
                for b in [None]  # dummy
                for r in items
            ],
            "total": len(items),
        }
    finally:
        db.close()


@router.post("/reports")
async def create_report(req: ReportReq):
    db = SessionLocal()
    try:
        r = Report(
            platform=req.platform,
            handle_or_url=req.handle_or_url,
            category=req.category,
            note=req.note,
        )
        db.add(r)
        db.commit()
        return {"status": "submitted", "id": r.id}
    finally:
        db.close()
