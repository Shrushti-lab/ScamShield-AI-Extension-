"""Blocklist API router."""
from __future__ import annotations
from fastapi import APIRouter
from app.db import SessionLocal, BlockedSender
from app.schemas import BlockReq

router = APIRouter(prefix="/api", tags=["blocklist"])


@router.get("/blocklist")
async def get_blocklist():
    db = SessionLocal()
    try:
        items = db.query(BlockedSender).order_by(BlockedSender.blocked_at.desc()).all()
        return {
            "blocked_senders": [
                {
                    "id": b.id,
                    "handle": b.handle,
                    "platform": b.platform,
                    "blocked_at": b.blocked_at.strftime("%Y-%m-%d %H:%M") if b.blocked_at else "",
                }
                for b in items
            ],
            "total": len(items),
        }
    finally:
        db.close()


@router.post("/blocklist")
async def add_blocked(req: BlockReq):
    db = SessionLocal()
    try:
        existing = db.query(BlockedSender).filter(BlockedSender.handle == req.handle).first()
        if existing:
            return {"status": "already_blocked", "id": existing.id}
        b = BlockedSender(handle=req.handle, platform=req.platform)
        db.add(b)
        db.commit()
        return {"status": "blocked", "id": b.id, "handle": b.handle}
    finally:
        db.close()


@router.delete("/blocklist/{handle}")
async def remove_blocked(handle: str):
    db = SessionLocal()
    try:
        b = db.query(BlockedSender).filter(BlockedSender.handle == handle).first()
        if not b:
            return {"status": "not_found"}
        db.delete(b)
        db.commit()
        return {"status": "unblocked", "handle": handle}
    finally:
        db.close()
