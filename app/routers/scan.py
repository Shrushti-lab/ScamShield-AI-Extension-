"""Scan API router — conversation, listing, URL, and payment form endpoints."""
from __future__ import annotations
import json, time, hashlib, datetime
from fastapi import APIRouter, Query
from typing import Optional
from app.schemas import ConversationScanReq, ListingScanReq, UrlScanReq, PaymentFormScanReq
from app.db import SessionLocal, Scan
from app.engine.conversation import analyze_conversation
from app.engine.marketplace import analyze_listing
from app.engine.url_features import predict_url
from app.engine.cardguard import analyze_payment_form

router = APIRouter(prefix="/api", tags=["scans"])


def _persist(result: dict, endpoint: str, primary_text: str = "", secondary_text: str = "") -> dict:
    """Save scan result to DB and return it with assigned id."""
    db = SessionLocal()
    try:
        scan = Scan(
            platform=result.get("platform", "Web"),
            category=result.get("category", ""),
            target=result.get("target", ""),
            primary_text=primary_text[:2000],
            secondary_text=secondary_text[:2000],
            verdict=result.get("verdict", "Safe"),
            risk_score=result.get("risk_score", 0),
            scam_dna=json.dumps(result.get("scam_dna", [])),
            matched_evidence=json.dumps(result.get("matched_evidence", [])),
            recommendations=json.dumps(result.get("recommendations", [])),
            timeline=json.dumps(result.get("timeline", [])),
            explanation=result.get("explanation", ""),
            latency_ms=result.get("latency_ms", 0),
            dom_selector=result.get("dom_selector", ""),
            endpoint=endpoint,
            engine_used=result.get("engine_used", ""),
            scan_hash=hashlib.md5(f"{result.get('target','')}:{primary_text[:200]}".encode()).hexdigest(),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        result["id"] = scan.id
        result["endpoint"] = endpoint
        result["timestamp"] = scan.timestamp.strftime("%Y-%m-%d %H:%M:%S") if scan.timestamp else ""
        return result
    finally:
        db.close()


def _scan_to_dict(s: Scan) -> dict:
    return {
        "id": s.id,
        "timestamp": s.timestamp.strftime("%Y-%m-%d %H:%M:%S") if s.timestamp else "",
        "platform": s.platform,
        "category": s.category,
        "target": s.target,
        "verdict": s.verdict,
        "risk_score": s.risk_score,
        "scam_dna": json.loads(s.scam_dna or "[]"),
        "matched_evidence": json.loads(s.matched_evidence or "[]"),
        "recommendations": json.loads(s.recommendations or "[]"),
        "timeline": json.loads(s.timeline or "[]"),
        "explanation": s.explanation,
        "latency_ms": s.latency_ms,
        "dom_selector": s.dom_selector,
        "endpoint": s.endpoint,
        "engine_used": s.engine_used,
        "primary_text": s.primary_text[:300] if s.primary_text else "",
    }


# ── POST endpoints ─────────────────────────────────────────────

@router.post("/scan/conversation")
async def scan_conversation(req: ConversationScanReq):
    result = analyze_conversation(
        platform=req.platform,
        sender=req.sender,
        messages=req.messages,
        page_url=req.page_url,
    )
    primary = " | ".join(req.messages[:5])
    return _persist(result, "/api/scan/conversation", primary_text=primary, secondary_text=req.sender)


@router.post("/scan/listing")
async def scan_listing(req: ListingScanReq):
    result = analyze_listing(
        title=req.title,
        price=req.price,
        currency=req.currency,
        seller_joined=req.seller_joined,
        seller_name=req.seller_name,
        description=req.description,
        messages=req.messages,
    )
    return _persist(result, "/api/scan/listing", primary_text=req.title, secondary_text=req.description)


@router.post("/scan/url")
async def scan_url(req: UrlScanReq):
    result = predict_url(req.url)
    return _persist(result, "/api/scan/url", primary_text=req.url)


@router.post("/scan/payment-form")
async def scan_payment(req: PaymentFormScanReq):
    result = analyze_payment_form(req.url, req.field_signals)
    return _persist(result, "/api/scan/payment-form", primary_text=req.url,
                    secondary_text=json.dumps(req.field_signals))


# ── GET endpoints ──────────────────────────────────────────────

@router.get("/scans")
async def list_scans(
    category: Optional[str] = Query(None),
    platform: Optional[str] = Query(None),
    verdict: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
):
    db = SessionLocal()
    try:
        q = db.query(Scan).order_by(Scan.id.desc())
        if category:
            q = q.filter(Scan.category == category)
        if platform:
            q = q.filter(Scan.platform == platform)
        if verdict:
            q = q.filter(Scan.verdict == verdict)
        items = q.limit(limit).all()
        return {"scans": [_scan_to_dict(s) for s in items], "count": len(items)}
    finally:
        db.close()


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: int):
    db = SessionLocal()
    try:
        s = db.query(Scan).filter(Scan.id == scan_id).first()
        if not s:
            return {"error": "Scan not found"}
        return _scan_to_dict(s)
    finally:
        db.close()
