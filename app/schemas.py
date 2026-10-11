"""Pydantic schemas for request/response validation."""
from __future__ import annotations
from typing import Any, Optional
from pydantic import BaseModel, Field


# ── Scan Requests ──────────────────────────────────────────────
class ConversationScanReq(BaseModel):
    platform: str = "Messenger"
    sender: str = ""
    messages: list[str] = []
    page_url: str = ""

class ListingScanReq(BaseModel):
    title: str
    price: float = 0
    currency: str = "USD"
    seller_joined: str = ""
    seller_name: str = ""
    description: str = ""
    messages: list[str] = []

class UrlScanReq(BaseModel):
    url: str

class PaymentFormScanReq(BaseModel):
    url: str
    field_signals: list[str] = []

# ── Blocklist ──────────────────────────────────────────────────
class BlockReq(BaseModel):
    handle: str
    platform: str = "General"

# ── Reports ────────────────────────────────────────────────────
class ReportReq(BaseModel):
    platform: str = "Web"
    handle_or_url: str = ""
    category: str = ""
    note: str = ""

# ── Settings ───────────────────────────────────────────────────
class SettingsUpdate(BaseModel):
    chime_enabled: Optional[bool] = None
    hud_enabled: Optional[bool] = None
    facebook_enabled: Optional[bool] = None
    telegram_enabled: Optional[bool] = None
    web_enabled: Optional[bool] = None
    cardguard_enabled: Optional[bool] = None

# ── Unified scan result ───────────────────────────────────────
class ScanResult(BaseModel):
    id: int = 0
    risk_score: int = 0
    verdict: str = "Safe"
    category: str = ""
    platform: str = ""
    scam_dna: list[str] = []
    matched_evidence: list[str] = []
    recommendations: list[str] = []
    timeline: list[dict] = []
    explanation: str = ""
    latency_ms: float = 0
    target: str = ""
    dom_selector: str = ""
    endpoint: str = ""
    engine_used: str = ""
    timestamp: str = ""
