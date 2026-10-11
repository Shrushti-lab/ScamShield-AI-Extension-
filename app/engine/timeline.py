"""
ScamShield AI — Conversation Trust Timeline Engine
Builds the 5-stage sequential behavioral trust timeline:
Friendly opening → Trust building → Financial request → Urgency pressure → Intercepted
"""
from __future__ import annotations
import re

STAGE_1 = "Friendly Opening"
STAGE_2 = "Trust Building"
STAGE_3 = "Financial Request"
STAGE_4 = "Urgency Pressure"
STAGE_5 = "Intercepted"

RE_FRIENDLY = re.compile(
    r"(hello|hi|hey|good\s*(morning|afternoon|evening)|howdy|greetings|dear|friend|buddy|sup)",
    re.I
)

RE_TRUST_BUILDING = re.compile(
    r"(i\s+(accidentally|mistakenly)|my\s+(son|husband|daughter|agent|assistant)|"
    r"i.?m\s+(out\s+of\s+town|military|abroad|busy|disabled)|i\s+can\s+trust\s+you|"
    r"official\s+(support|admin|representative)|joined|guaranteed|safe|honest|promise|"
    r"i\s+have\s+been\s+trading\s+for|member\s+of|verified)",
    re.I
)

RE_FINANCIAL_REQUEST = re.compile(
    r"(send|wire|pay|deposit|transfer|zelle|venmo|cashapp|upi|phonepe|gpay|paytm|"
    r"crypto|bitcoin|btc|eth|usdt|code|otp|seed\s*phrase|shipping\s*fee|advance|gift\s*card)",
    re.I
)

RE_URGENCY_PRESSURE = re.compile(
    r"(urgent|immediately|right\s*now|hurry|quick|fast|15\s*min|today\s*only|"
    r"last\s*chance|last\s*warning|will\s*be\s*(blocked|suspended|disabled|deleted)|"
    r"don.?t\s*delay|expires|forfeit)",
    re.I
)


def extract_trust_timeline(messages: list[str], risk_score: int = 0) -> list[dict]:
    """
    Classifies chronological stages across message sequence.
    Returns list of dicts: [{"stage": ..., "evidence": ..., "detected": bool}]
    """
    full_text = " \n ".join(messages) if messages else ""

    timeline = []

    # 1. Friendly Opening
    m_friendly = RE_FRIENDLY.search(full_text)
    if m_friendly:
        timeline.append({
            "stage": STAGE_1,
            "evidence": f"Initial conversational overture: '{m_friendly.group(0)}'",
            "detected": True
        })
    elif messages:
        timeline.append({
            "stage": STAGE_1,
            "evidence": "Opening message initiates interaction",
            "detected": True
        })

    # 2. Trust Building
    m_trust = RE_TRUST_BUILDING.search(full_text)
    if m_trust:
        timeline.append({
            "stage": STAGE_2,
            "evidence": f"Pretext or authority assertion: '{m_trust.group(0)}'",
            "detected": True
        })

    # 3. Financial / Credential Request
    m_fin = RE_FINANCIAL_REQUEST.search(full_text)
    if m_fin:
        timeline.append({
            "stage": STAGE_3,
            "evidence": f"Demand for payment, verification token, or credentials: '{m_fin.group(0)}'",
            "detected": True
        })

    # 4. Urgency Pressure
    m_urg = RE_URGENCY_PRESSURE.search(full_text)
    if m_urg:
        timeline.append({
            "stage": STAGE_4,
            "evidence": f"Psychological artificial deadline: '{m_urg.group(0)}'",
            "detected": True
        })

    # 5. Intercepted (if risk >= 35)
    if risk_score >= 35:
        timeline.append({
            "stage": STAGE_5,
            "evidence": f"Threat intercepted in real time by ScamShield AI (Risk Score: {risk_score}/100)",
            "detected": True
        })

    return timeline
