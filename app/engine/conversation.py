"""
Facebook Messenger + Telegram conversation heuristic engine.
Detects OTP theft, payment pivots, urgency pressure, crypto lures, romance/job scams.
"""
from __future__ import annotations
import re, time
from typing import Any

# ── Configurable weights (noisy-OR aggregation) ────────────────
W_OTP_EXPLICIT      = 0.85
W_OTP_PATTERN       = 0.60
W_PAYMENT_PIVOT     = 0.70
W_URGENCY           = 0.55
W_ROMANCE           = 0.45
W_JOB_SCAM          = 0.50
W_COPYRIGHT_PHISH   = 0.65
W_VIDEO_PHISH       = 0.60
W_CRYPTO_LURE       = 0.75
W_SEED_PHRASE       = 0.90
W_INR_REWARD        = 0.70
W_FAKE_ADMIN        = 0.65
W_AIRDROP           = 0.70

# ── Compiled patterns ─────────────────────────────────────────
RE_OTP_REQUEST = re.compile(
    r"((send|share|tell|give|type|enter)\s*.{0,25}(code|otp|verification|6[\s-]?digit)|"
    r"(otp|verification\s*code|6[\s-]?digit)\s*.{0,25}(send|share|tell|give|type)|"
    r"what.{0,10}code\s+(you\s+)?(got|received|just\s+got)|"
    r"i\s+(accidentally|mistakenly)\s+typed\s+your\s+number|"
    r"google\s+voice\s+verif|"
    r"confirm.{0,15}(code|otp)\s+(i\s+)?sent)",
    re.I
)
RE_OTP_DIGIT = re.compile(r"\b\d{6}\b")
RE_OTP_CONTEXT = re.compile(r"(code|otp|verify|confirm|digit|pin)", re.I)

RE_PAYMENT_PIVOT = re.compile(
    r"(zelle|venmo|cashapp|cash\s*app|paypal\s*(friends|f\s*&\s*f|personal)|"
    r"gift\s*card|wire\s*transfer|western\s*union|moneygram|crypto|bitcoin|btc|eth|usdt|"
    r"upi|phonepe|gpay|google\s*pay|paytm|bhim)", re.I
)

RE_URGENCY = re.compile(
    r"(verify\s+within\s+\d+|act\s+now|last\s+warning|account\s+(will\s+be\s+)?(disabled|suspended|blocked)|"
    r"urgent|immediately|right\s+now|hurry|limited\s+time|expires?\s+(in|soon)|don.?t\s+delay)", re.I
)

RE_ROMANCE = re.compile(
    r"(i\s+love\s+you\s+so\s+much|my\s+dear|my\s+darling|send\s+me\s+money|"
    r"stuck\s+(at\s+)?(airport|customs)|need\s+money\s+for\s+(flight|visa|medical)|"
    r"western\s+union|wire\s+me|investment\s+opportunity)", re.I
)

RE_JOB_SCAM = re.compile(
    r"(work\s+from\s+home.{0,30}(earn|make|salary)|easy\s+money|"
    r"daily\s+(income|earning|salary)\s+.{0,10}\d|"
    r"(task|job)\s*(scam|offer).{0,20}(pay|earn|money)|"
    r"like\s+and\s+earn|review\s+task|data\s+entry\s+job.{0,15}\d)", re.I
)

RE_COPYRIGHT_PHISH = re.compile(
    r"(copyright\s+(violation|infringement|strike)|your\s+page\s+(will|has)\s+be(en)?\s+(removed|disabled)|"
    r"facebook\s+(team|support|admin|security)\s+.{0,20}(verify|confirm)|"
    r"meta\s+business\s+suite\s+.{0,20}(violation|appeal))", re.I
)

RE_VIDEO_PHISH = re.compile(
    r"(is\s+this\s+you\s+in\s+(this|the)\s+video|look\s+what\s+i\s+found|"
    r"omg\s+.{0,10}(you|your)\s+.{0,10}video|i\s+can.?t\s+believe\s+.{0,10}video)", re.I
)

# Telegram-specific
RE_CRYPTO_LURE = re.compile(
    r"(double\s+your\s+(crypto|btc|eth)|guaranteed\s+(\d+%\s+)?(daily\s+)?(roi|return|profit)|"
    r"(usdt|crypto)\s+task|pump\s+signals?|vip\s+airdrop|free\s+(token|coin|nft)|"
    r"(100|200|500)x\s+guaranteed|join\s+.{0,25}(signals?|pump)\s+group)", re.I
)

RE_SEED_PHRASE = re.compile(
    r"(enter\s+.{0,10}(seed|recovery)\s+phrase|validate\s+.{0,10}wallet|"
    r"(sync|connect|claim)\s+.{0,10}wallet|private\s+key|"
    r"(12|24)\s*-?\s*word\s*(seed|recovery|mnemonic)|"
    r"wallet[\s-]?connect\s+.{0,10}(verify|validate|claim))", re.I
)

RE_INR_REWARD = re.compile(
    r"(₹\s*\d[\d,]*\s*(reward|won|prize|cashback|pending)|"
    r"rs\.?\s*\d[\d,]*\s*(reward|won|prize|cashback|pending)|"
    r"(kbc|kaun\s+banega)\s+(lottery|winner|prize)|"
    r"(pm|modi)\s+(scheme|yojana)\s+.{0,15}(reward|claim)|"
    r"claim\s+.{0,15}(reward|prize)\s+.{0,10}(upi|gpay|phonepe|paytm)|"
    r"inr\s+\d[\d,]*\s+(reward|won|credit))", re.I
)

RE_FAKE_ADMIN = re.compile(
    r"(telegram\s+(admin|support|team|official)|"
    r"channel\s+verif|verify\s+.{0,10}channel|"
    r"your\s+(account|channel)\s+.{0,15}(restrict|ban|suspend|violat))", re.I
)
from app.engine.crypto import BIP39_SUBSET



def _check_seed_words(text: str) -> int:
    """Return count of consecutive BIP39 words found."""
    words = text.lower().split()
    max_run = 0
    run = 0
    for w in words:
        if w.strip(".,!?;:\"'()") in BIP39_SUBSET:
            run += 1
            max_run = max(max_run, run)
        else:
            run = 0
    return max_run


# ── Trust Timeline stage classifier ───────────────────────────
STAGE_PATTERNS = [
    ("Friendly Opening", re.compile(r"(hey|hi|hello|how\s+are\s+you|nice\s+to\s+meet)", re.I)),
    ("Trust Building", re.compile(r"(trust\s+me|believe\s+me|i\s+promise|don.?t\s+worry|safe|secure|legit)", re.I)),
    ("Information Request", re.compile(r"(send\s+(me|your)|share\s+your|what.?s\s+your|give\s+me\s+your)", re.I)),
    ("Financial Request", re.compile(r"(send\s+money|pay|transfer|invest|deposit|wire|buy\s+(gift\s+card|crypto))", re.I)),
    ("Urgency Pressure", re.compile(r"(hurry|urgent|now|immediately|last\s+chance|expires?\s+soon|quick)", re.I)),
    ("Intercepted", None),  # Always added at end if threat detected
]


def _build_timeline(messages: list[str], is_threat: bool) -> list[dict]:
    """Classify message sequence into Trust Timeline stages."""
    seen = set()
    timeline = []
    for msg in messages:
        for stage_name, pattern in STAGE_PATTERNS:
            if pattern and stage_name not in seen and pattern.search(msg):
                seen.add(stage_name)
                timeline.append({
                    "stage": stage_name,
                    "active": True,
                    "evidence": msg[:80],
                })
    if is_threat:
        timeline.append({"stage": "Intercepted", "active": True, "evidence": "ScamShield blocked this threat."})
    return timeline


def analyze_conversation(
    platform: str,
    sender: str,
    messages: list[str],
    page_url: str = "",
) -> dict:
    """Run conversation through all heuristic engines. Returns unified result dict."""
    start = time.perf_counter()
    combined = " ".join(messages)
    scores: list[float] = []
    dna: list[str] = []
    evidence: list[str] = []
    recs: list[str] = []

    def _flag(weight: float, tag: str, match_text: str, rec: str = ""):
        scores.append(weight)
        dna.append(tag)
        evidence.append(match_text[:120])
        if rec:
            recs.append(rec)

    # OTP / 2FA theft
    m = RE_OTP_REQUEST.search(combined)
    if m:
        _flag(W_OTP_EXPLICIT, "OTP Exfiltration", m.group(),
              "Never share your 6-digit verification code with anyone.")
    elif RE_OTP_DIGIT.search(combined) and RE_OTP_CONTEXT.search(combined):
        _flag(W_OTP_PATTERN, "OTP Exfiltration", "6-digit code near verification context",
              "Never share your 6-digit verification code with anyone.")

    # Payment pivot
    m = RE_PAYMENT_PIVOT.search(combined)
    if m:
        _flag(W_PAYMENT_PIVOT, "Payment Pivot", m.group(),
              "Do not send money via irreversible methods to strangers.")

    # Urgency
    m = RE_URGENCY.search(combined)
    if m:
        _flag(W_URGENCY, "Urgency Pressure", m.group(),
              "Legitimate services never pressure you with urgent deadlines.")

    # Romance / investment
    m = RE_ROMANCE.search(combined)
    if m:
        _flag(W_ROMANCE, "Romance Scam", m.group(),
              "Be cautious of people asking for money online, especially strangers.")

    # Job scam
    m = RE_JOB_SCAM.search(combined)
    if m:
        _flag(W_JOB_SCAM, "Job Scam", m.group(),
              "Legitimate jobs don't ask you to pay upfront or promise unrealistic earnings.")

    # Copyright phishing
    m = RE_COPYRIGHT_PHISH.search(combined)
    if m:
        _flag(W_COPYRIGHT_PHISH, "Copyright Phishing", m.group(),
              "Facebook/Meta never asks you to verify via DMs.")

    # Video phishing
    m = RE_VIDEO_PHISH.search(combined)
    if m:
        _flag(W_VIDEO_PHISH, "Video Phishing", m.group(),
              "Don't click 'is this you in this video' links — they steal credentials.")

    # Crypto lures (primarily Telegram)
    m = RE_CRYPTO_LURE.search(combined)
    if m:
        _flag(W_CRYPTO_LURE, "Crypto Lure", m.group(),
              "No legitimate project guarantees returns. Never invest in 'guaranteed profit' schemes.")

    # Seed phrase / wallet drainer
    m = RE_SEED_PHRASE.search(combined)
    if m:
        _flag(W_SEED_PHRASE, "Seed Phrase Harvest", m.group(),
              "Never enter your seed phrase or private key anywhere. No legitimate service asks for it.")
    elif _check_seed_words(combined) >= 8:
        _flag(W_SEED_PHRASE, "Seed Phrase Harvest", f"{_check_seed_words(combined)} consecutive BIP39 words detected",
              "Never enter your seed phrase or private key anywhere.")

    # INR reward scams
    m = RE_INR_REWARD.search(combined)
    if m:
        _flag(W_INR_REWARD, "INR Reward Lure", m.group(),
              "Government schemes never ask for UPI payment to claim rewards.")

    # Fake admin
    m = RE_FAKE_ADMIN.search(combined)
    if m:
        _flag(W_FAKE_ADMIN, "Fake Admin", m.group(),
              "Platform admins never DM you first. Verify through official channels.")

    # Noisy-OR aggregation
    if scores:
        risk_prob = 1.0
        for s in scores:
            risk_prob *= (1.0 - s)
        risk_score = min(100, int((1.0 - risk_prob) * 100))
    else:
        risk_score = 0

    if risk_score >= 70:
        verdict = "High Risk"
    elif risk_score >= 35:
        verdict = "Proceed Carefully"
    else:
        verdict = "Safe"

    # Category
    if dna:
        category = dna[0]  # Primary threat
    else:
        category = "Conversations"

    timeline = _build_timeline(messages, risk_score >= 35)

    latency = round((time.perf_counter() - start) * 1000, 3)

    explanation = ""
    if risk_score >= 35:
        explanation = f"This conversation from '{sender}' on {platform} triggered {len(dna)} threat signal(s): {', '.join(dna)}. "
        if recs:
            explanation += recs[0]
    else:
        explanation = f"Conversation from '{sender}' on {platform} appears normal. No significant threat signals detected."

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "category": category,
        "platform": platform,
        "scam_dna": dna,
        "matched_evidence": evidence,
        "recommendations": recs,
        "timeline": timeline,
        "explanation": explanation,
        "latency_ms": latency,
        "target": sender or page_url,
        "engine_used": "Conversation Heuristic Engine v2",
    }
