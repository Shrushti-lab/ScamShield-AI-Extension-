"""
Facebook Marketplace anomaly detection engine.
Price deviation, burner accounts, courier advance-fee traps, off-platform contact.
"""
from __future__ import annotations
import re, time

W_PRICE_SEVERE   = 0.85
W_PRICE_MODERATE = 0.50
W_BURNER         = 0.55
W_COURIER        = 0.70
W_OFF_PLATFORM   = 0.50
W_REFUSAL_MEET   = 0.40

# Category baselines (keyword → approximate average price USD)
CATEGORY_BASELINES = {
    "iphone": 800, "macbook": 1200, "ipad": 600, "airpods": 180,
    "ps5": 450, "playstation": 450, "xbox": 400, "nintendo": 300,
    "laptop": 700, "television": 500, "tv": 500, "camera": 600,
    "bicycle": 350, "bike": 350, "motorcycle": 5000,
    "car": 15000, "truck": 20000, "furniture": 300, "sofa": 600,
    "gpu": 500, "graphics card": 500, "monitor": 300,
    "rolex": 8000, "watch": 200, "ring": 500, "jewelry": 300,
    "sneakers": 150, "shoes": 100, "handbag": 200, "purse": 150,
    "phone": 600, "samsung": 700, "pixel": 500, "oneplus": 400,
}

RE_COURIER = re.compile(
    r"(my\s+(son|daughter|husband|wife|agent|friend)\s+(will|can)\s+(pick|collect|deliver)|"
    r"courier\s+(will|service|fee|charge)|pay\s+(shipping|delivery)\s+fee\s*upfront|"
    r"i.?m\s+(out\s+of\s+town|overseas|military|deployed|abroad|travelling))", re.I
)

RE_OFF_PLATFORM = re.compile(
    r"(contact\s+me\s+on\s+whatsapp|text\s+me\s+on\s+whatsapp|my\s+whatsapp|"
    r"reach\s+me\s+on\s+telegram|email\s+me\s+(at|directly)|"
    r"let.?s\s+(move|continue|talk)\s+(on|via|through)\s+(whatsapp|telegram|hangouts|email))", re.I
)

RE_REFUSAL_MEET = re.compile(
    r"(can.?t\s+meet\s+in\s+person|no\s+meetup|ship\s+only|"
    r"not\s+(available|able)\s+to\s+meet|don.?t\s+do\s+local\s+pickup)", re.I
)

RE_BURNER_SIGNALS = re.compile(
    r"(just\s+joined|new\s+(to\s+)?(facebook|marketplace)|"
    r"joined\s+(last|this)\s+(week|month)|no\s+reviews|"
    r"account\s+(created|made)\s+(recently|\d+\s+days?\s+ago))", re.I
)


def _estimate_baseline(title: str) -> float | None:
    """Return baseline price from keyword matching, prioritizing longest match."""
    title_lower = title.lower()
    for kw in sorted(CATEGORY_BASELINES.keys(), key=len, reverse=True):
        if kw in title_lower:
            return CATEGORY_BASELINES[kw]
    return None


def analyze_listing(
    title: str,
    price: float,
    currency: str = "USD",
    seller_joined: str = "",
    seller_name: str = "",
    description: str = "",
    messages: list[str] = None,
) -> dict:
    start = time.perf_counter()
    messages = messages or []
    combined = f"{title} {description} {' '.join(messages)}"
    scores: list[float] = []
    dna: list[str] = []
    evidence: list[str] = []
    recs: list[str] = []

    def _flag(weight, tag, match_text, rec=""):
        scores.append(weight)
        dna.append(tag)
        evidence.append(match_text[:120])
        if rec:
            recs.append(rec)

    # Price deviation
    baseline = _estimate_baseline(title)
    if baseline and price > 0:
        discount = ((baseline - price) / baseline) * 100
        if discount > 60:
            _flag(W_PRICE_SEVERE, "Price Anomaly",
                  f"{discount:.0f}% below market avg (${price} vs ${baseline})",
                  "Inspect the item in person before paying. Extreme discounts are a common scam tactic.")
        elif discount > 40:
            _flag(W_PRICE_MODERATE, "Price Anomaly",
                  f"{discount:.0f}% below market avg (${price} vs ${baseline})",
                  "Compare prices with other listings. Consider meeting in a public place.")

    # Burner account
    m = RE_BURNER_SIGNALS.search(f"{seller_joined} {combined}")
    if m:
        _flag(W_BURNER, "Burner Account", m.group(),
              "New accounts with no history are more likely to be fraudulent.")

    # Courier pretext
    m = RE_COURIER.search(combined)
    if m:
        _flag(W_COURIER, "Courier Pretext", m.group(),
              "Never pay shipping fees upfront to individual sellers. Inspect in person.")

    # Off-platform
    m = RE_OFF_PLATFORM.search(combined)
    if m:
        _flag(W_OFF_PLATFORM, "Off-Platform Contact", m.group(),
              "Stay on the marketplace platform for buyer protection.")

    # Refusal to meet
    m = RE_REFUSAL_MEET.search(combined)
    if m:
        _flag(W_REFUSAL_MEET, "Refusal to Meet", m.group(),
              "Legitimate sellers are usually willing to meet locally.")

    # Noisy-OR
    if scores:
        risk_prob = 1.0
        for s in scores:
            risk_prob *= (1.0 - s)
        risk_score = min(100, int((1.0 - risk_prob) * 100))
    else:
        risk_score = 0

    verdict = "High Risk" if risk_score >= 70 else ("Proceed Carefully" if risk_score >= 35 else "Safe")
    category = dna[0] if dna else "Marketplace"
    latency = round((time.perf_counter() - start) * 1000, 3)

    explanation = ""
    if risk_score >= 35:
        explanation = f"Listing '{title}' at ${price} triggered {len(dna)} signal(s): {', '.join(dna)}. "
        if recs:
            explanation += recs[0]
    else:
        explanation = f"Listing '{title}' at ${price} appears normal."

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "category": category,
        "platform": "Marketplace",
        "scam_dna": dna,
        "matched_evidence": evidence,
        "recommendations": recs,
        "timeline": [],
        "explanation": explanation,
        "latency_ms": latency,
        "target": title,
        "engine_used": "Marketplace Anomaly Engine v2",
    }
