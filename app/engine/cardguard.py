"""Card guard / payment form engine. Detects credit card harvester traps."""
from __future__ import annotations
import re, time
from app.engine.url_features import PROTECTED_BRANDS, _levenshtein, HIGH_ABUSE_TLDS
from urllib.parse import urlparse

W_UNVERIFIED_DOMAIN = 0.60
W_BRAND_LOOKALIKE   = 0.85
W_BAD_TLD           = 0.65
W_NO_HTTPS          = 0.55
W_IP_HOST           = 0.85
W_PUNYCODE          = 0.85
W_CARD_FIELDS       = 0.40

CARD_FIELD_SIGNALS = [
    "cc-number", "cc-name", "cc-exp", "cc-csc", "cardnumber",
    "card-number", "cvv", "cvc", "expiry", "card_number",
    "security-code", "exp-date"
]

LEGIT_PAYMENT_PROVIDERS = [
    "stripe.com", "paypal.com", "checkout.stripe.com", "pay.google.com",
    "apple.com", "authorize.net", "braintreepayments.com", "squareup.com",
    "razorpay.com", "adyen.com"
]


def analyze_payment_form(url: str, field_signals: list[str] = None) -> dict:
    start = time.perf_counter()
    field_signals = field_signals or []
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname or ""
    scores = []
    dna = []
    evidence = []
    recs = []

    def _flag(w, tag, ev, rec=""):
        scores.append(w)
        if tag not in dna:
            dna.append(tag)
        evidence.append(ev[:120])
        if rec:
            recs.append(rec)

    # Check verified allowlist
    is_verified_provider = any(host == p or host.endswith("." + p) for p in LEGIT_PAYMENT_PROVIDERS)

    # Card field signals present
    card_fields_found = [f for f in field_signals if any(cf in f.lower() for cf in CARD_FIELD_SIGNALS)]

    if not is_verified_provider and card_fields_found:
        # Check brand lookalike across segments (e.g., paypa1 in paypa1-secure-checkout.xyz)
        host_parts = re.split(r"[-.]", host.lower())
        brand_match_found = False
        for part in host_parts:
            if len(part) < 3:
                continue
            for brand in PROTECTED_BRANDS:
                dist = _levenshtein(part, brand)
                if 0 < dist <= 2:
                    _flag(W_BRAND_LOOKALIKE, "Credit Card Harvester",
                          f"Domain part '{part}' resembles protected brand '{brand}' (distance {dist})",
                          "This site impersonates a trusted brand. Do not enter card details.")
                    brand_match_found = True
                    break
            if brand_match_found:
                break

        # Bad TLD
        tld = "." + host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in HIGH_ABUSE_TLDS:
            _flag(W_BAD_TLD, "Suspicious TLD", f"High-risk TLD on payment page: {tld}")
            _flag(W_BAD_TLD, "Credit Card Harvester", "Unverified TLD hosting checkout form")

        # No HTTPS
        if parsed.scheme != "https":
            _flag(W_NO_HTTPS, "No HTTPS", "Payment page without SSL/TLS encryption",
                  "Never enter card details on a non-HTTPS page.")

        # IP address host
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            _flag(W_IP_HOST, "IP Address Host", f"Payment form hosted on raw IP address: {host}")
            _flag(W_IP_HOST, "Credit Card Harvester", "Credit card form hosted on raw IP address")

        # Punycode / Homoglyph
        if "xn--" in host:
            _flag(W_PUNYCODE, "Punycode Domain", "Internationalized punycode domain on payment page")
            _flag(W_PUNYCODE, "Credit Card Harvester", "Punycode domain requesting payment cards")

        _flag(W_CARD_FIELDS, "Card Input Detected", f"Fields: {', '.join(card_fields_found[:3])}")

    elif is_verified_provider:
        # Verified provider
        recs.append("Verified payment gateway.")

    if scores:
        risk_prob = 1.0
        for s in scores:
            risk_prob *= (1.0 - s)
        risk_score = min(100, int((1.0 - risk_prob) * 100))
    else:
        risk_score = 0

    verdict = "High Risk" if risk_score >= 70 else ("Proceed Carefully" if risk_score >= 35 else "Safe")
    latency = round((time.perf_counter() - start) * 1000, 3)

    explanation = ""
    if risk_score >= 35:
        explanation = f"Payment form at '{url}' triggered {len(dna)} signal(s): {', '.join(dna)}."
    else:
        explanation = f"Payment form at '{url}' appears legitimate."

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "category": "Payments",
        "platform": "Web",
        "scam_dna": dna,
        "matched_evidence": evidence,
        "recommendations": recs,
        "timeline": [],
        "explanation": explanation,
        "latency_ms": latency,
        "target": url,
        "engine_used": "Card Guard Engine v2",
    }
