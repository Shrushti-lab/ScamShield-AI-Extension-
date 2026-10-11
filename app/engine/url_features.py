"""
URL lexical feature extractor (16-dim) + ML model loader/predictor.
No network requests — pure string analysis.
"""
from __future__ import annotations
import math, re, time, os
from urllib.parse import urlparse
import numpy as np
import joblib

# Protected brands for Levenshtein distance
PROTECTED_BRANDS = [
    "paypal", "amazon", "facebook", "meta", "telegram", "google", "apple",
    "microsoft", "netflix", "instagram", "whatsapp", "twitter", "linkedin",
    "ebay", "walmart", "target", "bestbuy", "chase", "bankofamerica",
    "wellsfargo", "citibank", "hdfc", "icici", "sbi", "axisbank", "paytm",
    "phonepe", "gpay", "razorpay", "stripe", "venmo", "cashapp",
]

HIGH_ABUSE_TLDS = {
    ".xyz", ".top", ".buzz", ".click", ".zip", ".tk", ".ml", ".ga", ".cf",
    ".gq", ".work", ".rest", ".fit", ".icu", ".monster", ".uno", ".pw",
    ".bid", ".trade", ".loan", ".racing", ".win", ".download", ".stream",
    ".party", ".review", ".science", ".date", ".faith", ".accountant",
}

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "wallet", "claim", "confirm", "update",
    "signin", "account", "suspend", "alert", "bank", "password", "prize",
    "winner", "reward", "free", "gift", "urgent", "click", "action",
    "validate", "authenticate", "billing", "refund", "locked",
}


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def extract_features(url: str) -> np.ndarray:
    """Extract 16-dimensional feature vector from a URL string."""
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
    except Exception:
        return np.zeros(16)

    host = parsed.hostname or ""
    path = parsed.path or ""
    full = url

    # 1. URL length
    url_length = len(full)
    # 2. Host length
    host_length = len(host)
    # 3. Path length
    path_length = len(path)
    # 4. Digit count
    digit_count = sum(c.isdigit() for c in full)
    # 5. Digit ratio
    digit_ratio = digit_count / max(len(full), 1)
    # 6. Special char count
    special_count = sum(not c.isalnum() and c not in "./-:_" for c in full)
    # 7. Dot count in host
    dot_count = host.count(".")
    # 8. Hyphen count in host
    hyphen_count = host.count("-")
    # 9. @ presence
    at_present = 1.0 if "@" in full else 0.0
    # 10. IP as host
    ip_host = 1.0 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) else 0.0
    # 11. Subdomain depth
    subdomain_depth = max(0, dot_count - 1)
    # 12. Shannon entropy of domain
    domain_entropy = _shannon_entropy(host)
    # 13. Min Levenshtein to protected brands
    min_lev = min((_levenshtein(host.split(".")[0], b) for b in PROTECTED_BRANDS), default=99)
    # 14. High-abuse TLD
    tld = ""
    if "." in host:
        tld = "." + host.rsplit(".", 1)[-1]
    abuse_tld = 1.0 if tld in HIGH_ABUSE_TLDS else 0.0
    # 15. Punycode / xn-- flag
    punycode = 1.0 if "xn--" in host else 0.0
    # 16. HTTPS flag
    https_flag = 1.0 if parsed.scheme == "https" else 0.0

    return np.array([
        url_length, host_length, path_length, digit_count, digit_ratio,
        special_count, dot_count, hyphen_count, at_present, ip_host,
        subdomain_depth, domain_entropy, min_lev, abuse_tld, punycode,
        https_flag
    ], dtype=np.float64)


FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "digit_count", "digit_ratio",
    "special_count", "dot_count", "hyphen_count", "at_present", "ip_host",
    "subdomain_depth", "domain_entropy", "min_levenshtein", "abuse_tld",
    "punycode", "https_flag",
]


# ── ML Model ──────────────────────────────────────────────────
MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "ml", "artifacts", "gwo_rf_model.joblib")
_model = None


def _load_model():
    global _model
    if _model is None:
        path = os.path.normpath(MODEL_PATH)
        if os.path.exists(path):
            _model = joblib.load(path)
    return _model


def predict_url(url: str) -> dict:
    """Run URL through feature extraction + ML model. Returns scan result dict."""
    start = time.perf_counter()
    features = extract_features(url)
    model = _load_model()

    dna = []
    evidence = []
    recs = []

    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname or ""

    # ML prediction
    ml_score = 0
    if model is not None:
        try:
            prob = model.predict_proba(features.reshape(1, -1))[0]
            ml_score = int(prob[1] * 100) if len(prob) > 1 else 0
        except Exception:
            ml_score = 0

    # Heuristic boosters
    heuristic_flags = 0

    # Levenshtein brand check
    min_lev = features[12]
    if 0 < min_lev <= 2:
        dna.append("Typosquat")
        evidence.append(f"Domain resembles a protected brand (edit distance: {int(min_lev)})")
        recs.append("Verify the URL carefully — it closely resembles a known brand.")
        heuristic_flags += 25

    # High entropy domain
    if features[11] > 4.0:
        dna.append("High Entropy Domain")
        evidence.append(f"Domain entropy: {features[11]:.2f}")
        heuristic_flags += 15

    # Abuse TLD
    if features[13] > 0:
        dna.append("Suspicious TLD")
        tld = "." + host.rsplit(".", 1)[-1] if "." in host else ""
        evidence.append(f"High-abuse TLD: {tld}")
        recs.append("This TLD is frequently associated with phishing.")
        heuristic_flags += 20

    # Punycode
    if features[14] > 0:
        dna.append("Punycode Domain")
        dna.append("Punycode/Homoglyph")
        evidence.append("Domain uses internationalized encoding (xn--)")
        recs.append("Punycode domains can impersonate legitimate sites with lookalike characters.")
        heuristic_flags += 20

    # IP as host
    if features[9] > 0:
        dna.append("IP Address Host")
        evidence.append("URL uses raw IP address instead of domain name")
        heuristic_flags += 15

    # No HTTPS
    if features[15] == 0:
        dna.append("No HTTPS")
        evidence.append("Connection is not encrypted")
        heuristic_flags += 10

    # Suspicious keywords in URL
    url_lower = url.lower()
    matched_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if matched_kw:
        dna.append("Suspicious Keywords")
        evidence.append(f"Keywords: {', '.join(matched_kw[:5])}")
        heuristic_flags += min(20, len(matched_kw) * 5)

    # Combine ML + heuristic
    risk_score = min(100, max(ml_score, heuristic_flags))

    if risk_score >= 70:
        verdict = "High Risk"
    elif risk_score >= 35:
        verdict = "Proceed Carefully"
    else:
        verdict = "Safe"

    if not recs and verdict != "Safe":
        recs.append("Exercise caution with this URL. Verify the domain before entering any information.")

    latency = round((time.perf_counter() - start) * 1000, 3)

    explanation = ""
    if risk_score >= 35:
        explanation = f"URL '{url}' scored {risk_score}/100 with {len(dna)} threat signal(s): {', '.join(dna)}."
    else:
        explanation = f"URL '{url}' appears legitimate. No significant threat signals."

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "category": "Links",
        "platform": "Web",
        "scam_dna": dna,
        "matched_evidence": evidence,
        "recommendations": recs,
        "timeline": [],
        "explanation": explanation,
        "latency_ms": latency,
        "target": url,
        "engine_used": "GWO-RF URL Classifier v2" if model else "Lexical Heuristic Engine",
        "feature_vector": dict(zip(FEATURE_NAMES, features.tolist())),
    }
