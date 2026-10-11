"""
ScamShield AI — TrustLens Explainable AI (XAI) Engine
Generates human-readable, auditable diagnostic reports explaining model and heuristic verdicts.
"""
from __future__ import annotations
from typing import Any
from app.engine.scam_dna import DNA_DESCRIPTIONS, ALL_SCAM_DNA


def generate_trustlens_explanation(
    target: str,
    platform: str,
    verdict: str,
    risk_score: int,
    scam_dna: list[str],
    matched_evidence: list[str],
    category: str = "",
) -> str:
    """Generates plain-language explainable AI narrative."""
    if risk_score < 35:
        return f"TrustLens verified {platform} content for '{target}'. No malicious signals or deception patterns detected. The transaction/conversation matches benign baseline behavioral criteria."

    signals_str = ", ".join(scam_dna) if scam_dna else category or "Suspicious anomaly"
    severity_term = "critical threat indicators" if risk_score >= 70 else "warning advisories"

    lead = f"TrustLens intercepted {severity_term} ({risk_score}/100) on {platform} target '{target}'. Flagged signals: [{signals_str}]."

    details = []
    for dna in scam_dna:
        if dna in DNA_DESCRIPTIONS:
            details.append(DNA_DESCRIPTIONS[dna])

    detail_str = " ".join(details[:2]) if details else ""
    return f"{lead} {detail_str}".strip()


def build_trustlens_dossier(scan_dict: dict[str, Any]) -> dict[str, Any]:
    """Enhances a scan dict with rich TrustLens explainability metadata."""
    dna = scan_dict.get("scam_dna", [])
    evidence = scan_dict.get("matched_evidence", [])
    score = scan_dict.get("risk_score", 0)
    verdict = scan_dict.get("verdict", "Safe")
    target = scan_dict.get("target", "Target")
    platform = scan_dict.get("platform", "Web")

    explanation = scan_dict.get("explanation")
    if not explanation or "No explanation" in explanation:
        explanation = generate_trustlens_explanation(
            target=target,
            platform=platform,
            verdict=verdict,
            risk_score=score,
            scam_dna=dna,
            matched_evidence=evidence,
            category=scan_dict.get("category", "")
        )

    # DNA definitions breakdown
    dna_breakdown = [
        {"tag": d, "description": DNA_DESCRIPTIONS.get(d, "Behavioral anomaly flag")}
        for d in dna
    ]

    return {
        **scan_dict,
        "explanation": explanation,
        "dna_breakdown": dna_breakdown,
        "xai_version": "TrustLens XAI v2.0",
    }
