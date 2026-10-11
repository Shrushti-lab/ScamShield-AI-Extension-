"""
ScamShield AI — Scam DNA Catalog & Tagging Definitions
Standard taxonomy of 12 primary threat genes.
"""
from __future__ import annotations

# Canonical DNA Tag constants
OTP_EXFILTRATION        = "OTP Exfiltration"
PRICE_ANOMALY           = "Price Anomaly"
COURIER_PRETEXT         = "Courier Pretext"
HIGH_ENTROPY_DOMAIN     = "High Entropy Domain"
PAYMENT_PIVOT           = "Payment Pivot"
URGENCY_PRESSURE        = "Urgency Pressure"
WALLET_DRAINER          = "Wallet Drainer"
SEED_PHRASE_HARVEST     = "Seed Phrase Harvest"
INR_REWARD_LURE         = "INR Reward Lure"
BURNER_ACCOUNT          = "Burner Account"
CREDIT_CARD_HARVESTER   = "Credit Card Harvester"
TYPOSQUAT               = "Typosquat"

ALL_SCAM_DNA = [
    OTP_EXFILTRATION,
    PRICE_ANOMALY,
    COURIER_PRETEXT,
    HIGH_ENTROPY_DOMAIN,
    PAYMENT_PIVOT,
    URGENCY_PRESSURE,
    WALLET_DRAINER,
    SEED_PHRASE_HARVEST,
    INR_REWARD_LURE,
    BURNER_ACCOUNT,
    CREDIT_CARD_HARVESTER,
    TYPOSQUAT,
]

DNA_DESCRIPTIONS = {
    OTP_EXFILTRATION: "Attempts to harvest 2FA/SMS one-time passcodes under pretexts like Google Voice verification or accidental phone number entries.",
    PRICE_ANOMALY: "Severe listing price deviation (>60% below market average) designed to induce FOMO and impetuous purchase.",
    COURIER_PRETEXT: "Excuses avoiding in-person inspection or handoff, requesting advance shipping/courier insurance deposits.",
    HIGH_ENTROPY_DOMAIN: "Algorithmically generated or high-randomness domain names used to evade static reputation blocklists.",
    PAYMENT_PIVOT: "Coercing user off-platform to non-refundable peer-to-peer rails (Zelle, Venmo, CashApp, crypto, UPI).",
    URGENCY_PRESSURE: "Artificial deadlines and psychological intimidation ('account will be disabled in 15 minutes').",
    WALLET_DRAINER: "Malicious smart contracts or phishing sites prompting users to approve unlimited token transfer allowances.",
    SEED_PHRASE_HARVEST: "Direct extraction of 12 or 24-word BIP39 mnemonic recovery phrases or private keys.",
    INR_REWARD_LURE: "Fake UPI lottery, cashback, or KBC prize claims designed to trick users into approving debit requests.",
    BURNER_ACCOUNT: "Accounts created within the last 90 days with zero ratings or activity history used for disposable fraud.",
    CREDIT_CARD_HARVESTER: "Lookalike or unverified checkout forms intercepting credit card PAN, CVV, and expiry fields.",
    TYPOSQUAT: "Misspelled or visually deceptive domain names imitating protected brand entities (e.g., paypa1 vs paypal).",
}
