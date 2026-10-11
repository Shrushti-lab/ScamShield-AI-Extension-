"""
ScamShield AI — Synthesizer for 20k+ Labeled URL Dataset
Generates >=20,000 realistic benign and phishing URLs with fixed seed.
Mutations: typosquatting, hyphen stuffing, random-string entropy, punycode, bad TLDs, IP hosts.
"""
from __future__ import annotations
import random
from pathlib import Path
import json

BRANDS = [
    "paypal", "amazon", "facebook", "meta", "telegram", "google", "apple",
    "microsoft", "netflix", "instagram", "whatsapp", "twitter", "linkedin",
    "ebay", "walmart", "target", "bestbuy", "chase", "bankofamerica",
    "wellsfargo", "citibank", "hdfc", "icici", "sbi", "axisbank", "paytm",
    "phonepe", "gpay", "razorpay", "stripe", "coinbase", "binance"
]

BAD_TLDS = [
    ".xyz", ".top", ".buzz", ".click", ".zip", ".tk", ".ml", ".ga", ".cf",
    ".gq", ".work", ".rest", ".fit", ".icu", ".monster", ".uno", ".pw",
    ".bid", ".trade", ".loan", ".racing", ".win", ".download"
]

BENIGN_DOMAINS = [
    "google.com", "amazon.com", "github.com", "wikipedia.org", "microsoft.com",
    "apple.com", "stackoverflow.com", "reddit.com", "nytimes.com", "bbc.co.uk",
    "youtube.com", "linkedin.com", "instagram.com", "cloudflare.com", "notion.so",
    "python.org", "fastapi.tiangolo.com", "mozilla.org", "w3schools.com", "nih.gov",
    "medium.com", "spotify.com", "dropbox.com", "slack.com", "zoom.us",
    "stripe.com", "chase.com", "bankofamerica.com", "walmart.com", "target.com"
]

SUSPICIOUS_PATHS = [
    "/login", "/verify", "/account-update", "/claim", "/auth/checkpoint",
    "/billing/confirm", "/secure/signin", "/wallet/sync", "/airdrop/claim",
    "/otp/validate", "/password-reset", "/security/alert", "/session/resolve"
]

BENIGN_PATHS = [
    "/docs/tutorial", "/article/tech-news-2024", "/search?q=machine-learning",
    "/explore/trending", "/profile/settings", "/about-us", "/pricing/plans",
    "/blog/engineering-principles", "/community/discussions", "/help/getting-started",
    "/products/item-84729", "/wiki/Computer_science", "/download/latest"
]

TYPOSQUAT_SUBS = {
    "o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "e": ["3"], "a": ["4", "@"], "s": ["5"]
}


def _mutate_typosquat(brand: str, rng: random.Random) -> str:
    """Substitutes characters with visual homoglyphs."""
    chars = list(brand)
    indices = [i for i, c in enumerate(chars) if c in TYPOSQUAT_SUBS]
    if indices:
        idx = rng.choice(indices)
        chars[idx] = rng.choice(TYPOSQUAT_SUBS[chars[idx]])
    return "".join(chars)


def generate_phishing_url(rng: random.Random) -> str:
    """Synthesizes an adversarial phishing URL."""
    pattern = rng.randint(0, 5)
    proto = "http://" if rng.random() > 0.3 else "https://"

    if pattern == 0:
        # TypoSquat + bad TLD
        brand = rng.choice(BRANDS)
        typo = _mutate_typosquat(brand, rng)
        tld = rng.choice(BAD_TLDS)
        path = rng.choice(SUSPICIOUS_PATHS)
        return f"{proto}{typo}{tld}{path}"

    elif pattern == 1:
        # Hyphen stuffing (e.g. secure-login-paypal.xyz)
        brand = rng.choice(BRANDS)
        prefix = rng.choice(["secure-login", "verify-account", "auth-portal", "helpdesk", "update-billing"])
        tld = rng.choice(BAD_TLDS)
        path = rng.choice(SUSPICIOUS_PATHS)
        return f"{proto}{prefix}-{brand}{tld}{path}"

    elif pattern == 2:
        # Random high-entropy subdomain
        rand_str = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=10))
        brand = rng.choice(BRANDS)
        tld = rng.choice(BAD_TLDS)
        return f"{proto}{rand_str}.{brand}-security{tld}/checkpoint"

    elif pattern == 3:
        # IP as host
        ip = f"{rng.randint(11, 220)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
        path = rng.choice(SUSPICIOUS_PATHS)
        return f"http://{ip}{path}?client_id={rng.randint(1000, 9999)}"

    elif pattern == 4:
        # Punycode spoofing (xn--)
        rand_suffix = "".join(rng.choices("abcdef0123456789", k=4))
        return f"{proto}xn--{rng.choice(BRANDS)}-{rand_suffix}.com{rng.choice(SUSPICIOUS_PATHS)}"

    else:
        # Deceptive subdomains on free hosting
        brand = rng.choice(BRANDS)
        return f"{proto}{brand}.verify-checkpoint.{rng.choice(['pages.dev', 'vercel.app', 'webflow.io', 'firebaseapp.com'])}{rng.choice(SUSPICIOUS_PATHS)}"


def generate_benign_url(rng: random.Random) -> str:
    """Synthesizes a benign, legitimate web URL."""
    domain = rng.choice(BENIGN_DOMAINS)
    path = rng.choice(BENIGN_PATHS)
    proto = "https://"
    if rng.random() > 0.5:
        param = f"?ref={rng.choice(['home', 'nav', 'footer'])}&id={rng.randint(100, 99999)}"
        return f"{proto}{domain}{path}{param}"
    return f"{proto}{domain}{path}"


def build_dataset(total_count: int = 20000, seed: int = 42) -> tuple[list[str], list[int]]:
    """
    Builds a labeled dataset of (urls, labels) where 1=phishing, 0=benign.
    Default: 10,000 phishing + 10,000 benign = 20,000 total.
    """
    rng = random.Random(seed)
    n_each = total_count // 2

    urls = []
    labels = []

    for _ in range(n_each):
        urls.append(generate_phishing_url(rng))
        labels.append(1)

    for _ in range(n_each):
        urls.append(generate_benign_url(rng))
        labels.append(0)

    # Shuffle synchronously
    combined = list(zip(urls, labels))
    rng.shuffle(combined)
    urls, labels = zip(*combined)

    return list(urls), list(labels)


if __name__ == "__main__":
    urls, labels = build_dataset(total_count=20000, seed=42)
    print(f"Synthesized {len(urls)} URLs ({sum(labels)} phishing, {len(labels) - sum(labels)} benign).")
    artifacts_dir = Path(__file__).resolve().parent / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    out_file = artifacts_dir / "dataset_sample.json"
    with open(out_file, "w") as f:
        json.dump([{"url": u, "label": l} for u, l in zip(urls[:50], labels[:50])], f, indent=2)
    print(f"Sample saved to {out_file}")
