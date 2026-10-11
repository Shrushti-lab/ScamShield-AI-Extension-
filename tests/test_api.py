"""
ScamShield AI — API & Engine Tests
Run: pytest tests/ -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.engine.conversation import analyze_conversation
from app.engine.marketplace import analyze_listing
from app.engine.url_features import predict_url
from app.engine.cardguard import analyze_payment_form


client = TestClient(app)


# ── Health / Stats ─────────────────────────────────────────
class TestHealth:
    def test_stats(self):
        r = client.get("/api/stats")
        assert r.status_code == 200
        data = r.json()
        assert "items_checked" in data
        assert "warnings" in data
        assert "high_risk" in data
        assert data["status"] == "Active"

    def test_settings(self):
        r = client.get("/api/settings")
        assert r.status_code == 200
        data = r.json()
        assert data["facebook_enabled"] is True

    def test_scans_list(self):
        r = client.get("/api/scans?limit=5")
        assert r.status_code == 200
        data = r.json()
        assert "scans" in data
        assert len(data["scans"]) > 0  # Seed data exists


# ── Conversation Engine ───────────────────────────────────
class TestConversationEngine:
    def test_otp_scam(self):
        result = analyze_conversation(
            platform="Messenger", sender="@scammer",
            messages=["Hey I accidentally typed your number and you got a Google Voice code, can you send it to me?"]
        )
        assert result["risk_score"] >= 70
        assert "OTP Exfiltration" in result["scam_dna"]

    def test_payment_pivot(self):
        result = analyze_conversation(
            platform="Messenger", sender="@seller",
            messages=["Can you send the deposit via Zelle before I hold the item?"]
        )
        assert result["risk_score"] >= 35
        assert "Payment Pivot" in result["scam_dna"]

    def test_crypto_lure(self):
        result = analyze_conversation(
            platform="Telegram", sender="@CryptoBot",
            messages=["Join our VIP signals group! Guaranteed 5% daily ROI on USDT trading!"]
        )
        assert result["risk_score"] >= 35
        assert "Crypto Lure" in result["scam_dna"]

    def test_seed_phrase(self):
        result = analyze_conversation(
            platform="Telegram", sender="@WalletSupport",
            messages=["To validate your wallet, please enter your 12-word recovery seed phrase."]
        )
        assert result["risk_score"] >= 70
        assert "Seed Phrase Harvest" in result["scam_dna"]

    def test_inr_reward(self):
        result = analyze_conversation(
            platform="Telegram", sender="+91-98765",
            messages=["Congratulations! You've won ₹50,000 in the KBC lottery! Claim your reward on GPay."]
        )
        assert result["risk_score"] >= 35
        assert "INR Reward Lure" in result["scam_dna"]

    def test_safe_conversation(self):
        result = analyze_conversation(
            platform="Messenger", sender="@mom",
            messages=["Hey, can you pick up groceries on the way home? We need milk and eggs."]
        )
        assert result["risk_score"] < 35
        assert result["verdict"] == "Safe"

    def test_copyright_phishing(self):
        result = analyze_conversation(
            platform="Messenger", sender="@FBSupport",
            messages=["Your page has been flagged for copyright violation. Facebook team requires you to verify your identity."]
        )
        assert result["risk_score"] >= 35
        assert "Copyright Phishing" in result["scam_dna"]

    def test_video_phishing(self):
        result = analyze_conversation(
            platform="Messenger", sender="@friend",
            messages=["OMG is this you in this video?? I can't believe it!"]
        )
        assert result["risk_score"] >= 35
        assert "Video Phishing" in result["scam_dna"]


# ── Marketplace Engine ────────────────────────────────────
class TestMarketplaceEngine:
    def test_price_anomaly(self):
        result = analyze_listing(
            title="iPhone 15 Pro Max", price=100, currency="USD"
        )
        assert result["risk_score"] >= 50
        assert "Price Anomaly" in result["scam_dna"]

    def test_courier_pretext(self):
        result = analyze_listing(
            title="PS5 Console", price=120, description="",
            messages=["I'm out of town, my agent will deliver via courier. Pay shipping upfront."]
        )
        assert result["risk_score"] >= 35
        assert any("Courier" in d for d in result["scam_dna"])

    def test_off_platform(self):
        result = analyze_listing(
            title="MacBook Pro", price=500, description="",
            messages=["Let's continue on WhatsApp, I don't check Facebook often."]
        )
        assert result["risk_score"] >= 20

    def test_normal_listing(self):
        result = analyze_listing(
            title="Wooden Bookshelf", price=75, description="Solid oak, good condition"
        )
        assert result["risk_score"] < 35
        assert result["verdict"] == "Safe"


# ── URL Engine ────────────────────────────────────────────
class TestURLEngine:
    def test_phishing_url(self):
        result = predict_url("http://paypa1-secure.xyz/login")
        assert result["risk_score"] >= 35
        assert any("Typosquat" in d or "Suspicious TLD" in d for d in result["scam_dna"])

    def test_ip_url(self):
        result = predict_url("http://192.168.1.100/phish/login.php")
        assert "IP Address Host" in result["scam_dna"]

    def test_legit_url(self):
        result = predict_url("https://www.google.com/search?q=python")
        assert result["risk_score"] < 35

    def test_no_https(self):
        result = predict_url("http://example.com")
        assert "No HTTPS" in result["scam_dna"]


# ── CardGuard Engine ──────────────────────────────────────
class TestCardGuard:
    def test_fake_payment(self):
        result = analyze_payment_form("http://paypa1-secure.xyz/checkout",
                                      field_signals=["cc-number", "cc-csc"])
        assert result["risk_score"] >= 35

    def test_legit_stripe(self):
        result = analyze_payment_form("https://checkout.stripe.com/pay/cs_test_abc")
        assert result["risk_score"] < 35


# ── API Endpoints ─────────────────────────────────────────
class TestAPIEndpoints:
    def test_scan_conversation_api(self):
        r = client.post("/api/scan/conversation", json={
            "platform": "Messenger",
            "sender": "@test_scammer",
            "messages": ["Send me the code you just got, I accidentally typed your number"]
        })
        assert r.status_code == 200
        data = r.json()
        assert data["risk_score"] >= 50
        assert data["id"] > 0

    def test_scan_url_api(self):
        r = client.post("/api/scan/url", json={"url": "http://paypa1-secure.xyz/login"})
        assert r.status_code == 200
        data = r.json()
        assert "risk_score" in data

    def test_scan_listing_api(self):
        r = client.post("/api/scan/listing", json={
            "title": "iPhone 15", "price": 50, "currency": "USD"
        })
        assert r.status_code == 200
        data = r.json()
        assert data["risk_score"] >= 35

    def test_scan_payment_api(self):
        r = client.post("/api/scan/payment-form", json={
            "url": "http://fakeshop.xyz/pay", "field_signals": ["cc-number"]
        })
        assert r.status_code == 200

    def test_get_scan_detail(self):
        # First create a scan
        r = client.post("/api/scan/url", json={"url": "https://www.google.com"})
        scan_id = r.json()["id"]
        # Then fetch it
        r2 = client.get(f"/api/scans/{scan_id}")
        assert r2.status_code == 200
        assert r2.json()["id"] == scan_id

    def test_blocklist_crud(self):
        r = client.post("/api/blocklist", json={"handle": "@test_block", "platform": "Test"})
        assert r.status_code == 200

        r = client.get("/api/blocklist")
        assert r.status_code == 200
        handles = [b["handle"] for b in r.json()["blocked_senders"]]
        assert "@test_block" in handles

        r = client.delete("/api/blocklist/@test_block")
        assert r.status_code == 200

    def test_reports_crud(self):
        r = client.post("/api/reports", json={
            "platform": "Telegram", "handle_or_url": "@scambot",
            "category": "Crypto Scam", "note": "Test report"
        })
        assert r.status_code == 200
        assert r.json()["status"] == "submitted"

        r = client.get("/api/reports")
        assert r.status_code == 200

    def test_settings_update(self):
        r = client.put("/api/settings", json={"facebook_enabled": False})
        assert r.status_code == 200
        r = client.get("/api/settings")
        assert r.json()["facebook_enabled"] is False
        # Restore
        client.put("/api/settings", json={"facebook_enabled": True})

    def test_heartbeat(self):
        r = client.post("/api/extension/heartbeat")
        assert r.status_code == 200
        r = client.get("/api/extension/heartbeat")
        assert r.json()["connected"] is True

    def test_portal_serves(self):
        r = client.get("/")
        assert r.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
