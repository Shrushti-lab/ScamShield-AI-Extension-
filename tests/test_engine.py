"""
ScamShield AI — Comprehensive Engine Test Suite (60+ Test Cases)
Covers:
- Facebook Messenger heuristics (OTP, Payment Pivot, Urgency, Copyright, Video Phishing, Romance, Job Scams)
- False-positive resistance on benign messages
- Facebook Marketplace heuristics (Price anomalies >60%, Burner accounts, Courier traps, Off-platform pivots)
- Telegram Web heuristics (Crypto lures, Guaranteed ROI, Wallet drainers, BIP39 seed phrase harvesting, INR/UPI rewards, Hinglish)
- CardGuard Form Defense & Strict Zero-Access Proof (verifying .value is never accessed)
- URL 16-dim Lexical Extractor & ML Model Predictor
"""
import sys, os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest
from app.engine.conversation import analyze_conversation
from app.engine.marketplace import analyze_listing
from app.engine.url_features import extract_features, predict_url
from app.engine.crypto import analyze_telegram_threats, detect_consecutive_seed_words
from app.engine.cardguard import analyze_payment_form
from app.engine.scam_dna import ALL_SCAM_DNA
from app.engine.timeline import extract_trust_timeline


# ═════════════════════════════════════════════════════════════════
# 1. FACEBOOK MESSENGER HEURISTICS (Tests 1-15)
# ═════════════════════════════════════════════════════════════════
class TestFacebookMessengerEngine:

    def test_01_otp_google_voice_pretext(self):
        res = analyze_conversation("Messenger", "@scam1", [
            "Hey I accidentally typed your number and you got a Google Voice code, can you send it to me real quick?"
        ])
        assert res["risk_score"] >= 70
        assert "OTP Exfiltration" in res["scam_dna"]

    def test_02_otp_explicit_6_digit_request(self):
        res = analyze_conversation("Messenger", "@scam2", [
            "Please send the 6-digit code you just received on your phone to confirm your account."
        ])
        assert res["risk_score"] >= 70
        assert "OTP Exfiltration" in res["scam_dna"]

    def test_03_otp_generic_share_code(self):
        res = analyze_conversation("Messenger", "@scam3", [
            "What code you received? Share the code with me."
        ])
        assert res["risk_score"] >= 70
        assert "OTP Exfiltration" in res["scam_dna"]

    def test_04_payment_pivot_zelle(self):
        res = analyze_conversation("Messenger", "@scam4", [
            "Can you send the $100 deposit via Zelle before I hold the item?"
        ])
        assert res["risk_score"] >= 35
        assert "Payment Pivot" in res["scam_dna"]

    def test_05_payment_pivot_venmo_cashapp(self):
        res = analyze_conversation("Messenger", "@scam5", [
            "I only take CashApp or Venmo friends and family. Send the money there."
        ])
        assert res["risk_score"] >= 35
        assert "Payment Pivot" in res["scam_dna"]

    def test_06_payment_pivot_gift_card(self):
        res = analyze_conversation("Messenger", "@scam6", [
            "You must pay using an Apple or Amazon gift card to complete the order."
        ])
        assert res["risk_score"] >= 35
        assert "Payment Pivot" in res["scam_dna"]

    def test_07_urgency_pressure_15_mins(self):
        res = analyze_conversation("Messenger", "@scam7", [
            "You must verify within 15 minutes or your account will be disabled permanently!"
        ])
        assert res["risk_score"] >= 35
        assert "Urgency Pressure" in res["scam_dna"]

    def test_08_urgency_pressure_last_warning(self):
        res = analyze_conversation("Messenger", "@scam8", [
            "Last warning: Act now immediately or your access will be blocked right now."
        ])
        assert res["risk_score"] >= 35
        assert "Urgency Pressure" in res["scam_dna"]

    def test_09_copyright_violation_phishing(self):
        res = analyze_conversation("Messenger", "@MetaDesk", [
            "Your page has been flagged for copyright violation. Facebook team requires you to confirm your identity."
        ])
        assert res["risk_score"] >= 35
        assert "Copyright Phishing" in res["scam_dna"]

    def test_10_meta_business_suite_appeal(self):
        res = analyze_conversation("Messenger", "@MetaNotice", [
            "Meta Business Suite policy violation detected. Submit appeal or page will be removed."
        ])
        assert res["risk_score"] >= 35
        assert "Copyright Phishing" in res["scam_dna"]

    def test_11_video_phishing_link(self):
        res = analyze_conversation("Messenger", "@friend_compromised", [
            "OMG is this you in this video?? I can't believe this!"
        ])
        assert res["risk_score"] >= 35
        assert "Video Phishing" in res["scam_dna"]

    def test_12_video_phishing_look_what_i_found(self):
        res = analyze_conversation("Messenger", "@user12", [
            "Look what I found, is that your video on this page?"
        ])
        assert res["risk_score"] >= 35
        assert "Video Phishing" in res["scam_dna"]

    def test_13_romance_grooming_wire(self):
        res = analyze_conversation("Messenger", "@romance1", [
            "My dear I love you so much, but I am stuck at customs and need money for flight. Please wire me funds."
        ])
        assert res["risk_score"] >= 35
        assert "Romance Scam" in res["scam_dna"]

    def test_14_job_scam_task_earn(self):
        res = analyze_conversation("Messenger", "@recruiter", [
            "Work from home and earn daily income $500! Simple like and earn task with daily salary."
        ])
        assert res["risk_score"] >= 35
        assert "Job Scam" in res["scam_dna"]

    def test_15_compound_multi_threat(self):
        res = analyze_conversation("Messenger", "@multi", [
            "Urgent: Send me the 6-digit code right now or account will be suspended, then send Zelle fee."
        ])
        assert res["risk_score"] >= 80
        assert res["verdict"] == "High Risk"
        assert "OTP Exfiltration" in res["scam_dna"]
        assert "Payment Pivot" in res["scam_dna"]


# ═════════════════════════════════════════════════════════════════
# 2. FALSE POSITIVE RESISTANCE ON BENIGN CHATS (Tests 16-23)
# ═════════════════════════════════════════════════════════════════
class TestBenignConversationFalsePositives:

    def test_16_benign_verification_email_arrived(self):
        # Critical test requirement: "my verification email arrived"
        res = analyze_conversation("Messenger", "@colleague", [
            "My verification email arrived finally! I was able to log in."
        ])
        assert res["risk_score"] < 35
        assert res["verdict"] == "Safe"

    def test_17_benign_cash_tomorrow(self):
        # Critical test requirement: "I'll pay with cash tomorrow"
        res = analyze_conversation("Messenger", "@buyer", [
            "I'll pay with cash tomorrow when we meet at the library."
        ])
        assert res["risk_score"] < 35
        assert res["verdict"] == "Safe"

    def test_18_benign_grocery_errand(self):
        res = analyze_conversation("Messenger", "@mom", [
            "Can you pick up milk, bread, and eggs on your way home?"
        ])
        assert res["risk_score"] < 35
        assert res["verdict"] == "Safe"

    def test_19_benign_work_project_sync(self):
        res = analyze_conversation("Messenger", "@pm", [
            "Let's review the sprint presentation at 3pm. The slides are uploaded to Google Drive."
        ])
        assert res["risk_score"] < 35
        assert res["verdict"] == "Safe"

    def test_20_benign_recipe_sharing(self):
        res = analyze_conversation("Messenger", "@chef", [
            "Here is the recipe: 2 cups flour, 1 egg, baking powder, and vanilla extract."
        ])
        assert res["risk_score"] < 35
        assert res["verdict"] == "Safe"

    def test_21_benign_homework_query(self):
        res = analyze_conversation("Messenger", "@student", [
            "Did you solve problem 4 from chapter 2? The calculus formulas are tricky."
        ])
        assert res["risk_score"] < 35
        assert res["verdict"] == "Safe"

    def test_22_benign_sports_coordination(self):
        res = analyze_conversation("Messenger", "@coach", [
            "Basketball practice is on field 3 at 9 AM Saturday morning."
        ])
        assert res["risk_score"] < 35
        assert res["verdict"] == "Safe"

    def test_23_benign_birthday_gathering(self):
        res = analyze_conversation("Messenger", "@sister", [
            "Grandma's birthday dinner is reserved for 7 PM. I brought the balloons."
        ])
        assert res["risk_score"] < 35
        assert res["verdict"] == "Safe"


# ═════════════════════════════════════════════════════════════════
# 3. FACEBOOK MARKETPLACE ANOMALY ENGINE (Tests 24-34)
# ═════════════════════════════════════════════════════════════════
class TestMarketplaceAnomalyEngine:

    def test_24_severe_price_anomaly_iphone(self):
        # Baseline iPhone ~$800; price $100 -> 87.5% discount (>60% severe alert)
        res = analyze_listing(title="iPhone 15 Pro Max", price=100)
        assert res["risk_score"] >= 70
        assert "Price Anomaly" in res["scam_dna"]
        assert res["verdict"] == "High Risk"

    def test_25_severe_price_anomaly_macbook(self):
        # Baseline MacBook ~$1200; price $200 -> >80% discount
        res = analyze_listing(title="Apple MacBook Pro M3", price=200)
        assert res["risk_score"] >= 70
        assert "Price Anomaly" in res["scam_dna"]

    def test_26_moderate_price_anomaly_ps5(self):
        # Baseline PS5 ~$450; price $250 -> ~44% discount (40-60% warning)
        res = analyze_listing(title="PS5 Digital Console", price=250)
        assert res["risk_score"] >= 35
        assert "Price Anomaly" in res["scam_dna"]

    def test_27_courier_advance_fee_husband(self):
        res = analyze_listing(
            title="PlayStation 5", price=200,
            messages=["My husband will pick up with courier, pay shipping fee upfront."]
        )
        assert res["risk_score"] >= 65
        assert "Courier Pretext" in res["scam_dna"]

    def test_28_courier_advance_fee_agent(self):
        res = analyze_listing(
            title="Nintendo Switch", price=150,
            messages=["I'm out of town right now, my agent will deliver via courier service."]
        )
        assert res["risk_score"] >= 35
        assert "Courier Pretext" in res["scam_dna"]

    def test_29_burner_account_profiling(self):
        res = analyze_listing(
            title="iPad Pro", price=300,
            seller_joined="Account created recently, joined this month with no reviews"
        )
        assert res["risk_score"] >= 35
        assert "Burner Account" in res["scam_dna"]

    def test_30_off_platform_whatsapp_pivot(self):
        res = analyze_listing(
            title="Gaming Monitor", price=200,
            messages=["Contact me on WhatsApp: +123456789, I don't use Facebook."]
        )
        assert res["risk_score"] >= 35
        assert "Off-Platform Contact" in res["scam_dna"]

    def test_31_refusal_to_meet_locally(self):
        res = analyze_listing(
            title="Drone 4K", price=250,
            messages=["Can't meet in person, ship only. Wire money first."]
        )
        assert res["risk_score"] >= 35

    def test_32_normal_listing_bookshelf(self):
        res = analyze_listing(title="Wooden Bookshelf", price=75, description="Solid oak, local pickup")
        assert res["risk_score"] < 35
        assert res["verdict"] == "Safe"

    def test_33_normal_listing_bicycle(self):
        res = analyze_listing(title="Used Mountain Bicycle", price=220, description="Can meet at central park")
        assert res["risk_score"] < 35
        assert res["verdict"] == "Safe"

    def test_34_normal_listing_acoustic_guitar(self):
        res = analyze_listing(title="Yamaha Acoustic Guitar", price=140, description="Cash upon in-person test")
        assert res["risk_score"] < 35
        assert res["verdict"] == "Safe"


# ═════════════════════════════════════════════════════════════════
# 4. TELEGRAM WEB ENGINE & CRYPTO DEFENSE (Tests 35-47)
# ═════════════════════════════════════════════════════════════════
class TestTelegramSecurityEngine:

    def test_35_crypto_guaranteed_roi(self):
        res = analyze_conversation("Telegram", "@CryptoVIP", [
            "Join our VIP signals channel! Guaranteed 5% daily ROI on USDT trading bot."
        ])
        assert res["risk_score"] >= 35
        assert "Crypto Lure" in res["scam_dna"]

    def test_36_crypto_double_your_btc(self):
        res = analyze_conversation("Telegram", "@ElonGiveaway", [
            "Double your crypto! Send 0.1 BTC and get 0.2 BTC back immediately."
        ])
        assert res["risk_score"] >= 35
        assert "Crypto Lure" in res["scam_dna"]

    def test_37_crypto_usdt_task_fraud(self):
        res = analyze_conversation("Telegram", "@TaskBot", [
            "USDT task scam: Like and earn daily task, complete 5 tasks to claim crypto."
        ])
        assert res["risk_score"] >= 35
        assert "Crypto Lure" in res["scam_dna"]

    def test_38_wallet_drainer_seed_phrase_explicit(self):
        res = analyze_conversation("Telegram", "@WalletConnectAdmin", [
            "To validate your wallet and claim the airdrop, please enter your 12-word recovery seed phrase."
        ])
        assert res["risk_score"] >= 70
        assert "Seed Phrase Harvest" in res["scam_dna"]
        assert res["verdict"] == "High Risk"

    def test_39_wallet_drainer_private_key(self):
        res = analyze_conversation("Telegram", "@MetaMaskSupport", [
            "Please sync your wallet by submitting your private key to our support desk."
        ])
        assert res["risk_score"] >= 70
        assert "Seed Phrase Harvest" in res["scam_dna"]

    def test_40_bip39_consecutive_wordlist_detection(self):
        # 10 consecutive BIP39 words
        seed_sample = "abandon ability able about above absent absorb abstract abuse access"
        assert detect_consecutive_seed_words(seed_sample, min_words=8) is True

    def test_41_bip39_consecutive_wordlist_in_conversation(self):
        seed_msg = "My phrase was: apple banana beach beauty beef begin behind believe below bench"
        res = analyze_conversation("Telegram", "@drainer", [seed_msg])
        assert res["risk_score"] >= 70
        assert "Seed Phrase Harvest" in res["scam_dna"]

    def test_42_inr_kbc_lottery_lure(self):
        res = analyze_conversation("Telegram", "+919876543210", [
            "Congratulations! You have won ₹50,000 in the KBC lottery! Claim your prize on GPay now."
        ])
        assert res["risk_score"] >= 35
        assert "INR Reward Lure" in res["scam_dna"]

    def test_43_inr_upi_cashback_lure(self):
        res = analyze_conversation("Telegram", "@PrizeBot", [
            "Rs. 25,000 cashback pending! Claim your reward on PhonePe UPI."
        ])
        assert res["risk_score"] >= 35
        assert "INR Reward Lure" in res["scam_dna"]

    def test_44_inr_hinglish_scheme_lure(self):
        res = analyze_conversation("Telegram", "+918888888888", [
            "Pradhan mantri yojana ke tahat ₹100,000 reward won! Claim reward on UPI."
        ])
        assert res["risk_score"] >= 35
        assert "INR Reward Lure" in res["scam_dna"]

    def test_45_fake_telegram_admin_impersonation(self):
        res = analyze_conversation("Telegram", "@Telegram_Security_Desk", [
            "Telegram Admin Alert: Your channel verification is required or account will be suspended."
        ])
        assert res["risk_score"] >= 35
        assert "Fake Admin" in res["scam_dna"]

    def test_46_telegram_benign_study_notes(self):
        res = analyze_conversation("Telegram", "@study_buddies", [
            "Can someone share the physics notes from lecture 3? I missed the wave motion topic."
        ])
        assert res["risk_score"] < 35
        assert res["verdict"] == "Safe"

    def test_47_telegram_benign_code_review(self):
        res = analyze_conversation("Telegram", "@dev_chat", [
            "I pushed a pull request for the database migration. Can you review when you have time?"
        ])
        assert res["risk_score"] < 35
        assert res["verdict"] == "Safe"


# ═════════════════════════════════════════════════════════════════
# 5. CARDGUARD PRIVACY & HARVESTER DEFENSE (Tests 48-52)
# ═════════════════════════════════════════════════════════════════
class TestCardGuardAndZeroAccess:

    def test_48_cardguard_flags_lookalike_checkout(self):
        res = analyze_payment_form(
            url="http://paypa1-secure-checkout.xyz/billing",
            field_signals=["cardnumber", "cvv", "exp-date"]
        )
        assert res["risk_score"] >= 70
        assert res["verdict"] == "High Risk"
        assert "Credit Card Harvester" in res["scam_dna"]

    def test_49_cardguard_safe_on_stripe(self):
        res = analyze_payment_form(
            url="https://checkout.stripe.com/pay/cs_live_123",
            field_signals=["cardnumber", "cvv"]
        )
        assert res["risk_score"] < 35
        assert res["verdict"] == "Safe"

    def test_50_zero_access_proof_never_reads_value_attribute(self):
        """
        AUTOMATED PROOF: Verify that CardGuard engine schemas and code
        strictly inspect only attribute names (field_signals) and NEVER accept,
        parse, or expose input `.value` or credit card digits.
        """
        import inspect
        from app.engine import cardguard
        from app.schemas import PaymentFormScanReq

        # 1. Inspect Pydantic schema
        schema_fields = PaymentFormScanReq.model_fields.keys()
        assert "value" not in schema_fields
        assert "card_number" not in schema_fields
        assert "cvv_val" not in schema_fields
        assert "field_signals" in schema_fields

        # 2. Inspect analyze_payment_form signature
        sig = inspect.signature(cardguard.analyze_payment_form)
        param_names = list(sig.parameters.keys())
        assert "card_number" not in param_names
        assert "card_value" not in param_names

        # 3. Content script source code verification
        cg_path = ROOT / "extension" / "content" / "cardguard.js"
        source = cg_path.read_text(encoding="utf-8")
        assert ".value" not in source, "Violation of Zero-Access Policy: .value accessed in cardguard.js!"

    def test_51_cardguard_flags_punycode_host(self):
        res = analyze_payment_form(
            url="http://xn--amazn-pqa.xyz/checkout",
            field_signals=["cc-number", "cc-csc"]
        )
        assert res["risk_score"] >= 70
        assert "Credit Card Harvester" in res["scam_dna"]

    def test_52_cardguard_flags_ip_address_checkout(self):
        res = analyze_payment_form(
            url="http://192.168.1.55/shop/pay.php",
            field_signals=["card_number", "cvv"]
        )
        assert res["risk_score"] >= 70
        assert "Credit Card Harvester" in res["scam_dna"]


# ═════════════════════════════════════════════════════════════════
# 6. URL 16-DIM LEXICAL EXTRACTOR & ML (Tests 53-62)
# ═════════════════════════════════════════════════════════════════
class TestURLLexicalAndML:

    def test_53_feature_vector_dimension(self):
        feats = extract_features("https://www.google.com/search?q=test")
        assert len(feats) == 16

    def test_54_typosquat_paypal_xyz(self):
        res = predict_url("http://paypa1-secure.xyz/login")
        assert res["risk_score"] >= 35
        assert any("Typosquat" in d or "Suspicious TLD" in d for d in res["scam_dna"])

    def test_55_ip_as_host_flag(self):
        res = predict_url("http://192.168.1.100/phish/login.php")
        assert "IP Address Host" in res["scam_dna"]

    def test_56_punycode_homoglyph_flag(self):
        res = predict_url("http://xn--apple-verify-9ka.com/auth")
        assert "Punycode/Homoglyph" in res["scam_dna"]

    def test_57_high_entropy_domain(self):
        res = predict_url("http://x7q9w2z8p4m1.top/checkpoint")
        assert res["risk_score"] >= 35

    def test_58_legit_google_url(self):
        res = predict_url("https://www.google.com/search?q=python")
        assert res["risk_score"] < 35
        assert res["verdict"] == "Safe"

    def test_59_legit_github_url(self):
        res = predict_url("https://github.com/fastapi/fastapi")
        assert res["risk_score"] < 35
        assert res["verdict"] == "Safe"

    def test_60_legit_amazon_url(self):
        res = predict_url("https://www.amazon.com/dp/B09V3KXJPB")
        assert res["risk_score"] < 35
        assert res["verdict"] == "Safe"

    def test_61_timeline_stepper_stages(self):
        msgs = [
            "Hey buddy!",
            "I mistakenly typed your number.",
            "Can you send the 6-digit code?",
            "Please act fast, do it right now!"
        ]
        tl = extract_trust_timeline(msgs, risk_score=85)
        stages = [step["stage"] for step in tl]
        assert "Friendly Opening" in stages
        assert "Financial Request" in stages
        assert "Urgency Pressure" in stages
        assert "Intercepted" in stages

    def test_62_canonical_scam_dna_taxonomy_coverage(self):
        assert len(ALL_SCAM_DNA) == 12
        assert "OTP Exfiltration" in ALL_SCAM_DNA
        assert "Price Anomaly" in ALL_SCAM_DNA
        assert "Courier Pretext" in ALL_SCAM_DNA
        assert "Seed Phrase Harvest" in ALL_SCAM_DNA
        assert "Credit Card Harvester" in ALL_SCAM_DNA
