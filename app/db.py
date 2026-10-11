"""ScamShield AI â€“ Database models and connection."""
from __future__ import annotations
import json, datetime, os
from pathlib import Path
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

DB_PATH = "/tmp/scamshield.db" if os.name != "nt" else "scamshield.db"
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    platform = Column(String(50), default="Web")
    category = Column(String(100), default="General")
    target = Column(String(500), default="")
    primary_text = Column(Text, default="")
    secondary_text = Column(Text, default="")
    verdict = Column(String(30), default="Safe")
    risk_score = Column(Integer, default=0)
    scam_dna = Column(Text, default="[]")          # JSON list
    matched_evidence = Column(Text, default="[]")   # JSON list
    recommendations = Column(Text, default="[]")    # JSON list
    timeline = Column(Text, default="[]")           # JSON list
    explanation = Column(Text, default="")
    latency_ms = Column(Float, default=0.0)
    dom_selector = Column(String(200), default="")
    endpoint = Column(String(100), default="")
    engine_used = Column(String(100), default="")
    scan_hash = Column(String(64), default="")
    seeded = Column(Boolean, default=False)


class BlockedSender(Base):
    __tablename__ = "blocked_senders"
    id = Column(Integer, primary_key=True, index=True)
    handle = Column(String(200), unique=True, index=True)
    platform = Column(String(50), default="General")
    blocked_at = Column(DateTime, default=datetime.datetime.utcnow)


class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    platform = Column(String(50), default="Web")
    handle_or_url = Column(String(500), default="")
    category = Column(String(100), default="")
    note = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class Settings(Base):
    __tablename__ = "settings"
    id = Column(Integer, primary_key=True)
    chime_enabled = Column(Boolean, default=True)
    hud_enabled = Column(Boolean, default=True)
    facebook_enabled = Column(Boolean, default=True)
    telegram_enabled = Column(Boolean, default=True)
    web_enabled = Column(Boolean, default=True)
    cardguard_enabled = Column(Boolean, default=True)


def seed_demo_scans(force: bool = False):
    """Seed ~35 realistic scans into the database from seed_scans.json."""
    db = SessionLocal()
    try:
        count = db.query(Scan).count()
        if count > 0 and not force:
            return
        if force:
            db.query(Scan).delete()
            db.commit()

        seed_file = Path(__file__).resolve().parent / "data" / "seed_scans.json"
        if not seed_file.exists():
            return

        with open(seed_file, "r", encoding="utf-8") as f:
            seed_items = json.load(f)

        base_time = datetime.datetime.utcnow()
        for i, s in enumerate(seed_items):
            scan_time = base_time - datetime.timedelta(minutes=max(1, (len(seed_items) - i) * 12))
            scan = Scan(
                timestamp=scan_time,
                platform=s.get("platform", "Web"),
                category=s.get("category", "General"),
                target=s.get("target", ""),
                primary_text=s.get("primary_text", ""),
                secondary_text=s.get("secondary_text", ""),
                verdict=s.get("verdict", "Safe"),
                risk_score=s.get("risk_score", 0),
                scam_dna=json.dumps(s.get("scam_dna", [])),
                matched_evidence=json.dumps(s.get("matched_evidence", [])),
                recommendations=json.dumps(s.get("recommendations", [])),
                timeline=json.dumps(s.get("timeline", [])),
                explanation=s.get("explanation", ""),
                latency_ms=round(0.04 + (i % 5) * 0.02, 2),
                dom_selector=s.get("dom_selector", ""),
                endpoint=s.get("endpoint", "/api/scan/conversation"),
                engine_used=s.get("engine_used", "ScamShield Heuristic"),
                scan_hash=f"seed_hash_{i}",
                seeded=True,
            )
            db.add(scan)
        db.commit()
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(Settings).first() is None:
            db.add(Settings(id=1))
            db.commit()
    finally:
        db.close()
    seed_demo_scans(force=False)


# Auto-initialize DB schema on load
init_db()

