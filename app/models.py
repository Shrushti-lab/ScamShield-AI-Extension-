"""ScamShield AI – SQLAlchemy Models."""
from __future__ import annotations
from app.db import Base, Scan, BlockedSender, Report, Settings

__all__ = ["Base", "Scan", "BlockedSender", "Report", "Settings"]
