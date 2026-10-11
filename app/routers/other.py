"""Backward compatible re-export of routers."""
from __future__ import annotations
from app.routers.blocklist import router as blocklist_router
from app.routers.reports import router as reports_router
from app.routers.stats import router as stats_router
from app.routers.settings import router as settings_router
from app.routers.settings import router as heartbeat_router

__all__ = [
    "blocklist_router",
    "reports_router",
    "stats_router",
    "settings_router",
    "heartbeat_router",
]
