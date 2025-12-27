"""API routes module."""

from .routes_ingest import router as ingest_router
from .routes_query import router as query_router
from .routes_verify import router as verify_router
from .routes_report import router as report_router

__all__ = ["ingest_router", "query_router", "verify_router", "report_router"]
