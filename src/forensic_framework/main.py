"""
Forensic Framework - FastAPI Application Entry Point.

AI-powered forensic log investigation framework using Ollama and OSS tools.
"""

import json
import logging
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api import ingest_router, query_router, verify_router, report_router
from .config import get_settings
from .storage import get_db, init_database


# ============================================================================
# JSON LOGGING SETUP FOR BACKEND
# ============================================================================

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields if present
        for key in ["endpoint", "method", "status_code", "duration_ms", 
                    "request", "response", "action", "data", "error",
                    "log_count", "template_id", "ingestion_id"]:
            if hasattr(record, key):
                log_data[key] = getattr(record, key)
            
        return json.dumps(log_data, default=str)


def setup_json_logging():
    """Configure JSON logging for the backend."""
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler with JSON format
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(JSONFormatter())
    root_logger.addHandler(console_handler)
    
    # Set specific loggers
    logging.getLogger("forensic_framework").setLevel(logging.DEBUG)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    
    return logging.getLogger("forensic_framework")


# Initialize JSON logging
logger = setup_json_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    logger.info("🔍 Starting Forensic Framework...")
    print("🔍 Starting Forensic Framework...")

    # Initialize database
    await init_database()
    logger.info("Database initialized successfully")
    print("  ✓ Database initialized")

    # Create data directories
    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Data directories created: {settings.data_dir}")
    print("  ✓ Directories created")

    logger.info("Forensic Framework ready!")
    print("✓ Forensic Framework ready!")
    print(f"  API Docs: http://localhost:8000/docs")

    yield

    # Shutdown
    logger.info("Shutting down Forensic Framework...")
    print("Shutting down Forensic Framework...")
    db = get_db()
    await db.close()
    logger.info("Shutdown complete")
    print("✓ Shutdown complete")


# Create FastAPI app
app = FastAPI(
    title="Forensic Framework",
    description="""
# AI-Powered Forensic Log Investigation Framework

Transform raw logs into structured evidence with:
- 🔍 **Intelligent Parsing**: Drain3-based automatic template extraction
- 🔐 **Forensic Integrity**: Merkle Tree logchain with tamper detection
- 🤖 **AI Correlation**: Anomaly detection and attack path analysis
- 💬 **Natural Language**: Ollama-powered Text-to-SQL queries
- 📊 **Explainability**: SHAP-based AI decision transparency
- 📄 **ISO 27037 Reports**: Court-ready forensic documentation

## Getting Started

1. Ingest logs via `/ingest/single` or `/ingest/batch`
2. Query with natural language via `/query/natural`
3. Verify integrity via `/verify/chain`
4. Generate reports via `/report/generate`

## Requirements

- Ollama running locally with a model (e.g., `ollama pull llama3.2`)
    """,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(ingest_router)
app.include_router(query_router)
app.include_router(verify_router)
app.include_router(report_router)


@app.get("/", tags=["Health"])
async def root():
    """Root endpoint with API information."""
    settings = get_settings()
    return {
        "name": settings.app_name,
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "endpoints": {
            "ingest": "/ingest",
            "query": "/query",
            "verify": "/verify",
            "report": "/report",
        },
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    logger.info("🏥 Health check requested", extra={"action": "health_check"})
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc),
        },
    )


# CLI entry point for running with uvicorn
def main():
    """Run the application with uvicorn."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "forensic_framework.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
    )


if __name__ == "__main__":
    main()
