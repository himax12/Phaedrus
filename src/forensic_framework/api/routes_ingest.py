"""
Log ingestion API routes.
"""

import logging
from datetime import datetime
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..ingestion import DrainParser, RawLogEntry, ParsedLog
from ..storage import get_db, ForensicLog

logger = logging.getLogger("forensic_framework.ingest")

router = APIRouter(prefix="/ingest", tags=["Ingestion"])


class LogBatchRequest(BaseModel):
    """Request to ingest a batch of logs."""

    logs: list[str] = Field(..., description="List of raw log messages")
    source_host: str | None = Field(None, description="Source hostname")
    source_file: str | None = Field(None, description="Source file path")
    log_type: str = Field("unknown", description="Log type (auth, syslog, etc.)")


class LogBatchResponse(BaseModel):
    """Response from batch ingestion."""

    success: bool
    ingested_count: int
    templates_discovered: int
    log_ids: list[str]


class SingleLogRequest(BaseModel):
    """Request to ingest a single log."""

    message: str = Field(..., description="Raw log message")
    timestamp: datetime | None = Field(None, description="Log timestamp")
    source_host: str | None = None
    source_file: str | None = None
    severity: str | None = None
    log_type: str = "unknown"


class SingleLogResponse(BaseModel):
    """Response from single log ingestion."""

    success: bool
    ingestion_id: str
    template_id: int
    template: str
    parameters: list[str]
    entities: dict[str, list[str]]


# Parser instance (shared across requests)
_parser: DrainParser | None = None


def get_parser() -> DrainParser:
    """Get or create shared parser instance."""
    global _parser
    if _parser is None:
        _parser = DrainParser()
    return _parser


@router.post("/single", response_model=SingleLogResponse)
async def ingest_single_log(request: SingleLogRequest) -> SingleLogResponse:
    """
    Ingest a single log entry.

    Parses the log with Drain3 and stores it in the database.
    """
    logger.info(f"📥 Ingesting single log: {request.message[:50]}...")
    
    try:
        parser = get_parser()
        logger.debug("Got parser instance")

        # Create raw log entry
        entry = RawLogEntry(
            ingestion_id=uuid4(),
            source_timestamp=request.timestamp,
            arrival_timestamp=datetime.utcnow(),
            source_host=request.source_host,
            source_file=request.source_file,
            source_type=request.log_type,
            raw_message=request.message,
            severity=request.severity,
        )
        logger.debug(f"Created RawLogEntry with ID: {entry.ingestion_id}")

        # Parse with Drain3
        parsed = parser.parse_entry(entry)
        logger.info(f"✅ Parsed log -> Template ID: {parsed.template_id}, Template: {parsed.template[:50]}...")

        # Store in database
        db = get_db()
        async with db.session() as session:
            log_record = ForensicLog(
                ingestion_id=str(parsed.ingestion_id),
                arrival_timestamp=parsed.arrival_timestamp,
                template_id=parsed.template_id,
                template=parsed.template,
                parameters=parsed.parameters,
                masked_message=parsed.masked_message,
                severity=parsed.severity,
                log_type=parsed.log_type,
                source_host=request.source_host,
                source_file=request.source_file,
                raw_message=request.message,
                entities=parsed.entities,
            )
            session.add(log_record)
        logger.info(f"💾 Stored log in database: {parsed.ingestion_id}")

        return SingleLogResponse(
            success=True,
            ingestion_id=str(parsed.ingestion_id),
            template_id=parsed.template_id,
            template=parsed.template,
            parameters=parsed.parameters,
            entities=parsed.entities,
        )
    except Exception as e:
        logger.error(f"❌ Error ingesting single log: {e}", exc_info=True)
        raise


@router.post("/batch", response_model=LogBatchResponse)
async def ingest_batch(request: LogBatchRequest) -> LogBatchResponse:
    """
    Ingest a batch of log entries.

    Parses all logs with Drain3 and stores them in the database.
    """
    logger.info(f"📥 Batch ingestion started: {len(request.logs)} logs from {request.source_host}")
    
    try:
        parser = get_parser()
        log_ids: list[str] = []
        initial_clusters = len(parser.get_cluster_templates())
        logger.debug(f"Initial cluster count: {initial_clusters}")

        db = get_db()
        async with db.session() as session:
            for i, message in enumerate(request.logs):
                logger.debug(f"Processing log {i+1}/{len(request.logs)}: {message[:50]}...")
                
                entry = RawLogEntry(
                    ingestion_id=uuid4(),
                    arrival_timestamp=datetime.utcnow(),
                    source_host=request.source_host,
                    source_file=request.source_file,
                    source_type=request.log_type,
                    raw_message=message,
                )

                parsed = parser.parse_entry(entry)
                logger.debug(f"  -> Template ID: {parsed.template_id}")

                log_record = ForensicLog(
                    ingestion_id=str(parsed.ingestion_id),
                    arrival_timestamp=parsed.arrival_timestamp,
                    template_id=parsed.template_id,
                    template=parsed.template,
                    parameters=parsed.parameters,
                    masked_message=parsed.masked_message,
                    severity=parsed.severity,
                    log_type=parsed.log_type,
                    source_host=request.source_host,
                    source_file=request.source_file,
                    raw_message=message,
                    entities=parsed.entities,
                )
                session.add(log_record)
                log_ids.append(str(parsed.ingestion_id))

        # Save parser state
        parser.save_state()
        logger.debug("Parser state saved")

        final_clusters = len(parser.get_cluster_templates())
        new_templates = final_clusters - initial_clusters

        logger.info(f"✅ Batch ingestion complete: {len(log_ids)} logs processed, {new_templates} new templates")

        return LogBatchResponse(
            success=True,
            ingested_count=len(log_ids),
            templates_discovered=new_templates,
            log_ids=log_ids,
        )
    except Exception as e:
        logger.error(f"❌ Error in batch ingestion: {e}", exc_info=True)
        raise


@router.get("/templates")
async def get_templates() -> dict[str, Any]:
    """Get all discovered log templates."""
    logger.info("📋 Fetching log templates")
    
    try:
        parser = get_parser()
        templates = parser.get_cluster_templates()
        stats = parser.get_stats()
        
        logger.info(f"✅ Retrieved {len(templates)} templates, {stats.get('total_logs_parsed', 0)} total logs")

        return {
            "templates": templates,
            "stats": stats,
        }
    except Exception as e:
        logger.error(f"❌ Error fetching templates: {e}", exc_info=True)
        raise


@router.post("/save-state")
async def save_parser_state() -> dict[str, str]:
    """Persist the Drain3 parser state."""
    logger.info("💾 Saving parser state")
    
    try:
        parser = get_parser()
        parser.save_state()
        logger.info("✅ Parser state saved successfully")
        return {"status": "saved"}
    except Exception as e:
        logger.error(f"❌ Error saving parser state: {e}", exc_info=True)
        raise

