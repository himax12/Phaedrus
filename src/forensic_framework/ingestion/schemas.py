"""
Pydantic schemas for log entries.
"""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class RawLogEntry(BaseModel):
    """Raw log entry with metadata envelope."""

    # Metadata Envelope
    ingestion_id: UUID = Field(default_factory=uuid4, description="UUID for tracking")
    source_timestamp: datetime | None = Field(
        default=None, description="When the log was created (local time)"
    )
    arrival_timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="When it reached the collector (UTC)"
    )

    # Source information
    source_host: str | None = None
    source_file: str | None = None
    source_type: str = "unknown"  # e.g., "syslog", "auth", "application"

    # Raw content
    raw_message: str
    severity: str | None = None  # e.g., "INFO", "WARNING", "ERROR", "CRITICAL"

    # Optional structured fields
    extra_fields: dict[str, Any] = Field(default_factory=dict)


class ParsedLog(BaseModel):
    """Log entry after Drain3 parsing."""

    # Original entry reference
    ingestion_id: UUID
    arrival_timestamp: datetime

    # Drain3 results
    template_id: int = Field(description="Cluster ID from Drain3")
    template: str = Field(description="Log template with <*> placeholders")
    parameters: list[str] = Field(
        default_factory=list, description="Extracted variable values"
    )

    # Preprocessed data
    masked_message: str = Field(description="Message after variable masking")

    # Classification
    severity: str = "INFO"
    log_type: str = "unknown"

    # Extracted entities (from preprocessing)
    entities: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Extracted entities like IPs, users, paths",
    )


class EvidenceBlock(BaseModel):
    """A batch of logs with Merkle Tree integrity."""

    block_id: int
    merkle_root: str
    prev_block_hash: str
    timestamp: datetime
    log_count: int
    log_ids: list[UUID]

    # Verification status
    verified: bool = False
    verification_timestamp: datetime | None = None


class AnomalyScore(BaseModel):
    """AI-generated anomaly assessment."""

    log_id: UUID
    score: float = Field(ge=0.0, le=1.0, description="Anomaly score 0-1")
    perplexity: float | None = Field(
        default=None, description="LogBERT perplexity score"
    )
    is_anomaly: bool = False
    detection_method: str = "unknown"

    # Explainability
    top_features: list[dict[str, float]] = Field(
        default_factory=list,
        description="SHAP feature importances",
    )
    explanation: str | None = None
