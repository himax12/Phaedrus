"""
SQLAlchemy models for forensic data storage.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""
    pass


class ForensicLog(Base):
    """Parsed forensic log entry."""

    __tablename__ = "forensic_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ingestion_id = Column(String(36), unique=True, nullable=False, index=True)
    arrival_timestamp = Column(DateTime, nullable=False, index=True)

    # Drain3 parsing results
    template_id = Column(Integer, nullable=False, index=True)
    template = Column(Text, nullable=False)
    parameters = Column(JSON, default=list)
    masked_message = Column(Text)

    # Classification
    severity = Column(String(20), default="INFO", index=True)
    log_type = Column(String(50), default="unknown")

    # Source information
    source_host = Column(String(255))
    source_file = Column(String(512))
    raw_message = Column(Text)

    # Extracted entities
    entities = Column(JSON, default=dict)

    # Evidence block reference
    block_id = Column(Integer, ForeignKey("evidence_blocks.block_id"), nullable=True)

    # Relationships
    anomaly_scores = relationship("AnomalyScoreDB", back_populates="log")
    evidence_block = relationship("EvidenceBlockDB", back_populates="logs")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "ingestion_id": self.ingestion_id,
            "arrival_timestamp": self.arrival_timestamp.isoformat() if self.arrival_timestamp else None,
            "template_id": self.template_id,
            "template": self.template,
            "parameters": self.parameters,
            "masked_message": self.masked_message,
            "severity": self.severity,
            "log_type": self.log_type,
            "source_host": self.source_host,
            "source_file": self.source_file,
            "raw_message": self.raw_message,
            "entities": self.entities,
            "block_id": self.block_id,
        }


class EvidenceBlockDB(Base):
    """Evidence block in the logchain."""

    __tablename__ = "evidence_blocks"

    block_id = Column(Integer, primary_key=True)
    merkle_root = Column(String(128), nullable=False)
    prev_block_hash = Column(String(128), nullable=False)
    block_hash = Column(String(128), nullable=False, unique=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    log_count = Column(Integer, nullable=False)
    log_ids = Column(JSON, default=list)

    # Verification status
    verified = Column(Boolean, default=False)
    verification_timestamp = Column(DateTime, nullable=True)

    # Relationships
    logs = relationship("ForensicLog", back_populates="evidence_block")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "block_id": self.block_id,
            "merkle_root": self.merkle_root,
            "prev_block_hash": self.prev_block_hash,
            "block_hash": self.block_hash,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "log_count": self.log_count,
            "log_ids": self.log_ids,
            "verified": self.verified,
            "verification_timestamp": (
                self.verification_timestamp.isoformat()
                if self.verification_timestamp
                else None
            ),
        }


class AnomalyScoreDB(Base):
    """Anomaly detection results."""

    __tablename__ = "anomaly_scores"

    id = Column(Integer, primary_key=True, autoincrement=True)
    log_id = Column(String(36), ForeignKey("forensic_logs.ingestion_id"), nullable=False, index=True)

    # Detection results
    score = Column(Float, nullable=False)
    is_anomaly = Column(Boolean, default=False, index=True)
    detection_method = Column(String(50))
    perplexity = Column(Float, nullable=True)

    # Explainability
    top_features = Column(JSON, default=list)
    explanation = Column(Text)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    log = relationship("ForensicLog", back_populates="anomaly_scores")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "log_id": self.log_id,
            "score": self.score,
            "is_anomaly": self.is_anomaly,
            "detection_method": self.detection_method,
            "perplexity": self.perplexity,
            "top_features": self.top_features,
            "explanation": self.explanation,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AttackPath(Base):
    """Detected attack paths from graph analysis."""

    __tablename__ = "attack_paths"

    id = Column(Integer, primary_key=True, autoincrement=True)
    entry_point = Column(String(255), nullable=False)
    target = Column(String(255), nullable=False)
    risk_score = Column(Float, nullable=False)
    nodes = Column(JSON, default=list)
    edges = Column(JSON, default=list)
    description = Column(Text)
    detected_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "entry_point": self.entry_point,
            "target": self.target,
            "risk_score": self.risk_score,
            "nodes": self.nodes,
            "edges": self.edges,
            "description": self.description,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
        }
