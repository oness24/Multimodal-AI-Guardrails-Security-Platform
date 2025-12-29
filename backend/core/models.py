"""
SQLAlchemy models for AdversarialShield.
"""
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from backend.core.database import Base


class AttackPattern(Base):
    """Model for storing attack patterns."""

    __tablename__ = "attack_patterns"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    technique = Column(String(100), nullable=False, index=True)
    category = Column(String(100), nullable=False, index=True)  # OWASP, MITRE, etc.
    pattern_text = Column(Text, nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low
    success_rate = Column(Float, default=0.0)
    target_models = Column(JSONB, default=list)
    mitre_atlas_id = Column(String(50))
    owasp_category = Column(String(100))
    metadata = Column(JSONB, default=dict)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    executions = relationship("AttackExecution", back_populates="pattern")


class AttackExecution(Base):
    """Model for tracking attack execution results."""

    __tablename__ = "attack_executions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    pattern_id = Column(UUID(as_uuid=True), ForeignKey("attack_patterns.id"))
    target_provider = Column(String(100), nullable=False)
    target_model = Column(String(100), nullable=False)
    payload = Column(Text, nullable=False)
    system_prompt = Column(Text)
    response = Column(Text)
    success = Column(Boolean, default=False)
    detection_bypassed = Column(Boolean, default=False)
    confidence_score = Column(Float)
    execution_time_ms = Column(Integer)
    metadata = Column(JSONB, default=dict)
    executed_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    pattern = relationship("AttackPattern", back_populates="executions")


class GuardrailCheck(Base):
    """Model for logging guardrail validation checks."""

    __tablename__ = "guardrail_checks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    mode = Column(String(20), nullable=False)  # input or output
    original_text = Column(Text, nullable=False)
    sanitized_text = Column(Text)
    is_safe = Column(Boolean, nullable=False)
    risk_score = Column(Float, nullable=False)
    threats_detected = Column(JSONB, default=list)
    pii_detected = Column(JSONB, default=list)
    policy_violations = Column(JSONB, default=list)
    processing_time_ms = Column(Integer)
    metadata = Column(JSONB, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)


class ScanResult(Base):
    """Model for storing vulnerability scan results."""

    __tablename__ = "scan_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_type = Column(String(50), nullable=False)  # code or prompt
    language = Column(String(50))
    source_hash = Column(String(64))  # SHA256 of scanned content
    total_issues = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    is_safe = Column(Boolean)
    risk_score = Column(Float)
    vulnerabilities = Column(JSONB, default=list)
    scan_time_ms = Column(Integer)
    metadata = Column(JSONB, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)


class Policy(Base):
    """Model for guardrail policies."""

    __tablename__ = "policies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text)
    policy_type = Column(String(50), nullable=False)  # content, pii, rate_limit, etc.
    severity = Column(String(20), nullable=False)
    is_enabled = Column(Boolean, default=True)
    config = Column(JSONB, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ThreatIntel(Base):
    """Model for threat intelligence data."""

    __tablename__ = "threat_intel"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    threat_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), nullable=False)
    source = Column(String(255))
    description = Column(Text)
    indicators = Column(JSONB, default=list)  # IOCs, patterns, etc.
    mitigations = Column(JSONB, default=list)
    references = Column(JSONB, default=list)
    is_active = Column(Boolean, default=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    metadata = Column(JSONB, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AuditLog(Base):
    """Model for audit logging."""

    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(100), index=True)
    resource_id = Column(String(100))
    action = Column(String(50), nullable=False)
    actor = Column(String(255))
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    details = Column(JSONB, default=dict)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
