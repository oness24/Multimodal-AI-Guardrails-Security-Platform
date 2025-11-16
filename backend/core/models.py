"""
Database models for AdversarialShield.
Uses SQLAlchemy with async support.
"""
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSON, UUID

from backend.core.database import Base


class AttackPattern(Base):
    """Attack pattern template for generating adversarial attacks."""

    __tablename__ = "attack_patterns"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, unique=True, index=True)
    technique = Column(String(100), nullable=False, index=True)
    category = Column(String(100), nullable=False, index=True)
    description = Column(Text)
    template = Column(Text, nullable=False)
    variables = Column(JSON)  # Variables that can be replaced in template
    severity = Column(String(20), default="medium")  # low, medium, high, critical

    # OWASP/MITRE classification
    owasp_category = Column(String(100))
    mitre_atlas_id = Column(String(50))

    # Success metrics
    success_rate = Column(Float, default=0.0)
    total_executions = Column(Integer, default=0)
    successful_executions = Column(Integer, default=0)

    # Metadata
    target_models = Column(JSON)  # List of models this works against
    tags = Column(JSON)  # Additional tags for categorization

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Active status
    is_active = Column(Boolean, default=True)

    def __repr__(self) -> str:
        return f"<AttackPattern(name={self.name}, technique={self.technique})>"


class AttackLog(Base):
    """Log of attack execution and results."""

    __tablename__ = "attack_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Attack details
    pattern_id = Column(UUID(as_uuid=True), index=True)
    technique = Column(String(100), nullable=False, index=True)
    payload = Column(Text, nullable=False)

    # Target information
    target_model = Column(String(100), index=True)
    target_endpoint = Column(String(255))

    # Execution results
    response = Column(Text)
    success = Column(Boolean, default=False, index=True)
    execution_time_ms = Column(Integer)  # Execution time in milliseconds

    # Classification
    attack_type = Column(String(100))  # prompt_injection, jailbreak, etc.
    severity = Column(String(20))

    # Metadata
    metadata = Column(JSON)  # Additional context and data
    user_id = Column(String(100))  # User who executed the attack

    # Error information
    error_message = Column(Text)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def __repr__(self) -> str:
        return f"<AttackLog(technique={self.technique}, success={self.success})>"


class DetectionLog(Base):
    """Log of guardrail detections."""

    __tablename__ = "detection_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Detection details
    input_text = Column(Text, nullable=False)
    detected_technique = Column(String(100), index=True)
    confidence = Column(Float, nullable=False)  # 0.0 to 1.0

    # Detector information
    detector_name = Column(String(100), nullable=False)
    detector_version = Column(String(50))

    # Action taken
    action = Column(String(50))  # blocked, flagged, allowed
    blocked = Column(Boolean, default=False, index=True)

    # Associated attack log (if from testing)
    attack_log_id = Column(UUID(as_uuid=True), index=True)

    # Metadata
    metadata = Column(JSON)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def __repr__(self) -> str:
        return f"<DetectionLog(technique={self.detected_technique}, confidence={self.confidence})>"


class VulnerabilityScan(Base):
    """Record of vulnerability scans."""

    __tablename__ = "vulnerability_scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Scan details
    scan_type = Column(String(50), nullable=False)  # static, dynamic, compliance
    target = Column(String(255), nullable=False)  # Repository URL, endpoint, etc.
    status = Column(String(50), default="pending")  # pending, running, completed, failed

    # Results summary
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    # Detailed results
    findings = Column(JSON)  # Detailed vulnerability findings

    # Risk score
    risk_score = Column(Float, default=0.0)  # 0.0 to 10.0

    # Scan configuration
    config = Column(JSON)

    # Metadata
    user_id = Column(String(100))

    # Timestamps
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<VulnerabilityScan(type={self.scan_type}, status={self.status})>"
