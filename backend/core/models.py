"""
Database models for AdversarialShield.
Uses SQLAlchemy with async support.
"""
import uuid
from datetime import datetime, timezone
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
from sqlalchemy.dialects.postgresql import ARRAY, JSON, UUID

from backend.core.database import Base


def utcnow():
    """Get current UTC time with timezone awareness."""
    return datetime.now(timezone.utc)


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
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

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
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)

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
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)

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
    started_at = Column(DateTime, default=utcnow, nullable=False)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<VulnerabilityScan(type={self.scan_type}, status={self.status})>"


class UserDB(Base):
    """User account model for authentication and authorization."""

    __tablename__ = "users"

    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(String(100), nullable=False, unique=True, index=True)

    # Authentication
    email = Column(String(255), nullable=False, unique=True, index=True)
    hashed_password = Column(String(255), nullable=False)

    # Profile
    full_name = Column(String(255))

    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)

    # Permissions
    scopes = Column(ARRAY(String), default=["read", "scan"], nullable=False)

    # Account security
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime)
    password_changed_at = Column(DateTime)

    # Timestamps
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    last_login_at = Column(DateTime)

    def __repr__(self) -> str:
        return f"<UserDB(email={self.email}, is_active={self.is_active})>"


class APIKeyDB(Base):
    """API key model for programmatic access."""

    __tablename__ = "api_keys"

    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key_id = Column(String(100), nullable=False, unique=True, index=True)

    # Key information (hashed for security)
    key_hash = Column(String(255), nullable=False, index=True)
    key_prefix = Column(String(16), nullable=False)  # First 16 chars for display
    name = Column(String(255), nullable=False)

    # Associated user
    user_id = Column(String(100), nullable=False, index=True)

    # Permissions
    scopes = Column(ARRAY(String), default=["read", "scan"], nullable=False)

    # Status
    is_active = Column(Boolean, default=True, nullable=False, index=True)

    # Expiration
    expires_at = Column(DateTime)

    # Usage tracking
    last_used_at = Column(DateTime)
    total_requests = Column(Integer, default=0)

    # Timestamps
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)
    revoked_at = Column(DateTime)

    def __repr__(self) -> str:
        return f"<APIKeyDB(name={self.name}, user_id={self.user_id}, is_active={self.is_active})>"
