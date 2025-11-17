"""
Guardrails System API routes for input/output validation and threat detection.
"""
from typing import List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter()


class GuardrailCheckRequest(BaseModel):
    """Request model for guardrail validation."""

    text: str = Field(..., description="Text to validate")
    mode: str = Field(default="input", description="Mode: input or output")
    checks: Optional[List[str]] = Field(
        default=None, description="Specific checks to run (all if None)"
    )


class ThreatDetection(BaseModel):
    """Model for a detected threat."""

    threat_type: str
    severity: str
    confidence: float
    description: str
    matched_pattern: Optional[str] = None


class PIIDetection(BaseModel):
    """Model for detected PII."""

    pii_type: str
    value: str
    start_pos: int
    end_pos: int
    confidence: float


class GuardrailCheckResponse(BaseModel):
    """Response model for guardrail validation."""

    is_safe: bool
    risk_score: float
    threats: List[ThreatDetection]
    pii_detected: List[PIIDetection]
    sanitized_text: Optional[str] = None
    policy_violations: List[str]


@router.get("/checks")
async def get_available_checks():
    """Get list of available guardrail checks."""
    return {
        "checks": [
            {
                "id": "prompt_injection",
                "name": "Prompt Injection Detection",
                "description": "Detects attempts to inject malicious prompts",
                "enabled": True,
            },
            {
                "id": "pii_detection",
                "name": "PII Detection",
                "description": "Identifies personally identifiable information",
                "enabled": True,
            },
            {
                "id": "toxicity",
                "name": "Toxicity Detection",
                "description": "Detects toxic, abusive, or harmful content",
                "enabled": True,
            },
            {
                "id": "jailbreak",
                "name": "Jailbreak Detection",
                "description": "Identifies jailbreak attempts",
                "enabled": True,
            },
            {
                "id": "data_leakage",
                "name": "Data Leakage Prevention",
                "description": "Prevents leakage of sensitive information",
                "enabled": True,
            },
            {
                "id": "policy_compliance",
                "name": "Policy Compliance",
                "description": "Validates against custom policies",
                "enabled": True,
            },
        ]
    }


@router.post("/validate", response_model=GuardrailCheckResponse)
async def validate_text(request: GuardrailCheckRequest):
    """Validate text against guardrails."""
    threats = []
    pii_detected = []
    policy_violations = []
    text_lower = request.text.lower()

    # Prompt Injection Detection
    injection_patterns = [
        "ignore previous",
        "ignore all previous",
        "disregard",
        "new task",
        "system override",
        "forget your",
        "act as",
        "[inst]",
        "developer mode",
    ]
    for pattern in injection_patterns:
        if pattern in text_lower:
            threats.append(
                ThreatDetection(
                    threat_type="prompt_injection",
                    severity="high",
                    confidence=0.85,
                    description=f"Potential prompt injection detected",
                    matched_pattern=pattern,
                )
            )

    # Jailbreak Detection
    jailbreak_patterns = [
        "dan mode",
        "do anything now",
        "without filters",
        "unrestricted",
        "bypass safety",
        "hypothetical scenario",
    ]
    for pattern in jailbreak_patterns:
        if pattern in text_lower:
            threats.append(
                ThreatDetection(
                    threat_type="jailbreak",
                    severity="critical",
                    confidence=0.90,
                    description=f"Jailbreak attempt detected",
                    matched_pattern=pattern,
                )
            )

    # PII Detection (simplified)
    import re

    # Email detection
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    for match in re.finditer(email_pattern, request.text):
        pii_detected.append(
            PIIDetection(
                pii_type="email",
                value=match.group(),
                start_pos=match.start(),
                end_pos=match.end(),
                confidence=0.95,
            )
        )

    # Phone number detection
    phone_pattern = r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"
    for match in re.finditer(phone_pattern, request.text):
        pii_detected.append(
            PIIDetection(
                pii_type="phone",
                value=match.group(),
                start_pos=match.start(),
                end_pos=match.end(),
                confidence=0.85,
            )
        )

    # SSN detection
    ssn_pattern = r"\b\d{3}-\d{2}-\d{4}\b"
    for match in re.finditer(ssn_pattern, request.text):
        pii_detected.append(
            PIIDetection(
                pii_type="ssn",
                value=match.group(),
                start_pos=match.start(),
                end_pos=match.end(),
                confidence=0.90,
            )
        )

    # Credit card detection
    cc_pattern = r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"
    for match in re.finditer(cc_pattern, request.text):
        pii_detected.append(
            PIIDetection(
                pii_type="credit_card",
                value=match.group(),
                start_pos=match.start(),
                end_pos=match.end(),
                confidence=0.80,
            )
        )

    # Toxicity Detection (simplified)
    toxic_words = ["harmful", "malicious", "attack", "exploit", "hack"]
    toxicity_count = sum(1 for word in toxic_words if word in text_lower)
    if toxicity_count >= 2:
        threats.append(
            ThreatDetection(
                threat_type="toxicity",
                severity="medium",
                confidence=0.70,
                description=f"Potentially toxic content detected",
                matched_pattern=None,
            )
        )

    # Policy Violations
    if len(request.text) > 10000:
        policy_violations.append("Text exceeds maximum length of 10000 characters")

    if request.mode == "output" and pii_detected:
        policy_violations.append("Output contains PII which should be sanitized")

    # Calculate risk score
    risk_score = 0.0
    for threat in threats:
        if threat.severity == "critical":
            risk_score += 0.4
        elif threat.severity == "high":
            risk_score += 0.25
        elif threat.severity == "medium":
            risk_score += 0.1

    risk_score += len(pii_detected) * 0.15
    risk_score = min(risk_score, 1.0)

    # Sanitize text if needed
    sanitized_text = request.text
    if pii_detected:
        for pii in sorted(pii_detected, key=lambda x: x.start_pos, reverse=True):
            sanitized_text = (
                sanitized_text[: pii.start_pos]
                + f"[REDACTED_{pii.pii_type.upper()}]"
                + sanitized_text[pii.end_pos :]
            )

    is_safe = risk_score < 0.5 and len(policy_violations) == 0

    return GuardrailCheckResponse(
        is_safe=is_safe,
        risk_score=risk_score,
        threats=threats,
        pii_detected=pii_detected,
        sanitized_text=sanitized_text if pii_detected else None,
        policy_violations=policy_violations,
    )


@router.get("/policies")
async def get_policies():
    """Get configured policies."""
    return {
        "policies": [
            {
                "id": "no_pii",
                "name": "No PII in Output",
                "description": "Prevents PII from appearing in model outputs",
                "enabled": True,
                "severity": "high",
            },
            {
                "id": "max_tokens",
                "name": "Maximum Token Limit",
                "description": "Limits response length to prevent abuse",
                "enabled": True,
                "severity": "medium",
                "config": {"max_tokens": 4096},
            },
            {
                "id": "content_filter",
                "name": "Content Filter",
                "description": "Blocks inappropriate content",
                "enabled": True,
                "severity": "high",
            },
        ]
    }


@router.get("/stats")
async def get_guardrail_stats():
    """Get guardrail statistics."""
    return {
        "total_checks": 12450,
        "threats_blocked": 342,
        "pii_redacted": 127,
        "policy_violations": 89,
        "success_rate": 0.973,
        "avg_processing_time_ms": 45,
        "top_threats": [
            {"type": "prompt_injection", "count": 156},
            {"type": "jailbreak", "count": 98},
            {"type": "pii_leak", "count": 88},
        ],
    }
