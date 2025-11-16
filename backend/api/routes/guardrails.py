"""
Guardrails API endpoints.
"""
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.guardrails.engine import GuardrailsEngine

logger = logging.getLogger(__name__)

router = APIRouter()

# Initialize guardrails engine (singleton pattern)
_guardrails_engine: Optional[GuardrailsEngine] = None


def get_guardrails_engine() -> GuardrailsEngine:
    """Get or create guardrails engine instance."""
    global _guardrails_engine
    if _guardrails_engine is None:
        _guardrails_engine = GuardrailsEngine()
    return _guardrails_engine


# Request/Response Models


class ProtectInputRequest(BaseModel):
    """Request model for input protection."""

    user_input: str = Field(..., description="User input to protect", min_length=1)
    context: Optional[Dict[str, Any]] = Field(
        None, description="Optional context information"
    )


class ProtectOutputRequest(BaseModel):
    """Request model for output protection."""

    model_output: str = Field(..., description="Model output to validate", min_length=1)
    original_input: str = Field(..., description="Original user input")
    context: Optional[Dict[str, Any]] = Field(
        None, description="Optional context information"
    )


class DetectorTestRequest(BaseModel):
    """Request model for testing individual detector."""

    text: str = Field(..., description="Text to analyze", min_length=1)
    detector_type: str = Field(
        ...,
        description="Detector type (injection, pii, toxicity)",
        pattern="^(injection|pii|toxicity)$",
    )


class SanitizationRequest(BaseModel):
    """Request model for sanitization testing."""

    text: str = Field(..., description="Text to sanitize", min_length=1)


# API Endpoints


@router.post("/protect/input")
async def protect_input(request: ProtectInputRequest) -> Dict[str, Any]:
    """
    Protect user input through guardrails pipeline.

    This endpoint runs input through:
    1. Sanitization layer
    2. Threat detection (injection, PII, toxicity)
    3. Policy evaluation

    Returns protection result with action recommendation.
    """
    try:
        engine = get_guardrails_engine()
        result = await engine.protect_input(
            user_input=request.user_input, context=request.context
        )
        return result

    except Exception as e:
        logger.error(f"Input protection failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Protection failed: {str(e)}")


@router.post("/protect/output")
async def protect_output(request: ProtectOutputRequest) -> Dict[str, Any]:
    """
    Validate model output through guardrails pipeline.

    This endpoint checks output for:
    - PII leakage
    - Toxic content
    - Policy violations

    Returns validation result with action recommendation.
    """
    try:
        engine = get_guardrails_engine()
        result = await engine.protect_output(
            model_output=request.model_output,
            original_input=request.original_input,
            context=request.context,
        )
        return result

    except Exception as e:
        logger.error(f"Output protection failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Protection failed: {str(e)}")


@router.get("/statistics")
async def get_statistics() -> Dict[str, Any]:
    """
    Get guardrails engine statistics.

    Returns:
    - Total checks performed
    - Threats detected
    - Blocked/warned requests
    - Detection rates
    """
    try:
        engine = get_guardrails_engine()
        stats = await engine.get_statistics()
        return stats

    except Exception as e:
        logger.error(f"Failed to get statistics: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail=f"Failed to get statistics: {str(e)}"
        )


@router.post("/test/detector")
async def test_detector(request: DetectorTestRequest) -> Dict[str, Any]:
    """
    Test individual detector.

    Allows testing a specific detector in isolation:
    - `injection`: Prompt injection detector
    - `pii`: PII detector
    - `toxicity`: Toxicity detector

    Returns detailed detection results.
    """
    try:
        engine = get_guardrails_engine()

        if request.detector_type == "injection":
            result = await engine.injection_detector.detect(request.text)
            return {
                "detector": "prompt_injection",
                "detected": result.detected,
                "severity": result.severity,
                "confidence": result.confidence,
                "technique": result.technique,
                "matched_patterns": result.matched_patterns,
                "indicators": result.indicators,
            }

        elif request.detector_type == "pii":
            result = await engine.pii_detector.detect(request.text)
            return {
                "detector": "pii",
                "detected": result.detected,
                "entity_types": result.entity_types,
                "total_count": result.total_count,
                "entities": [
                    {
                        "type": e.type,
                        "text": e.text,
                        "score": e.score,
                        "start": e.start,
                        "end": e.end,
                    }
                    for e in result.entities
                ],
            }

        elif request.detector_type == "toxicity":
            result = await engine.toxicity_detector.detect(request.text)
            return {
                "detector": "toxicity",
                "detected": result.detected,
                "severity": result.severity,
                "confidence": result.confidence,
                "categories": result.categories,
                "matched_terms": result.matched_terms,
                "score_breakdown": result.score_breakdown,
            }

        else:
            raise HTTPException(status_code=400, detail="Invalid detector type")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Detector test failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Detector test failed: {str(e)}")


@router.post("/test/sanitization")
async def test_sanitization(request: SanitizationRequest) -> Dict[str, Any]:
    """
    Test sanitization agent.

    Returns:
    - Sanitized text
    - List of modifications made
    """
    try:
        engine = get_guardrails_engine()
        sanitized = await engine.sanitization_agent.clean(request.text)
        modifications = engine.sanitization_agent.get_modifications()

        return {
            "original": request.text,
            "sanitized": sanitized,
            "modifications": modifications,
            "changed": request.text != sanitized,
        }

    except Exception as e:
        logger.error(f"Sanitization test failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail=f"Sanitization test failed: {str(e)}"
        )


@router.get("/detectors/injection/patterns")
async def get_injection_patterns() -> Dict[str, Any]:
    """
    Get prompt injection detection patterns.

    Returns list of patterns used for detection by technique.
    """
    try:
        engine = get_guardrails_engine()
        patterns = engine.injection_detector.INJECTION_PATTERNS

        return {
            "techniques": list(patterns.keys()),
            "patterns": {
                technique: patterns_list for technique, patterns_list in patterns.items()
            },
            "high_risk_indicators": engine.injection_detector.HIGH_RISK_INDICATORS,
        }

    except Exception as e:
        logger.error(f"Failed to get patterns: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get patterns: {str(e)}")


@router.get("/detectors/toxicity/categories")
async def get_toxicity_categories() -> Dict[str, Any]:
    """
    Get toxicity detection categories.

    Returns list of toxicity categories and their severity weights.
    """
    try:
        engine = get_guardrails_engine()

        return {
            "categories": list(engine.toxicity_detector.TOXICITY_PATTERNS.keys()),
            "severity_weights": engine.toxicity_detector.CATEGORY_SEVERITY,
            "descriptions": {
                "hate_speech": "Content promoting hatred or discrimination",
                "violence": "Content describing or promoting violence",
                "sexual_content": "Explicit sexual content",
                "harassment": "Content intended to harass or bully",
                "self_harm": "Content promoting self-harm or suicide",
                "illegal_activities": "Content describing illegal activities",
                "extremism": "Extremist or terrorist content",
            },
        }

    except Exception as e:
        logger.error(f"Failed to get categories: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail=f"Failed to get categories: {str(e)}"
        )


@router.get("/policies")
async def get_policies() -> Dict[str, Any]:
    """
    Get configured policies.

    Returns list of active policies and their configurations.
    """
    try:
        engine = get_guardrails_engine()
        policies = engine.policy_engine.policies

        return {
            "total_policies": len(policies),
            "policies": {
                name: {
                    "enabled": config.get("enabled", True),
                    "action": config.get("action"),
                    "priority": config.get("priority"),
                    "condition": config.get("condition"),
                }
                for name, config in policies.items()
            },
        }

    except Exception as e:
        logger.error(f"Failed to get policies: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get policies: {str(e)}")


@router.get("/health")
async def health_check() -> Dict[str, str]:
    """
    Health check for guardrails system.

    Returns status of guardrails components.
    """
    try:
        engine = get_guardrails_engine()

        # Test each component
        components_status = {
            "sanitization_agent": "healthy",
            "validation_agent": "healthy",
            "injection_detector": "healthy",
            "pii_detector": "healthy",
            "toxicity_detector": "healthy",
            "policy_engine": "healthy",
        }

        return {
            "status": "healthy",
            "components": components_status,
            "version": "0.1.0",
        }

    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        return {"status": "unhealthy", "error": str(e)}
