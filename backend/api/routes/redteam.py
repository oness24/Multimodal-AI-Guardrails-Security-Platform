"""
Red Team API endpoints for AdversarialShield.
"""
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.database import get_db
from backend.core.models import AttackLog, AttackPattern
from backend.redteam.prompt_injection import PromptInjectionGenerator

router = APIRouter()


# Request/Response Models
class AttackGenerationRequest(BaseModel):
    """Request model for generating attacks."""

    technique: str = Field(..., description="Attack technique to use")
    target_context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Context about the target system",
    )
    custom_objective: Optional[str] = Field(
        default=None,
        description="Custom attack objective",
    )
    llm_provider: str = Field(
        default="openai",
        description="LLM provider to use (openai, anthropic, ollama)",
    )


class BatchAttackGenerationRequest(BaseModel):
    """Request model for batch attack generation."""

    techniques: List[str] = Field(..., description="List of techniques to generate")
    target_context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Context about the target system",
    )
    llm_provider: str = Field(
        default="openai",
        description="LLM provider to use",
    )


class AttackTestRequest(BaseModel):
    """Request model for testing attacks."""

    payload: str = Field(..., description="Attack payload to test")
    target_model: str = Field(
        default="gpt-3.5-turbo",
        description="Target model to test against",
    )
    test_prompt: Optional[str] = Field(
        default=None,
        description="Optional test prompt to combine with payload",
    )
    llm_provider: str = Field(
        default="openai",
        description="LLM provider to use",
    )


class AttackGenerationResponse(BaseModel):
    """Response model for attack generation."""

    id: Optional[UUID] = None
    technique: str
    payload: str
    llm_provider: str
    success: bool = True
    error: Optional[str] = None


class AttackTestResponse(BaseModel):
    """Response model for attack testing."""

    id: UUID
    payload: str
    response: Optional[str]
    success: bool
    execution_time_ms: int
    target_model: str
    error: Optional[str] = None


class AttackPatternResponse(BaseModel):
    """Response model for attack patterns."""

    id: UUID
    name: str
    technique: str
    category: str
    description: Optional[str]
    severity: str
    owasp_category: Optional[str]
    success_rate: float
    total_executions: int


class AttackLogResponse(BaseModel):
    """Response model for attack logs."""

    id: UUID
    technique: str
    success: bool
    target_model: Optional[str]
    execution_time_ms: Optional[int]
    created_at: str


# Endpoints


@router.post("/generate", response_model=AttackGenerationResponse)
async def generate_attack(
    request: AttackGenerationRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Generate an adversarial attack using specified technique.

    This endpoint uses LLMs to generate creative prompt injection attacks
    based on the specified technique.
    """
    try:
        # Initialize generator
        generator = PromptInjectionGenerator(llm_provider=request.llm_provider)

        # Generate attack
        payload = await generator.generate_attack(
            technique=request.technique,
            target_context=request.target_context,
            custom_objective=request.custom_objective,
        )

        return AttackGenerationResponse(
            technique=request.technique,
            payload=payload,
            llm_provider=request.llm_provider,
            success=True,
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        return AttackGenerationResponse(
            technique=request.technique,
            payload="",
            llm_provider=request.llm_provider,
            success=False,
            error=str(e),
        )


@router.post("/generate/batch", response_model=List[AttackGenerationResponse])
async def generate_batch_attacks(
    request: BatchAttackGenerationRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Generate multiple attacks in parallel.

    This endpoint generates attacks for multiple techniques concurrently,
    improving performance for bulk generation.
    """
    try:
        generator = PromptInjectionGenerator(llm_provider=request.llm_provider)

        # Generate attacks in parallel
        results = await generator.generate_batch(
            techniques=request.techniques,
            target_context=request.target_context,
        )

        return [
            AttackGenerationResponse(
                technique=technique,
                payload=payload,
                llm_provider=request.llm_provider,
                success=True,
            )
            for technique, payload in results.items()
        ]

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test", response_model=AttackTestResponse)
async def test_attack(
    request: AttackTestRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Test an attack payload against a target model.

    This endpoint executes the attack and analyzes the response
    to determine if the attack was successful.
    """
    try:
        generator = PromptInjectionGenerator(llm_provider=request.llm_provider)

        # Test attack
        result = await generator.test_attack(
            payload=request.payload,
            target_model=request.target_model,
            test_prompt=request.test_prompt,
        )

        # Log to database
        attack_log = await generator.log_attack(
            db=db,
            technique="unknown",  # Technique not specified in test
            payload=request.payload,
            result=result,
        )

        return AttackTestResponse(
            id=attack_log.id,
            payload=result["payload"],
            response=result["response"],
            success=result["success"],
            execution_time_ms=result["execution_time_ms"],
            target_model=result["target_model"],
            error=result.get("error"),
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/techniques", response_model=List[str])
async def list_techniques():
    """
    List all available attack techniques.

    Returns a list of supported prompt injection techniques.
    """
    return PromptInjectionGenerator.TECHNIQUES


@router.get("/patterns", response_model=List[AttackPatternResponse])
async def list_patterns(
    technique: Optional[str] = Query(None, description="Filter by technique"),
    category: Optional[str] = Query(None, description="Filter by category"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=100, description="Number of results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: AsyncSession = Depends(get_db),
):
    """
    List attack patterns from database.

    Returns patterns with optional filtering by technique, category, or severity.
    """
    query = select(AttackPattern).where(AttackPattern.is_active == True)

    if technique:
        query = query.where(AttackPattern.technique == technique)
    if category:
        query = query.where(AttackPattern.category == category)
    if severity:
        query = query.where(AttackPattern.severity == severity)

    query = query.offset(offset).limit(limit)

    result = await db.execute(query)
    patterns = result.scalars().all()

    return [
        AttackPatternResponse(
            id=p.id,
            name=p.name,
            technique=p.technique,
            category=p.category,
            description=p.description,
            severity=p.severity,
            owasp_category=p.owasp_category,
            success_rate=p.success_rate,
            total_executions=p.total_executions,
        )
        for p in patterns
    ]


@router.get("/patterns/{pattern_id}", response_model=AttackPatternResponse)
async def get_pattern(
    pattern_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Get a specific attack pattern by ID.
    """
    result = await db.execute(
        select(AttackPattern).where(AttackPattern.id == pattern_id)
    )
    pattern = result.scalar_one_or_none()

    if not pattern:
        raise HTTPException(status_code=404, detail="Pattern not found")

    return AttackPatternResponse(
        id=pattern.id,
        name=pattern.name,
        technique=pattern.technique,
        category=pattern.category,
        description=pattern.description,
        severity=pattern.severity,
        owasp_category=pattern.owasp_category,
        success_rate=pattern.success_rate,
        total_executions=pattern.total_executions,
    )


@router.get("/logs", response_model=List[AttackLogResponse])
async def list_attack_logs(
    technique: Optional[str] = Query(None, description="Filter by technique"),
    success: Optional[bool] = Query(None, description="Filter by success status"),
    limit: int = Query(50, ge=1, le=100, description="Number of results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: AsyncSession = Depends(get_db),
):
    """
    List attack execution logs.

    Returns logs of attack executions with optional filtering.
    """
    query = select(AttackLog).order_by(AttackLog.created_at.desc())

    if technique:
        query = query.where(AttackLog.technique == technique)
    if success is not None:
        query = query.where(AttackLog.success == success)

    query = query.offset(offset).limit(limit)

    result = await db.execute(query)
    logs = result.scalars().all()

    return [
        AttackLogResponse(
            id=log.id,
            technique=log.technique,
            success=log.success,
            target_model=log.target_model,
            execution_time_ms=log.execution_time_ms,
            created_at=log.created_at.isoformat(),
        )
        for log in logs
    ]


@router.get("/logs/{log_id}", response_model=Dict[str, Any])
async def get_attack_log(
    log_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Get detailed information about a specific attack log.
    """
    result = await db.execute(
        select(AttackLog).where(AttackLog.id == log_id)
    )
    log = result.scalar_one_or_none()

    if not log:
        raise HTTPException(status_code=404, detail="Attack log not found")

    return {
        "id": str(log.id),
        "technique": log.technique,
        "payload": log.payload,
        "response": log.response,
        "success": log.success,
        "target_model": log.target_model,
        "execution_time_ms": log.execution_time_ms,
        "attack_type": log.attack_type,
        "metadata": log.metadata,
        "error_message": log.error_message,
        "created_at": log.created_at.isoformat(),
    }


@router.get("/stats", response_model=Dict[str, Any])
async def get_attack_stats(
    db: AsyncSession = Depends(get_db),
):
    """
    Get statistics about attacks.

    Returns overall success rates, popular techniques, and other metrics.
    """
    # Get total attacks
    total_result = await db.execute(select(AttackLog))
    all_logs = total_result.scalars().all()

    total_attacks = len(all_logs)
    successful_attacks = sum(1 for log in all_logs if log.success)

    # Calculate stats
    success_rate = (
        (successful_attacks / total_attacks * 100)
        if total_attacks > 0
        else 0.0
    )

    # Group by technique
    technique_stats = {}
    for log in all_logs:
        if log.technique not in technique_stats:
            technique_stats[log.technique] = {"total": 0, "successful": 0}
        technique_stats[log.technique]["total"] += 1
        if log.success:
            technique_stats[log.technique]["successful"] += 1

    # Calculate success rate per technique
    for technique, stats in technique_stats.items():
        stats["success_rate"] = (
            (stats["successful"] / stats["total"] * 100)
            if stats["total"] > 0
            else 0.0
        )

    return {
        "total_attacks": total_attacks,
        "successful_attacks": successful_attacks,
        "overall_success_rate": round(success_rate, 2),
        "technique_stats": technique_stats,
    }
