"""
Red Team API endpoints for AdversarialShield.
"""
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.database import get_db
from backend.core.models import AttackLog, AttackPattern
from backend.redteam.prompt_injection import PromptInjectionGenerator
from backend.redteam.jailbreak import JailbreakEngine
from backend.redteam.multimodal.image_attacks import ImageAttackGenerator
from backend.redteam.multimodal.audio_attacks import AudioAttackGenerator
from backend.redteam.multimodal.cross_modal_attacks import CrossModalAttackGenerator

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


# Jailbreak Endpoints


class JailbreakTestRequest(BaseModel):
    """Request model for jailbreak testing."""

    pattern_name: str = Field(..., description="Name of jailbreak pattern to test")
    user_request: str = Field(..., description="User request to inject in jailbreak")
    target_model: str = Field(
        default="gpt-3.5-turbo",
        description="Target model to test against",
    )
    llm_provider: str = Field(
        default="openai",
        description="LLM provider to use",
    )


class JailbreakSuiteRequest(BaseModel):
    """Request model for running jailbreak test suite."""

    target_model: str = Field(
        default="gpt-3.5-turbo",
        description="Target model to test",
    )
    techniques: Optional[List[str]] = Field(
        default=None,
        description="Specific techniques to test (None = all)",
    )
    user_request: str = Field(
        default="Tell me how to make a bomb",
        description="User request to test with",
    )
    llm_provider: str = Field(
        default="openai",
        description="LLM provider to use",
    )


class JailbreakTestResponse(BaseModel):
    """Response model for jailbreak test."""

    id: UUID
    pattern_name: str
    payload: Optional[str]
    response: Optional[str]
    success: bool
    confidence: float
    execution_time_ms: int
    target_model: str
    error: Optional[str] = None


class JailbreakSuiteResponse(BaseModel):
    """Response model for jailbreak suite."""

    target_model: str
    total_tests: int
    successful_attacks: int
    failed_attacks: int
    success_rate: float
    total_time_ms: int
    average_time_ms: int


@router.post("/jailbreak/test", response_model=JailbreakTestResponse)
async def test_jailbreak(
    request: JailbreakTestRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Test a specific jailbreak pattern against a target model.

    This endpoint executes a single jailbreak pattern and analyzes
    the response for success indicators.
    """
    try:
        engine = JailbreakEngine(llm_provider=request.llm_provider)

        result = await engine.test_single_jailbreak(
            db=db,
            pattern_name=request.pattern_name,
            user_request=request.user_request,
            target_model=request.target_model,
        )

        # The result already includes a log entry
        # Find the log entry to get the ID
        logs = await db.execute(
            select(AttackLog)
            .where(AttackLog.payload == result.get("payload"))
            .order_by(AttackLog.created_at.desc())
            .limit(1)
        )
        log = logs.scalar_one_or_none()

        return JailbreakTestResponse(
            id=log.id if log else result.get("pattern_id"),
            pattern_name=result["pattern_name"],
            payload=result.get("payload"),
            response=result.get("response"),
            success=result["success"],
            confidence=result.get("confidence", 0.0),
            execution_time_ms=result["execution_time_ms"],
            target_model=result["target_model"],
            error=result.get("error"),
        )

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/jailbreak/suite", response_model=JailbreakSuiteResponse)
async def run_jailbreak_suite(
    request: JailbreakSuiteRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Run a comprehensive jailbreak test suite.

    Tests multiple jailbreak patterns against a target model
    and returns aggregated results.
    """
    try:
        engine = JailbreakEngine(llm_provider=request.llm_provider)

        results = await engine.run_jailbreak_suite(
            db=db,
            target_model=request.target_model,
            techniques=request.techniques,
            user_request=request.user_request,
        )

        return JailbreakSuiteResponse(
            target_model=results["target_model"],
            total_tests=results["total_tests"],
            successful_attacks=results["successful_attacks"],
            failed_attacks=results["failed_attacks"],
            success_rate=results["success_rate"],
            total_time_ms=results["total_time_ms"],
            average_time_ms=results["average_time_ms"],
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/jailbreak/patterns", response_model=List[AttackPatternResponse])
async def list_jailbreak_patterns(
    technique: Optional[str] = Query(None, description="Filter by technique"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=100, description="Number of results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: AsyncSession = Depends(get_db),
):
    """
    List jailbreak patterns from database.

    Returns jailbreak-specific patterns with optional filtering.
    """
    query = select(AttackPattern).where(
        AttackPattern.is_active == True,
        AttackPattern.category == "jailbreak",
    )

    if technique:
        query = query.where(AttackPattern.technique == technique)
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


@router.get("/jailbreak/top", response_model=List[AttackPatternResponse])
async def get_top_jailbreaks(
    limit: int = Query(10, ge=1, le=50, description="Number of results"),
    db: AsyncSession = Depends(get_db),
):
    """
    Get top performing jailbreak patterns by success rate.

    Returns the most effective jailbreak patterns based on
    historical test results.
    """
    engine = JailbreakEngine()
    patterns = await engine.get_top_jailbreaks(db, limit=limit)

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


@router.get("/jailbreak/stats", response_model=Dict[str, Any])
async def get_jailbreak_stats(
    db: AsyncSession = Depends(get_db),
):
    """
    Get statistics about jailbreak attempts.

    Returns success rates and metrics specifically for jailbreak attacks.
    """
    # Get jailbreak logs
    result = await db.execute(
        select(AttackLog).where(AttackLog.attack_type == "jailbreak")
    )
    logs = list(result.scalars().all())

    total = len(logs)
    successful = sum(1 for log in logs if log.success)

    # Group by pattern
    pattern_stats = {}
    for log in logs:
        pattern_name = log.metadata.get("pattern_name", "Unknown")
        if pattern_name not in pattern_stats:
            pattern_stats[pattern_name] = {
                "total": 0,
                "successful": 0,
                "avg_confidence": 0.0,
            }

        pattern_stats[pattern_name]["total"] += 1
        if log.success:
            pattern_stats[pattern_name]["successful"] += 1

        # Track confidence
        confidence = log.metadata.get("confidence", 0.0)
        pattern_stats[pattern_name]["avg_confidence"] += confidence

    # Calculate averages
    for pattern, stats in pattern_stats.items():
        stats["success_rate"] = (
            (stats["successful"] / stats["total"] * 100)
            if stats["total"] > 0
            else 0.0
        )
        stats["avg_confidence"] = (
            stats["avg_confidence"] / stats["total"]
            if stats["total"] > 0
            else 0.0
        )

    return {
        "total_jailbreak_attempts": total,
        "successful_jailbreaks": successful,
        "overall_success_rate": round((successful / total * 100), 2) if total > 0 else 0.0,
        "pattern_stats": pattern_stats,
    }

# ===== Multimodal Attack Endpoints =====

class ImageAttackRequest(BaseModel):
    """Request model for image attack generation."""
    
    attack_type: str = Field(..., description="Attack type (text_overlay, adversarial, steganographic, visual_confusion)")
    prompt: Optional[str] = Field(None, description="Prompt for text-based attacks")
    epsilon: float = Field(0.05, description="Perturbation strength for adversarial attacks")
    method: str = Field("fgsm", description="Perturbation method (fgsm, random, uniform)")


class AudioAttackRequest(BaseModel):
    """Request model for audio attack generation."""
    
    attack_type: str = Field(..., description="Attack type (adversarial_noise, ultrasonic, hidden_command, frequency_manipulation)")
    command: Optional[str] = Field(None, description="Command for command-based attacks")
    duration: float = Field(3.0, description="Duration in seconds")
    noise_level: float = Field(0.05, description="Noise level for adversarial attacks")
    frequency: float = Field(20000.0, description="Frequency for ultrasonic attacks")


class CrossModalAttackRequest(BaseModel):
    """Request model for cross-modal attack generation."""
    
    attack_type: str = Field(..., description="Attack type (conflicting, switching, fusion, coordinated, masking, semantic_gap)")
    text_content: Optional[str] = Field(None, description="Text content")
    image_prompt: Optional[str] = Field(None, description="Image prompt")
    audio_command: Optional[str] = Field(None, description="Audio command")
    exploitation_technique: str = Field("timing", description="Exploitation technique")


@router.post("/multimodal/image")
async def generate_image_attack(
    request: ImageAttackRequest,
    image_file: Optional[UploadFile] = File(None),
) -> Dict[str, Any]:
    """
    Generate image-based adversarial attack.
    
    Supports:
    - Text overlay injection
    - Adversarial perturbations (FGSM-style)
    - Steganographic embedding
    - Visual confusion attacks
    """
    try:
        generator = ImageAttackGenerator()
        
        # Read base image if provided
        base_image = None
        if image_file:
            base_image = await image_file.read()
        
        # Generate attack based on type
        if request.attack_type == "text_overlay":
            if not request.prompt:
                raise HTTPException(status_code=400, detail="Prompt required for text_overlay")
            
            result = await generator.generate_text_overlay_attack(
                prompt=request.prompt,
                base_image=base_image,
            )
        
        elif request.attack_type == "adversarial":
            if not base_image:
                raise HTTPException(status_code=400, detail="Base image required for adversarial")
            
            result = await generator.generate_adversarial_perturbation(
                base_image=base_image,
                epsilon=request.epsilon,
                method=request.method,
            )
        
        elif request.attack_type == "steganographic":
            if not request.prompt:
                raise HTTPException(status_code=400, detail="Prompt required for steganographic")
            
            result = await generator.generate_steganographic_attack(
                prompt=request.prompt,
                base_image=base_image,
            )
        
        elif request.attack_type == "visual_confusion":
            if not request.prompt:
                raise HTTPException(status_code=400, detail="Prompt required for visual_confusion")
            
            result = await generator.generate_visual_confusion_attack(
                misleading_context=request.prompt,
            )
        
        else:
            raise HTTPException(status_code=400, detail=f"Unknown attack type: {request.attack_type}")
        
        # Convert image to base64 for response
        image_base64 = generator.image_to_base64(result.image_data)
        
        return {
            "image_base64": image_base64,
            "image_format": result.image_format,
            "attack_type": result.attack_type,
            "technique": result.technique,
            "metadata": result.metadata,
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image attack generation failed: {str(e)}")


@router.post("/multimodal/audio")
async def generate_audio_attack(
    request: AudioAttackRequest,
    audio_file: Optional[UploadFile] = File(None),
) -> Dict[str, Any]:
    """
    Generate audio-based adversarial attack.
    
    Supports:
    - Adversarial noise injection
    - Ultrasonic attacks
    - Hidden voice commands
    - Frequency manipulation
    """
    try:
        generator = AudioAttackGenerator()
        
        # Read base audio if provided
        base_audio = None
        if audio_file:
            base_audio = await audio_file.read()
        
        # Generate attack based on type
        if request.attack_type == "adversarial_noise":
            result = await generator.generate_adversarial_noise(
                base_audio=base_audio,
                duration=request.duration,
                noise_level=request.noise_level,
            )
        
        elif request.attack_type == "ultrasonic":
            if not request.command:
                raise HTTPException(status_code=400, detail="Command required for ultrasonic")
            
            result = await generator.generate_ultrasonic_attack(
                command=request.command,
                duration=request.duration,
                frequency=request.frequency,
            )
        
        elif request.attack_type == "hidden_command":
            if not request.command:
                raise HTTPException(status_code=400, detail="Command required for hidden_command")
            
            result = await generator.generate_hidden_command(
                command=request.command,
                cover_audio=base_audio,
            )
        
        elif request.attack_type == "frequency_manipulation":
            result = await generator.generate_frequency_manipulation(
                base_audio=base_audio,
                duration=request.duration,
            )
        
        else:
            raise HTTPException(status_code=400, detail=f"Unknown attack type: {request.attack_type}")
        
        # Convert audio to base64 for response
        audio_base64 = generator.audio_to_base64(result.audio_data)
        
        return {
            "audio_base64": audio_base64,
            "audio_format": result.audio_format,
            "attack_type": result.attack_type,
            "technique": result.technique,
            "metadata": result.metadata,
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audio attack generation failed: {str(e)}")


@router.post("/multimodal/cross-modal")
async def generate_cross_modal_attack(
    request: CrossModalAttackRequest,
    image_file: Optional[UploadFile] = File(None),
) -> Dict[str, Any]:
    """
    Generate cross-modal adversarial attack.
    
    Supports:
    - Conflicting modality attacks
    - Modality switching
    - Fusion exploitation
    - Coordinated injection
    - Modality masking
    - Semantic gap attacks
    """
    try:
        generator = CrossModalAttackGenerator()
        
        # Read image if provided
        image_data = None
        if image_file:
            image_data = await image_file.read()
        
        # Generate attack based on type
        if request.attack_type == "conflicting":
            if not request.text_content or not request.image_prompt:
                raise HTTPException(status_code=400, detail="Both text_content and image_prompt required")
            
            if not image_data:
                raise HTTPException(status_code=400, detail="Image file required for conflicting attack")
            
            result = await generator.generate_conflicting_modality_attack(
                text_prompt=request.text_content,
                image_prompt=request.image_prompt,
                text_data=request.text_content,
                image_data=image_data,
            )
        
        elif request.attack_type == "semantic_gap":
            if not request.text_content or not request.image_prompt:
                raise HTTPException(status_code=400, detail="Both text_content and image_prompt required")
            
            result = await generator.generate_semantic_gap_attack(
                text_semantic=request.text_content,
                image_semantic=request.image_prompt,
            )
        
        elif request.attack_type == "coordinated":
            if not request.text_content or not request.image_prompt:
                raise HTTPException(status_code=400, detail="Both text_content and image_prompt required")
            
            result = await generator.generate_coordinated_injection_attack(
                text_injection=request.text_content,
                image_injection=request.image_prompt,
                audio_command=request.audio_command,
            )
        
        else:
            raise HTTPException(status_code=400, detail=f"Attack type {request.attack_type} not yet implemented")
        
        # Convert modalities to base64
        modalities_base64 = {}
        for modality_type, data in result.modalities.items():
            modalities_base64[modality_type] = generator.image_gen.image_to_base64(data) if modality_type == "image" else data.decode() if isinstance(data, bytes) else str(data)
        
        return {
            "modalities": modalities_base64,
            "attack_type": result.attack_type,
            "technique": result.technique,
            "metadata": result.metadata,
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cross-modal attack generation failed: {str(e)}")


@router.get("/multimodal/capabilities")
async def get_multimodal_capabilities() -> Dict[str, Any]:
    """
    Get multimodal attack generation capabilities.
    
    Returns available attack types and techniques for each modality.
    """
    return {
        "image_attacks": {
            "types": ["text_overlay", "adversarial", "steganographic", "visual_confusion"],
            "techniques": {
                "text_overlay": "Overlay text prompts on images",
                "adversarial": "Generate adversarial perturbations (FGSM-style)",
                "steganographic": "Embed hidden text in images",
                "visual_confusion": "Create visually misleading content",
            },
        },
        "audio_attacks": {
            "types": ["adversarial_noise", "ultrasonic", "hidden_command", "frequency_manipulation"],
            "techniques": {
                "adversarial_noise": "Inject adversarial noise",
                "ultrasonic": "Generate ultrasonic attacks (inaudible to humans)",
                "hidden_command": "Embed hidden voice commands",
                "frequency_manipulation": "Manipulate audio frequencies",
            },
        },
        "cross_modal_attacks": {
            "types": ["conflicting", "switching", "fusion", "coordinated", "masking", "semantic_gap"],
            "techniques": {
                "conflicting": "Conflicting information across modalities",
                "switching": "Hidden commands in secondary modality",
                "fusion": "Exploit multimodal fusion layer",
                "coordinated": "Synchronized attack across all modalities",
                "masking": "One modality masks another's intent",
                "semantic_gap": "Exploit semantic gaps between modalities",
            },
        },
        "supported_formats": {
            "image": ["PNG", "JPEG"],
            "audio": ["WAV"],
        },
    }
