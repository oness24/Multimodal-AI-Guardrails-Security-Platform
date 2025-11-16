"""
Threat Intelligence API endpoints.
"""
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.threat_intel.attack_surface_mapper import (
    AttackSurface,
    AttackSurfaceMapper,
    Component,
)
from backend.threat_intel.mitre_atlas import MITREATLASIntegration
from backend.threat_intel.owasp_threat_modeler import OWASPThreatModeler
from backend.threat_intel.stride_modeler import STRIDEModeler, ThreatModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])

# Initialize services
attack_surface_mapper = AttackSurfaceMapper()
stride_modeler = STRIDEModeler()
owasp_modeler = OWASPThreatModeler()
mitre_atlas = MITREATLASIntegration()


# Request/Response Models
class ApplicationConfigRequest(BaseModel):
    """Request model for application configuration."""

    app_name: str = Field(..., description="Application name")
    llm_models: Optional[List[Dict[str, Any]]] = Field(default=None, description="LLM model configurations")
    api_endpoints: Optional[List[Dict[str, Any]]] = Field(default=None, description="API endpoint configurations")
    databases: Optional[List[Dict[str, Any]]] = Field(default=None, description="Database configurations")
    vector_stores: Optional[List[Dict[str, Any]]] = Field(default=None, description="Vector store configurations")
    plugins: Optional[List[Dict[str, Any]]] = Field(default=None, description="Plugin configurations")
    data_flows: Optional[List[Dict[str, Any]]] = Field(default=None, description="Data flow configurations")


class AttackSurfaceResponse(BaseModel):
    """Response model for attack surface analysis."""

    analysis_id: str
    application_name: str
    total_components: int
    internet_exposed_components: int
    high_risk_components: int
    total_entry_points: int
    risky_data_flows: int
    overall_risk_score: float
    recommendations: List[Dict[str, str]]


class ThreatModelResponse(BaseModel):
    """Response model for STRIDE threat model."""

    model_id: str
    system_name: str
    total_threats: int
    critical_threats: int
    high_threats: int
    medium_threats: int
    low_threats: int
    threats_by_category: Dict[str, int]
    overall_risk_score: float
    unmitigated_threats: int


class OWASPThreatModelResponse(BaseModel):
    """Response model for OWASP threat model."""

    model_id: str
    application_name: str
    total_threats: int
    critical_threats: int
    high_threats: int
    owasp_categories_found: List[str]
    coverage_percentage: float


class MITREMappingRequest(BaseModel):
    """Request for MITRE ATLAS mapping."""

    threat_description: str = Field(..., description="Threat description")
    owasp_categories: Optional[List[str]] = Field(None, description="OWASP categories")


# Attack Surface Endpoints
@router.post("/attack-surface/analyze", response_model=AttackSurfaceResponse)
async def analyze_attack_surface(request: ApplicationConfigRequest) -> AttackSurfaceResponse:
    """
    Analyze application attack surface.

    Discovers components, maps data flows, identifies entry points,
    and calculates risk scores.

    Args:
        request: Application configuration

    Returns:
        Attack surface analysis
    """
    try:
        # Create mapper
        mapper = AttackSurfaceMapper()

        # Convert request to dict
        app_config = request.dict(exclude_none=True)

        # Perform analysis
        attack_surface = await mapper.analyze_attack_surface(app_config)

        # Get recommendations
        recommendations = await mapper.get_recommendations(attack_surface)

        return AttackSurfaceResponse(
            analysis_id=attack_surface.analysis_id,
            application_name=attack_surface.application_name,
            total_components=attack_surface.total_components,
            internet_exposed_components=attack_surface.internet_exposed_components,
            high_risk_components=attack_surface.high_risk_components,
            total_entry_points=attack_surface.total_entry_points,
            risky_data_flows=attack_surface.risky_data_flows,
            overall_risk_score=attack_surface.overall_risk_score,
            recommendations=recommendations,
        )

    except Exception as e:
        logger.error(f"Error analyzing attack surface: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to analyze attack surface: {str(e)}")


@router.get("/attack-surface/components/{analysis_id}")
async def get_attack_surface_components(analysis_id: str) -> Dict[str, Any]:
    """
    Get detailed component information from attack surface analysis.

    Args:
        analysis_id: Attack surface analysis ID

    Returns:
        Component details
    """
    # In production, would retrieve from database
    # For now, return placeholder
    raise HTTPException(
        status_code=501,
        detail="Component retrieval not yet implemented. Store analysis results in database first.",
    )


# STRIDE Threat Modeling Endpoints
@router.post("/stride/analyze")
async def stride_threat_model(request: ApplicationConfigRequest) -> Dict[str, Any]:
    """
    Perform STRIDE threat modeling on application.

    Analyzes threats across all STRIDE categories:
    - Spoofing
    - Tampering
    - Repudiation
    - Information Disclosure
    - Denial of Service
    - Elevation of Privilege

    Args:
        request: Application configuration

    Returns:
        STRIDE threat model
    """
    try:
        # First get attack surface
        mapper = AttackSurfaceMapper()
        app_config = request.dict(exclude_none=True)
        attack_surface = await mapper.analyze_attack_surface(app_config)

        # Perform STRIDE analysis
        modeler = STRIDEModeler()
        threat_model = await modeler.analyze_attack_surface(attack_surface)

        # Generate report
        report = await modeler.get_threat_report(threat_model)

        return report

    except Exception as e:
        logger.error(f"Error performing STRIDE analysis: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to perform STRIDE analysis: {str(e)}")


# OWASP LLM Threat Modeling Endpoints
@router.post("/owasp/analyze")
async def owasp_threat_model(request: ApplicationConfigRequest) -> Dict[str, Any]:
    """
    Perform OWASP Top 10 for LLM threat modeling.

    Analyzes application against OWASP Top 10 for LLM Applications:
    - LLM01: Prompt Injection
    - LLM02: Insecure Output Handling
    - LLM03: Training Data Poisoning
    - LLM04: Model Denial of Service
    - LLM05: Supply Chain Vulnerabilities
    - LLM06: Sensitive Information Disclosure
    - LLM07: Insecure Plugin Design
    - LLM08: Excessive Agency
    - LLM09: Overreliance
    - LLM10: Model Theft

    Args:
        request: Application configuration

    Returns:
        OWASP threat model
    """
    try:
        # First get attack surface
        mapper = AttackSurfaceMapper()
        app_config = request.dict(exclude_none=True)
        attack_surface = await mapper.analyze_attack_surface(app_config)

        # Perform OWASP analysis
        modeler = OWASPThreatModeler()
        threat_model = await modeler.analyze_attack_surface(attack_surface)

        # Generate report
        report = await modeler.generate_report(threat_model)

        return report

    except Exception as e:
        logger.error(f"Error performing OWASP analysis: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to perform OWASP analysis: {str(e)}")


@router.get("/owasp/categories")
async def get_owasp_categories() -> Dict[str, Any]:
    """
    Get all OWASP Top 10 for LLM categories.

    Returns:
        List of OWASP categories with details
    """
    modeler = OWASPThreatModeler()
    categories = modeler.get_all_categories_info()

    return {"categories": categories, "total": len(categories)}


# MITRE ATLAS Endpoints
@router.post("/mitre-atlas/map")
async def map_to_mitre_atlas(request: MITREMappingRequest) -> Dict[str, Any]:
    """
    Map threat to MITRE ATLAS techniques.

    Args:
        request: Threat description and optional OWASP categories

    Returns:
        MITRE ATLAS technique mappings
    """
    try:
        atlas = MITREATLASIntegration()

        # Map threat to ATLAS techniques
        techniques = await atlas.map_threat_to_atlas(
            request.threat_description, request.owasp_categories
        )

        # Get threat intelligence report
        if techniques:
            report = await atlas.get_threat_intelligence_report(techniques)
            return report
        else:
            return {
                "total_techniques": 0,
                "tactics_involved": [],
                "techniques": [],
                "combined_mitigations": [],
                "combined_detection_methods": [],
            }

    except Exception as e:
        logger.error(f"Error mapping to MITRE ATLAS: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to map to MITRE ATLAS: {str(e)}")


@router.get("/mitre-atlas/techniques/{technique_id}")
async def get_mitre_atlas_technique(technique_id: str) -> Dict[str, Any]:
    """
    Get details for specific MITRE ATLAS technique.

    Args:
        technique_id: ATLAS technique ID (e.g., "AML.T0051.000")

    Returns:
        Technique details
    """
    atlas = MITREATLASIntegration()
    technique = atlas.get_technique(technique_id)

    if not technique:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")

    return {
        "technique_id": technique.technique_id,
        "name": technique.name,
        "description": technique.description,
        "tactic": technique.tactic.value,
        "mitigations": technique.mitigations,
        "detection_methods": technique.detection_methods,
        "examples": technique.examples,
        "owasp_llm_mapping": technique.owasp_llm_mapping,
    }


@router.get("/mitre-atlas/techniques")
async def get_all_mitre_atlas_techniques() -> Dict[str, Any]:
    """
    Get all MITRE ATLAS techniques.

    Returns:
        List of all techniques
    """
    atlas = MITREATLASIntegration()
    techniques = atlas.get_all_techniques_summary()

    return {"techniques": techniques, "total": len(techniques)}


@router.get("/mitre-atlas/tactics")
async def get_mitre_atlas_tactics() -> Dict[str, Any]:
    """
    Get all MITRE ATLAS tactics.

    Returns:
        List of tactics
    """
    atlas = MITREATLASIntegration()
    tactics = atlas.get_all_tactics()

    return {"tactics": tactics, "total": len(tactics)}


@router.get("/mitre-atlas/owasp-mapping/{owasp_id}")
async def get_atlas_by_owasp(owasp_id: str) -> Dict[str, Any]:
    """
    Get MITRE ATLAS techniques mapped to OWASP category.

    Args:
        owasp_id: OWASP category ID (e.g., "LLM01")

    Returns:
        Mapped ATLAS techniques
    """
    atlas = MITREATLASIntegration()
    techniques = atlas.get_techniques_by_owasp(owasp_id)

    return {
        "owasp_id": owasp_id,
        "techniques": [
            {
                "technique_id": t.technique_id,
                "name": t.name,
                "tactic": t.tactic.value,
                "description": t.description,
            }
            for t in techniques
        ],
        "total": len(techniques),
    }


@router.post("/mitre-atlas/navigator")
async def generate_attack_navigator(technique_ids: List[str]) -> Dict[str, Any]:
    """
    Generate ATT&CK Navigator layer for visualization.

    Args:
        technique_ids: List of ATLAS technique IDs to visualize

    Returns:
        Navigator layer JSON
    """
    try:
        atlas = MITREATLASIntegration()
        layer = await atlas.generate_attack_navigator_layer(technique_ids)

        return layer

    except Exception as e:
        logger.error(f"Error generating navigator layer: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to generate navigator: {str(e)}")


# Comprehensive Threat Intelligence Endpoint
@router.post("/comprehensive-analysis")
async def comprehensive_threat_analysis(request: ApplicationConfigRequest) -> Dict[str, Any]:
    """
    Perform comprehensive threat analysis combining all frameworks.

    Analyzes application using:
    - Attack Surface Mapping
    - STRIDE Threat Modeling
    - OWASP Top 10 for LLM
    - MITRE ATLAS Mapping

    Args:
        request: Application configuration

    Returns:
        Comprehensive threat intelligence report
    """
    try:
        app_config = request.dict(exclude_none=True)

        # 1. Attack Surface Analysis
        mapper = AttackSurfaceMapper()
        attack_surface = await mapper.analyze_attack_surface(app_config)
        recommendations = await mapper.get_recommendations(attack_surface)

        # 2. STRIDE Analysis
        stride = STRIDEModeler()
        stride_model = await stride.analyze_attack_surface(attack_surface)
        stride_report = await stride.get_threat_report(stride_model)

        # 3. OWASP Analysis
        owasp = OWASPThreatModeler()
        owasp_model = await owasp.analyze_attack_surface(attack_surface)
        owasp_report = await owasp.generate_report(owasp_model)

        # 4. MITRE ATLAS Coverage
        atlas = MITREATLASIntegration()

        # Collect all ATLAS techniques from STRIDE and OWASP
        all_atlas_techniques = set()
        for threat in stride_model.threats:
            all_atlas_techniques.update(threat.mitre_atlas_mapping)
        for threat in owasp_model.threats:
            all_atlas_techniques.update(threat.mitre_atlas_techniques)

        atlas_techniques = list(all_atlas_techniques)

        # Get comprehensive report
        return {
            "application_name": request.app_name,
            "analysis_summary": {
                "attack_surface": {
                    "total_components": attack_surface.total_components,
                    "internet_exposed": attack_surface.internet_exposed_components,
                    "high_risk": attack_surface.high_risk_components,
                    "overall_risk": f"{attack_surface.overall_risk_score:.2f}/10",
                },
                "stride": {
                    "total_threats": stride_model.total_threats,
                    "critical": stride_model.critical_threats,
                    "high": stride_model.high_threats,
                    "unmitigated": stride_model.unmitigated_threats,
                },
                "owasp": {
                    "total_threats": owasp_model.total_threats,
                    "categories_found": len(owasp_model.owasp_categories_found),
                    "coverage": f"{owasp_model.coverage_percentage:.1f}%",
                },
                "mitre_atlas": {
                    "techniques_identified": len(atlas_techniques),
                    "tactics_involved": len(
                        set(
                            atlas.get_technique(tid).tactic.value
                            for tid in atlas_techniques
                            if atlas.get_technique(tid)
                        )
                    ),
                },
            },
            "attack_surface": {
                "analysis_id": attack_surface.analysis_id,
                "recommendations": recommendations,
            },
            "stride_threats": stride_report["threats"][:10],  # Top 10 by risk
            "owasp_threats": owasp_report["threats"][:10],  # Top 10
            "mitre_atlas_techniques": atlas_techniques,
            "recommendations": {
                "critical_actions": [
                    r["recommendation"]
                    for r in recommendations
                    if r["priority"] == "critical"
                ][:5],
                "high_priority_actions": [
                    r["recommendation"] for r in recommendations if r["priority"] == "high"
                ][:5],
            },
        }

    except Exception as e:
        logger.error(f"Error performing comprehensive analysis: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to perform comprehensive analysis: {str(e)}")


@router.get("/health")
async def threat_intel_health_check() -> Dict[str, str]:
    """Health check for threat intelligence service."""
    return {
        "status": "healthy",
        "service": "threat-intelligence",
        "version": "1.0.0",
    }
