"""
Alerting and incident response API endpoints.
"""
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.alerting.alert_manager import (
    Alert,
    AlertCategory,
    AlertManager,
    AlertSeverity,
    AlertStatus,
)
from backend.alerting.incident_response import (
    Incident,
    IncidentResponseEngine,
    IncidentStatus,
)
from backend.alerting.notifications import (
    EmailNotifier,
    PagerDutyNotifier,
    SlackNotifier,
)
from backend.alerting.siem_connectors import SplunkConnector, WazuhConnector

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/alerting", tags=["alerting"])

# Initialize services
alert_manager = AlertManager()
incident_engine = IncidentResponseEngine()


# Request/Response Models
class CreateAlertRequest(BaseModel):
    """Request to create an alert."""

    severity: str = Field(..., description="Alert severity (critical, high, medium, low, info)")
    category: str = Field(..., description="Alert category")
    title: str = Field(..., description="Alert title")
    description: str = Field(..., description="Alert description")
    detection_method: Optional[str] = Field(None, description="Detection method")
    confidence_score: float = Field(1.0, description="Confidence score (0-1)")
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    endpoint: Optional[str] = None
    owasp_id: Optional[str] = None
    indicators: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)


class AlertResponse(BaseModel):
    """Response model for alert."""

    alert_id: str
    timestamp: str
    severity: str
    category: str
    title: str
    description: str
    status: str
    detection_method: Optional[str] = None
    confidence_score: float
    owasp_id: Optional[str] = None
    indicators: List[str]
    recommended_actions: List[str]


class UpdateAlertStatusRequest(BaseModel):
    """Request to update alert status."""

    status: str = Field(..., description="New status (open, acknowledged, in_progress, resolved, closed)")
    notes: Optional[str] = Field(None, description="Optional notes")


class IncidentResponse(BaseModel):
    """Response model for incident."""

    incident_id: str
    created_at: str
    status: str
    title: str
    description: str
    severity: str
    category: str
    alerts: List[str]
    playbook_id: Optional[str] = None
    completed_steps: List[str]
    timeline: List[Dict[str, Any]]


class UpdateIncidentRequest(BaseModel):
    """Request to update incident."""

    status: str = Field(..., description="New status")
    notes: Optional[str] = Field(None, description="Optional notes")


class CloseIncidentRequest(BaseModel):
    """Request to close incident."""

    resolution_notes: str
    root_cause: Optional[str] = None
    lessons_learned: Optional[str] = None


# Alert Endpoints
@router.post("/alerts", response_model=AlertResponse)
async def create_alert(request: CreateAlertRequest) -> AlertResponse:
    """
    Create a new security alert.

    Args:
        request: Alert creation request

    Returns:
        Created alert
    """
    try:
        severity = AlertSeverity(request.severity.lower())
        category = AlertCategory(request.category.lower())

        alert = await alert_manager.create_alert(
            severity=severity,
            category=category,
            title=request.title,
            description=request.description,
            detection_method=request.detection_method,
            confidence_score=request.confidence_score,
            user_id=request.user_id,
            session_id=request.session_id,
            endpoint=request.endpoint,
            owasp_id=request.owasp_id,
            indicators=request.indicators,
            recommended_actions=request.recommended_actions,
        )

        if not alert:
            raise HTTPException(
                status_code=400,
                detail="Alert was suppressed due to correlation",
            )

        return AlertResponse(
            alert_id=alert.alert_id,
            timestamp=alert.timestamp.isoformat(),
            severity=alert.severity.value,
            category=alert.category.value,
            title=alert.title,
            description=alert.description,
            status=alert.status.value,
            detection_method=alert.detection_method,
            confidence_score=alert.confidence_score,
            owasp_id=alert.owasp_id,
            indicators=alert.indicators,
            recommended_actions=alert.recommended_actions,
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid parameter: {str(e)}")
    except Exception as e:
        logger.error(f"Error creating alert: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to create alert: {str(e)}")


@router.get("/alerts", response_model=List[AlertResponse])
async def get_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    category: Optional[str] = Query(None, description="Filter by category"),
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(100, description="Maximum alerts to return"),
) -> List[AlertResponse]:
    """
    Get alerts with optional filtering.

    Args:
        severity: Optional severity filter
        category: Optional category filter
        status: Optional status filter
        limit: Maximum alerts to return

    Returns:
        List of alerts
    """
    try:
        severity_enum = AlertSeverity(severity.lower()) if severity else None
        category_enum = AlertCategory(category.lower()) if category else None
        status_enum = AlertStatus(status.lower()) if status else None

        alerts = await alert_manager.get_alerts(
            severity=severity_enum,
            category=category_enum,
            status=status_enum,
            limit=limit,
        )

        return [
            AlertResponse(
                alert_id=alert.alert_id,
                timestamp=alert.timestamp.isoformat(),
                severity=alert.severity.value,
                category=alert.category.value,
                title=alert.title,
                description=alert.description,
                status=alert.status.value,
                detection_method=alert.detection_method,
                confidence_score=alert.confidence_score,
                owasp_id=alert.owasp_id,
                indicators=alert.indicators,
                recommended_actions=alert.recommended_actions,
            )
            for alert in alerts
        ]

    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid parameter: {str(e)}")
    except Exception as e:
        logger.error(f"Error getting alerts: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get alerts: {str(e)}")


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str) -> AlertResponse:
    """
    Get specific alert by ID.

    Args:
        alert_id: Alert ID

    Returns:
        Alert details
    """
    if alert_id not in alert_manager.alerts:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert = alert_manager.alerts[alert_id]

    return AlertResponse(
        alert_id=alert.alert_id,
        timestamp=alert.timestamp.isoformat(),
        severity=alert.severity.value,
        category=alert.category.value,
        title=alert.title,
        description=alert.description,
        status=alert.status.value,
        detection_method=alert.detection_method,
        confidence_score=alert.confidence_score,
        owasp_id=alert.owasp_id,
        indicators=alert.indicators,
        recommended_actions=alert.recommended_actions,
    )


@router.patch("/alerts/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    request: UpdateAlertStatusRequest,
) -> Dict[str, str]:
    """
    Update alert status.

    Args:
        alert_id: Alert ID
        request: Status update request

    Returns:
        Success message
    """
    try:
        if alert_id not in alert_manager.alerts:
            raise HTTPException(status_code=404, detail="Alert not found")

        status = AlertStatus(request.status.lower())

        await alert_manager.update_alert_status(alert_id, status, request.notes)

        return {"status": "success", "message": f"Alert status updated to {status.value}"}

    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid status: {str(e)}")
    except Exception as e:
        logger.error(f"Error updating alert status: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to update status: {str(e)}")


@router.get("/alerts/statistics")
async def get_alert_statistics() -> Dict[str, Any]:
    """
    Get alert statistics.

    Returns:
        Statistics dictionary
    """
    try:
        stats = await alert_manager.get_statistics()
        aggregation_summary = await alert_manager.aggregator.get_aggregated_summary()

        return {
            **stats,
            "aggregation": aggregation_summary,
        }

    except Exception as e:
        logger.error(f"Error getting statistics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")


# Incident Endpoints
@router.post("/incidents/from-alert/{alert_id}", response_model=IncidentResponse)
async def create_incident_from_alert(alert_id: str) -> IncidentResponse:
    """
    Create incident from alert.

    Args:
        alert_id: Alert ID to create incident from

    Returns:
        Created incident
    """
    try:
        if alert_id not in alert_manager.alerts:
            raise HTTPException(status_code=404, detail="Alert not found")

        alert = alert_manager.alerts[alert_id]

        incident = await incident_engine.create_incident_from_alert(alert)

        return IncidentResponse(
            incident_id=incident.incident_id,
            created_at=incident.created_at.isoformat(),
            status=incident.status.value,
            title=incident.title,
            description=incident.description,
            severity=incident.severity.value,
            category=incident.category.value,
            alerts=incident.alerts,
            playbook_id=incident.playbook_id,
            completed_steps=incident.completed_steps,
            timeline=incident.timeline,
        )

    except Exception as e:
        logger.error(f"Error creating incident: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to create incident: {str(e)}")


@router.get("/incidents", response_model=List[IncidentResponse])
async def get_incidents(active_only: bool = Query(False, description="Get only active incidents")):
    """
    Get incidents.

    Args:
        active_only: Whether to return only active incidents

    Returns:
        List of incidents
    """
    try:
        if active_only:
            incidents = await incident_engine.get_active_incidents()
        else:
            incidents = list(incident_engine.incidents.values())

        return [
            IncidentResponse(
                incident_id=incident.incident_id,
                created_at=incident.created_at.isoformat(),
                status=incident.status.value,
                title=incident.title,
                description=incident.description,
                severity=incident.severity.value,
                category=incident.category.value,
                alerts=incident.alerts,
                playbook_id=incident.playbook_id,
                completed_steps=incident.completed_steps,
                timeline=incident.timeline,
            )
            for incident in incidents
        ]

    except Exception as e:
        logger.error(f"Error getting incidents: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get incidents: {str(e)}")


@router.patch("/incidents/{incident_id}/status")
async def update_incident_status(
    incident_id: str,
    request: UpdateIncidentRequest,
) -> Dict[str, str]:
    """
    Update incident status.

    Args:
        incident_id: Incident ID
        request: Status update request

    Returns:
        Success message
    """
    try:
        if incident_id not in incident_engine.incidents:
            raise HTTPException(status_code=404, detail="Incident not found")

        status = IncidentStatus(request.status.lower())

        await incident_engine.update_incident_status(incident_id, status, request.notes)

        return {"status": "success", "message": f"Incident status updated to {status.value}"}

    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid status: {str(e)}")
    except Exception as e:
        logger.error(f"Error updating incident status: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to update status: {str(e)}")


@router.post("/incidents/{incident_id}/close")
async def close_incident(
    incident_id: str,
    request: CloseIncidentRequest,
) -> Dict[str, str]:
    """
    Close incident.

    Args:
        incident_id: Incident ID
        request: Close request with resolution notes

    Returns:
        Success message
    """
    try:
        if incident_id not in incident_engine.incidents:
            raise HTTPException(status_code=404, detail="Incident not found")

        await incident_engine.close_incident(
            incident_id,
            request.resolution_notes,
            request.root_cause,
            request.lessons_learned,
        )

        return {"status": "success", "message": "Incident closed"}

    except Exception as e:
        logger.error(f"Error closing incident: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to close incident: {str(e)}")


@router.get("/incidents/statistics")
async def get_incident_statistics() -> Dict[str, Any]:
    """
    Get incident statistics.

    Returns:
        Statistics dictionary
    """
    try:
        stats = await incident_engine.get_incident_statistics()
        return stats

    except Exception as e:
        logger.error(f"Error getting incident statistics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")


# Playbook Endpoints
@router.get("/playbooks")
async def get_playbooks() -> Dict[str, Any]:
    """
    Get available incident response playbooks.

    Returns:
        Dictionary of playbooks
    """
    return {
        "playbooks": [
            {
                "playbook_id": pb.playbook_id,
                "name": pb.name,
                "description": pb.description,
                "trigger_categories": [cat.value for cat in pb.trigger_categories],
                "trigger_severities": [sev.value for sev in pb.trigger_severities],
                "steps": [
                    {
                        "step_id": step.step_id,
                        "action": step.action.value,
                        "description": step.description,
                        "automated": step.automated,
                    }
                    for step in pb.steps
                ],
                "enabled": pb.enabled,
            }
            for pb in incident_engine.playbooks.values()
        ]
    }


@router.get("/health")
async def alerting_health_check() -> Dict[str, str]:
    """Health check for alerting service."""
    return {
        "status": "healthy",
        "service": "alerting",
        "version": "1.0.0",
    }
