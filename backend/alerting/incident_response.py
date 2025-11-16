"""
Incident response workflows and playbooks.
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from backend.alerting.alert_manager import Alert, AlertCategory, AlertSeverity

logger = logging.getLogger(__name__)


class IncidentStatus(str, Enum):
    """Incident status."""

    INVESTIGATING = "investigating"
    IDENTIFIED = "identified"
    MITIGATING = "mitigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


class PlaybookAction(str, Enum):
    """Playbook action types."""

    NOTIFY = "notify"
    ISOLATE = "isolate"
    BLOCK_USER = "block_user"
    BLOCK_IP = "block_ip"
    KILL_SESSION = "kill_session"
    ESCALATE = "escalate"
    LOG = "log"
    CUSTOM = "custom"


@dataclass
class PlaybookStep:
    """Step in incident response playbook."""

    step_id: str
    action: PlaybookAction
    description: str
    automated: bool = False
    parameters: Dict[str, Any] = field(default_factory=dict)
    required: bool = True


@dataclass
class Playbook:
    """Incident response playbook."""

    playbook_id: str
    name: str
    description: str
    trigger_categories: List[AlertCategory]
    trigger_severities: List[AlertSeverity]
    steps: List[PlaybookStep]
    enabled: bool = True


@dataclass
class Incident:
    """Security incident."""

    incident_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    status: IncidentStatus = IncidentStatus.INVESTIGATING

    # Related alerts
    alerts: List[str] = field(default_factory=list)  # Alert IDs

    # Classification
    title: str = ""
    description: str = ""
    severity: AlertSeverity = AlertSeverity.MEDIUM
    category: AlertCategory = AlertCategory.ANOMALY_DETECTED

    # Response
    assigned_to: Optional[str] = None
    playbook_id: Optional[str] = None
    completed_steps: List[str] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)

    # Resolution
    resolution_notes: Optional[str] = None
    root_cause: Optional[str] = None
    lessons_learned: Optional[str] = None

    def add_timeline_entry(self, event: str, details: Optional[str] = None):
        """Add entry to incident timeline."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": event,
            "details": details,
        }
        self.timeline.append(entry)
        self.updated_at = datetime.utcnow()


class IncidentResponseEngine:
    """
    Incident response automation engine.
    """

    # Default playbooks
    DEFAULT_PLAYBOOKS = [
        Playbook(
            playbook_id="pb-prompt-injection",
            name="Prompt Injection Response",
            description="Response playbook for prompt injection attacks",
            trigger_categories=[AlertCategory.PROMPT_INJECTION],
            trigger_severities=[AlertSeverity.CRITICAL, AlertSeverity.HIGH],
            steps=[
                PlaybookStep(
                    step_id="1",
                    action=PlaybookAction.LOG,
                    description="Log full request details for forensics",
                    automated=True,
                ),
                PlaybookStep(
                    step_id="2",
                    action=PlaybookAction.KILL_SESSION,
                    description="Terminate active session",
                    automated=True,
                ),
                PlaybookStep(
                    step_id="3",
                    action=PlaybookAction.NOTIFY,
                    description="Notify security team",
                    automated=True,
                    parameters={"channels": ["slack", "email"]},
                ),
                PlaybookStep(
                    step_id="4",
                    action=PlaybookAction.BLOCK_USER,
                    description="Review and potentially block user",
                    automated=False,
                ),
            ],
        ),
        Playbook(
            playbook_id="pb-data-exfiltration",
            name="Data Exfiltration Response",
            description="Response playbook for data exfiltration attempts",
            trigger_categories=[AlertCategory.DATA_EXFILTRATION],
            trigger_severities=[AlertSeverity.CRITICAL],
            steps=[
                PlaybookStep(
                    step_id="1",
                    action=PlaybookAction.ISOLATE,
                    description="Isolate affected endpoint",
                    automated=True,
                ),
                PlaybookStep(
                    step_id="2",
                    action=PlaybookAction.KILL_SESSION,
                    description="Kill all active sessions for user",
                    automated=True,
                ),
                PlaybookStep(
                    step_id="3",
                    action=PlaybookAction.ESCALATE,
                    description="Escalate to security lead",
                    automated=True,
                    parameters={"escalation_level": "critical"},
                ),
                PlaybookStep(
                    step_id="4",
                    action=PlaybookAction.LOG,
                    description="Capture forensic evidence",
                    automated=True,
                ),
                PlaybookStep(
                    step_id="5",
                    action=PlaybookAction.BLOCK_USER,
                    description="Block user pending investigation",
                    automated=False,
                ),
            ],
        ),
        Playbook(
            playbook_id="pb-compliance-violation",
            name="Compliance Violation Response",
            description="Response playbook for compliance violations",
            trigger_categories=[AlertCategory.COMPLIANCE_VIOLATION],
            trigger_severities=[AlertSeverity.HIGH, AlertSeverity.CRITICAL],
            steps=[
                PlaybookStep(
                    step_id="1",
                    action=PlaybookAction.LOG,
                    description="Log violation details",
                    automated=True,
                ),
                PlaybookStep(
                    step_id="2",
                    action=PlaybookAction.NOTIFY,
                    description="Notify compliance team",
                    automated=True,
                    parameters={"channels": ["email"], "recipients": ["compliance@company.com"]},
                ),
                PlaybookStep(
                    step_id="3",
                    action=PlaybookAction.CUSTOM,
                    description="Generate compliance report",
                    automated=False,
                ),
            ],
        ),
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize incident response engine.

        Args:
            config: Optional configuration
        """
        self.config = config or {}
        self.playbooks: Dict[str, Playbook] = {}
        self.incidents: Dict[str, Incident] = {}

        # Load default playbooks
        for playbook in self.DEFAULT_PLAYBOOKS:
            self.playbooks[playbook.playbook_id] = playbook

    async def create_incident_from_alert(self, alert: Alert) -> Incident:
        """
        Create incident from alert.

        Args:
            alert: Alert to create incident from

        Returns:
            Created incident
        """
        incident = Incident(
            title=f"Incident: {alert.title}",
            description=alert.description,
            severity=alert.severity,
            category=alert.category,
            alerts=[alert.alert_id],
        )

        incident.add_timeline_entry("Incident created", f"From alert {alert.alert_id}")

        # Find matching playbook
        playbook = self._find_playbook(alert)
        if playbook:
            incident.playbook_id = playbook.playbook_id
            incident.add_timeline_entry("Playbook assigned", playbook.name)

            # Execute automated steps
            await self._execute_playbook(incident, playbook, alert)

        self.incidents[incident.incident_id] = incident

        logger.info(f"Created incident {incident.incident_id} from alert {alert.alert_id}")
        return incident

    def _find_playbook(self, alert: Alert) -> Optional[Playbook]:
        """
        Find matching playbook for alert.

        Args:
            alert: Alert to find playbook for

        Returns:
            Matching playbook or None
        """
        for playbook in self.playbooks.values():
            if not playbook.enabled:
                continue

            category_match = alert.category in playbook.trigger_categories
            severity_match = alert.severity in playbook.trigger_severities

            if category_match and severity_match:
                return playbook

        return None

    async def _execute_playbook(self, incident: Incident, playbook: Playbook, alert: Alert):
        """
        Execute playbook steps.

        Args:
            incident: Incident to execute for
            playbook: Playbook to execute
            alert: Associated alert
        """
        for step in playbook.steps:
            if step.automated:
                try:
                    await self._execute_step(incident, step, alert)
                    incident.completed_steps.append(step.step_id)
                    incident.add_timeline_entry(
                        f"Completed step: {step.action.value}",
                        step.description,
                    )
                except Exception as e:
                    logger.error(f"Failed to execute step {step.step_id}: {e}")
                    incident.add_timeline_entry(
                        f"Failed step: {step.action.value}",
                        f"Error: {str(e)}",
                    )

    async def _execute_step(self, incident: Incident, step: PlaybookStep, alert: Alert):
        """
        Execute individual playbook step.

        Args:
            incident: Incident
            step: Step to execute
            alert: Associated alert
        """
        if step.action == PlaybookAction.LOG:
            logger.info(f"Incident {incident.incident_id}: {step.description}")
            logger.info(f"Alert details: {alert.__dict__}")

        elif step.action == PlaybookAction.NOTIFY:
            channels = step.parameters.get("channels", [])
            logger.info(f"Would notify channels: {channels}")
            # In production, would trigger actual notifications

        elif step.action == PlaybookAction.KILL_SESSION:
            session_id = alert.session_id
            logger.info(f"Would kill session: {session_id}")
            # In production, would terminate session

        elif step.action == PlaybookAction.BLOCK_USER:
            user_id = alert.user_id
            logger.info(f"Would block user: {user_id}")
            # In production, would block user

        elif step.action == PlaybookAction.ISOLATE:
            endpoint = alert.endpoint
            logger.info(f"Would isolate endpoint: {endpoint}")
            # In production, would isolate endpoint

        elif step.action == PlaybookAction.ESCALATE:
            level = step.parameters.get("escalation_level", "standard")
            logger.info(f"Would escalate to level: {level}")
            # In production, would trigger escalation

    async def update_incident_status(
        self,
        incident_id: str,
        status: IncidentStatus,
        notes: Optional[str] = None,
    ):
        """
        Update incident status.

        Args:
            incident_id: Incident ID
            status: New status
            notes: Optional notes
        """
        if incident_id in self.incidents:
            incident = self.incidents[incident_id]
            old_status = incident.status
            incident.status = status
            incident.updated_at = datetime.utcnow()

            timeline_details = notes or f"Status changed from {old_status.value} to {status.value}"
            incident.add_timeline_entry("Status updated", timeline_details)

            logger.info(f"Updated incident {incident_id} status to {status.value}")

    async def close_incident(
        self,
        incident_id: str,
        resolution_notes: str,
        root_cause: Optional[str] = None,
        lessons_learned: Optional[str] = None,
    ):
        """
        Close incident.

        Args:
            incident_id: Incident ID
            resolution_notes: Resolution notes
            root_cause: Optional root cause analysis
            lessons_learned: Optional lessons learned
        """
        if incident_id in self.incidents:
            incident = self.incidents[incident_id]
            incident.status = IncidentStatus.CLOSED
            incident.resolution_notes = resolution_notes
            incident.root_cause = root_cause
            incident.lessons_learned = lessons_learned
            incident.updated_at = datetime.utcnow()

            incident.add_timeline_entry("Incident closed", resolution_notes)

            logger.info(f"Closed incident {incident_id}")

    async def get_active_incidents(self) -> List[Incident]:
        """Get all active (non-closed) incidents."""
        return [
            incident
            for incident in self.incidents.values()
            if incident.status != IncidentStatus.CLOSED
        ]

    async def get_incident_statistics(self) -> Dict[str, Any]:
        """Get incident statistics."""
        total = len(self.incidents)
        by_status = {}
        by_severity = {}
        by_category = {}

        for incident in self.incidents.values():
            by_status[incident.status.value] = by_status.get(incident.status.value, 0) + 1
            by_severity[incident.severity.value] = by_severity.get(incident.severity.value, 0) + 1
            by_category[incident.category.value] = by_category.get(incident.category.value, 0) + 1

        return {
            "total_incidents": total,
            "active_incidents": len(await self.get_active_incidents()),
            "by_status": by_status,
            "by_severity": by_severity,
            "by_category": by_category,
        }
