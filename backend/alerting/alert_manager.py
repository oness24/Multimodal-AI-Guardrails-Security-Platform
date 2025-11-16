"""
Alert management and correlation system.
"""
import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

logger = logging.getLogger(__name__)


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    """Alert status."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class AlertCategory(str, Enum):
    """Alert categories."""

    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    CONTEXT_LEAKAGE = "context_leakage"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    COMPLIANCE_VIOLATION = "compliance_violation"
    VULNERABILITY_DETECTED = "vulnerability_detected"
    ANOMALY_DETECTED = "anomaly_detected"
    POLICY_VIOLATION = "policy_violation"


@dataclass
class Alert:
    """Security alert."""

    alert_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    severity: AlertSeverity = AlertSeverity.INFO
    category: AlertCategory = AlertCategory.ANOMALY_DETECTED
    title: str = ""
    description: str = ""
    source: str = "AdversarialShield"
    status: AlertStatus = AlertStatus.OPEN

    # Detection details
    detection_method: Optional[str] = None
    confidence_score: float = 1.0

    # Context
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    endpoint: Optional[str] = None

    # Evidence
    evidence: Dict[str, Any] = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)

    # OWASP/MITRE mapping
    owasp_id: Optional[str] = None
    mitre_atlas_id: Optional[str] = None
    cwe_id: Optional[str] = None

    # Incident response
    recommended_actions: List[str] = field(default_factory=list)
    assigned_to: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    # Metadata
    tags: List[str] = field(default_factory=list)
    related_alerts: List[str] = field(default_factory=list)
    suppressed: bool = False

    def get_fingerprint(self) -> str:
        """Generate unique fingerprint for deduplication."""
        components = [
            self.category.value,
            self.title,
            self.source,
            self.endpoint or "",
            str(sorted(self.indicators)),
        ]
        fingerprint_str = "|".join(components)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()


@dataclass
class AlertRule:
    """Alert rule definition."""

    rule_id: str
    name: str
    severity: AlertSeverity
    category: AlertCategory
    enabled: bool = True

    # Conditions
    conditions: Dict[str, Any] = field(default_factory=dict)
    threshold: Optional[int] = None
    time_window_seconds: Optional[int] = None

    # Actions
    notify_channels: List[str] = field(default_factory=list)
    auto_suppress: bool = False
    suppress_duration_seconds: int = 3600


class AlertCorrelationEngine:
    """
    Correlates and aggregates alerts to reduce noise.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize correlation engine.

        Args:
            config: Optional configuration
        """
        self.config = config or {}
        self.alert_history: Dict[str, Alert] = {}
        self.fingerprint_cache: Dict[str, List[str]] = {}
        self.correlation_window = self.config.get("correlation_window_seconds", 300)

    async def process_alert(self, alert: Alert) -> Optional[Alert]:
        """
        Process alert through correlation engine.

        Args:
            alert: Alert to process

        Returns:
            Processed alert or None if suppressed
        """
        # Generate fingerprint for deduplication
        fingerprint = alert.get_fingerprint()

        # Check for duplicates in recent history
        if fingerprint in self.fingerprint_cache:
            recent_alerts = self.fingerprint_cache[fingerprint]

            # Check if any recent alert is within correlation window
            current_time = time.time()
            for alert_id in recent_alerts[:]:
                if alert_id in self.alert_history:
                    existing_alert = self.alert_history[alert_id]
                    alert_age = current_time - existing_alert.timestamp.timestamp()

                    if alert_age < self.correlation_window:
                        # Duplicate alert within window - correlate
                        logger.info(f"Correlating duplicate alert: {fingerprint[:8]}")
                        existing_alert.related_alerts.append(alert.alert_id)
                        return None  # Suppress duplicate
                    else:
                        # Alert too old, remove from cache
                        recent_alerts.remove(alert_id)

        # Store alert
        self.alert_history[alert.alert_id] = alert

        # Update fingerprint cache
        if fingerprint not in self.fingerprint_cache:
            self.fingerprint_cache[fingerprint] = []
        self.fingerprint_cache[fingerprint].append(alert.alert_id)

        # Clean up old alerts
        await self._cleanup_old_alerts()

        return alert

    async def _cleanup_old_alerts(self):
        """Remove alerts older than correlation window."""
        current_time = time.time()
        cutoff_time = current_time - (self.correlation_window * 2)

        alerts_to_remove = []
        for alert_id, alert in self.alert_history.items():
            if alert.timestamp.timestamp() < cutoff_time:
                alerts_to_remove.append(alert_id)

        for alert_id in alerts_to_remove:
            del self.alert_history[alert_id]

    async def correlate_alerts(
        self, alerts: List[Alert], correlation_key: str = "session_id"
    ) -> List[List[Alert]]:
        """
        Correlate alerts by specified key.

        Args:
            alerts: List of alerts
            correlation_key: Key to correlate by (session_id, user_id, endpoint)

        Returns:
            List of correlated alert groups
        """
        correlation_groups: Dict[str, List[Alert]] = {}

        for alert in alerts:
            key_value = getattr(alert, correlation_key, None)
            if key_value:
                if key_value not in correlation_groups:
                    correlation_groups[key_value] = []
                correlation_groups[key_value].append(alert)

        return list(correlation_groups.values())


class AlertAggregator:
    """
    Aggregates alerts for batch processing and reporting.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize aggregator.

        Args:
            config: Optional configuration
        """
        self.config = config or {}
        self.aggregation_window = self.config.get("aggregation_window_seconds", 60)
        self.pending_alerts: List[Alert] = []
        self.last_flush_time = time.time()

    async def add_alert(self, alert: Alert):
        """
        Add alert to aggregation buffer.

        Args:
            alert: Alert to add
        """
        self.pending_alerts.append(alert)

        # Auto-flush if window elapsed
        if time.time() - self.last_flush_time >= self.aggregation_window:
            await self.flush()

    async def flush(self) -> List[Alert]:
        """
        Flush pending alerts.

        Returns:
            List of pending alerts
        """
        alerts = self.pending_alerts.copy()
        self.pending_alerts.clear()
        self.last_flush_time = time.time()

        logger.info(f"Flushed {len(alerts)} alerts from aggregation buffer")
        return alerts

    async def get_aggregated_summary(self) -> Dict[str, Any]:
        """
        Get summary of aggregated alerts.

        Returns:
            Summary statistics
        """
        if not self.pending_alerts:
            return {
                "total_alerts": 0,
                "by_severity": {},
                "by_category": {},
                "by_status": {},
            }

        by_severity = {}
        by_category = {}
        by_status = {}

        for alert in self.pending_alerts:
            # Count by severity
            severity = alert.severity.value
            by_severity[severity] = by_severity.get(severity, 0) + 1

            # Count by category
            category = alert.category.value
            by_category[category] = by_category.get(category, 0) + 1

            # Count by status
            status = alert.status.value
            by_status[status] = by_status.get(status, 0) + 1

        return {
            "total_alerts": len(self.pending_alerts),
            "by_severity": by_severity,
            "by_category": by_category,
            "by_status": by_status,
            "oldest_alert": min(a.timestamp for a in self.pending_alerts).isoformat(),
            "newest_alert": max(a.timestamp for a in self.pending_alerts).isoformat(),
        }


class AlertManager:
    """
    Central alert management system.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize alert manager.

        Args:
            config: Optional configuration
        """
        self.config = config or {}
        self.correlation_engine = AlertCorrelationEngine(config)
        self.aggregator = AlertAggregator(config)
        self.alert_rules: Dict[str, AlertRule] = {}
        self.alerts: Dict[str, Alert] = {}

        # Notification channels (to be injected)
        self.notification_channels: Dict[str, Any] = {}

    async def create_alert(
        self,
        severity: AlertSeverity,
        category: AlertCategory,
        title: str,
        description: str,
        **kwargs,
    ) -> Alert:
        """
        Create new alert.

        Args:
            severity: Alert severity
            category: Alert category
            title: Alert title
            description: Alert description
            **kwargs: Additional alert fields

        Returns:
            Created alert
        """
        alert = Alert(
            severity=severity,
            category=category,
            title=title,
            description=description,
            **kwargs,
        )

        # Process through correlation engine
        processed_alert = await self.correlation_engine.process_alert(alert)

        if processed_alert:
            # Store alert
            self.alerts[alert.alert_id] = alert

            # Add to aggregation buffer
            await self.aggregator.add_alert(alert)

            # Apply rules
            await self._apply_rules(alert)

            logger.info(
                f"Created alert: {alert.alert_id} - {alert.severity.value} - {alert.title}"
            )

            return alert
        else:
            logger.info(f"Alert suppressed due to correlation: {alert.title}")
            return None

    async def update_alert_status(
        self, alert_id: str, status: AlertStatus, notes: Optional[str] = None
    ):
        """
        Update alert status.

        Args:
            alert_id: Alert ID
            status: New status
            notes: Optional notes
        """
        if alert_id in self.alerts:
            alert = self.alerts[alert_id]
            alert.status = status

            if notes:
                alert.notes.append(f"[{datetime.utcnow().isoformat()}] {notes}")

            logger.info(f"Updated alert {alert_id} status to {status.value}")

    async def get_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        category: Optional[AlertCategory] = None,
        status: Optional[AlertStatus] = None,
        limit: int = 100,
    ) -> List[Alert]:
        """
        Get alerts with optional filtering.

        Args:
            severity: Filter by severity
            category: Filter by category
            status: Filter by status
            limit: Maximum alerts to return

        Returns:
            List of alerts
        """
        filtered_alerts = list(self.alerts.values())

        if severity:
            filtered_alerts = [a for a in filtered_alerts if a.severity == severity]

        if category:
            filtered_alerts = [a for a in filtered_alerts if a.category == category]

        if status:
            filtered_alerts = [a for a in filtered_alerts if a.status == status]

        # Sort by timestamp (newest first)
        filtered_alerts.sort(key=lambda a: a.timestamp, reverse=True)

        return filtered_alerts[:limit]

    async def _apply_rules(self, alert: Alert):
        """
        Apply alert rules.

        Args:
            alert: Alert to apply rules to
        """
        for rule in self.alert_rules.values():
            if not rule.enabled:
                continue

            # Check if rule matches alert
            if rule.category == alert.category and rule.severity == alert.severity:
                # Apply rule actions
                if rule.auto_suppress:
                    alert.suppressed = True
                    logger.info(f"Auto-suppressed alert {alert.alert_id} by rule {rule.rule_id}")

                # Notify channels
                await self._notify_channels(alert, rule.notify_channels)

    async def _notify_channels(self, alert: Alert, channels: List[str]):
        """
        Notify specified channels.

        Args:
            alert: Alert to notify about
            channels: List of channel names
        """
        for channel_name in channels:
            if channel_name in self.notification_channels:
                channel = self.notification_channels[channel_name]
                try:
                    await channel.send_alert(alert)
                except Exception as e:
                    logger.error(f"Failed to notify channel {channel_name}: {e}")

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get alert statistics.

        Returns:
            Statistics dictionary
        """
        total = len(self.alerts)
        by_severity = {}
        by_category = {}
        by_status = {}

        for alert in self.alerts.values():
            by_severity[alert.severity.value] = by_severity.get(alert.severity.value, 0) + 1
            by_category[alert.category.value] = by_category.get(alert.category.value, 0) + 1
            by_status[alert.status.value] = by_status.get(alert.status.value, 0) + 1

        return {
            "total_alerts": total,
            "by_severity": by_severity,
            "by_category": by_category,
            "by_status": by_status,
            "correlation_cache_size": len(self.correlation_engine.fingerprint_cache),
            "pending_aggregation": len(self.aggregator.pending_alerts),
        }
