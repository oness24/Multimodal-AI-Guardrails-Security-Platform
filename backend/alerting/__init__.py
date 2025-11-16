"""
Alerting module for SIEM integration and notifications.
"""
from backend.alerting.alert_manager import (
    Alert,
    AlertAggregator,
    AlertCategory,
    AlertCorrelationEngine,
    AlertManager,
    AlertRule,
    AlertSeverity,
    AlertStatus,
)
from backend.alerting.notifications import (
    EmailNotifier,
    NotificationChannel,
    PagerDutyNotifier,
    SlackNotifier,
)
from backend.alerting.siem_connectors import (
    CEFFormatter,
    GenericSyslogConnector,
    LEEFFormatter,
    SIEMConnector,
    SplunkConnector,
    WazuhConnector,
)

__all__ = [
    # Alert management
    "Alert",
    "AlertSeverity",
    "AlertStatus",
    "AlertCategory",
    "AlertRule",
    "AlertManager",
    "AlertCorrelationEngine",
    "AlertAggregator",
    # SIEM connectors
    "SIEMConnector",
    "WazuhConnector",
    "SplunkConnector",
    "GenericSyslogConnector",
    "CEFFormatter",
    "LEEFFormatter",
    # Notifications
    "NotificationChannel",
    "EmailNotifier",
    "SlackNotifier",
    "PagerDutyNotifier",
]
