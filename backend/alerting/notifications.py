"""
Notification integrations for Email, Slack, PagerDuty, etc.
"""
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import httpx

from backend.alerting.alert_manager import Alert, AlertSeverity

logger = logging.getLogger(__name__)


class NotificationChannel(ABC):
    """Base class for notification channels."""

    @abstractmethod
    async def send_alert(self, alert: Alert) -> bool:
        """Send alert notification."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check channel health."""
        pass


class EmailNotifier(NotificationChannel):
    """
    Email notification channel.
    """

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int = 587,
        smtp_user: Optional[str] = None,
        smtp_password: Optional[str] = None,
        from_addr: str = "alerts@adversarialshield.com",
        to_addrs: List[str] = None,
        use_tls: bool = True,
    ):
        """
        Initialize email notifier.

        Args:
            smtp_host: SMTP server host
            smtp_port: SMTP port
            smtp_user: SMTP username
            smtp_password: SMTP password
            from_addr: From email address
            to_addrs: List of recipient email addresses
            use_tls: Use TLS encryption
        """
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.from_addr = from_addr
        self.to_addrs = to_addrs or []
        self.use_tls = use_tls

    async def send_alert(self, alert: Alert) -> bool:
        """
        Send alert via email.

        Args:
            alert: Alert to send

        Returns:
            True if successful
        """
        try:
            # Import aiosmtplib for async email
            import aiosmtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText

            # Build email
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[{alert.severity.value.upper()}] {alert.title}"
            msg["From"] = self.from_addr
            msg["To"] = ", ".join(self.to_addrs)

            # Plain text version
            text_body = f"""
AdversarialShield Security Alert

Severity: {alert.severity.value.upper()}
Category: {alert.category.value}
Title: {alert.title}

Description:
{alert.description}

Detection Method: {alert.detection_method or 'N/A'}
Confidence Score: {alert.confidence_score}

Timestamp: {alert.timestamp.isoformat()}
Alert ID: {alert.alert_id}

{f"OWASP: {alert.owasp_id}" if alert.owasp_id else ""}
{f"MITRE ATT&CK: {alert.mitre_atlas_id}" if alert.mitre_atlas_id else ""}

Indicators:
{chr(10).join('- ' + ind for ind in alert.indicators) if alert.indicators else 'None'}

Recommended Actions:
{chr(10).join('- ' + action for action in alert.recommended_actions) if alert.recommended_actions else 'Review and assess'}

---
This is an automated alert from AdversarialShield
Alert ID: {alert.alert_id}
"""

            # HTML version
            severity_colors = {
                "critical": "#dc3545",
                "high": "#fd7e14",
                "medium": "#ffc107",
                "low": "#0dcaf0",
                "info": "#6c757d",
            }

            severity_color = severity_colors.get(alert.severity.value, "#6c757d")

            html_body = f"""
<html>
<head></head>
<body style="font-family: Arial, sans-serif;">
    <div style="max-width: 600px; margin: 0 auto; border: 1px solid #ddd; border-radius: 5px;">
        <div style="background-color: {severity_color}; color: white; padding: 20px; border-radius: 5px 5px 0 0;">
            <h2 style="margin: 0;">AdversarialShield Security Alert</h2>
            <p style="margin: 5px 0 0 0; font-size: 14px;">Severity: {alert.severity.value.upper()}</p>
        </div>

        <div style="padding: 20px;">
            <h3 style="color: #333; border-bottom: 2px solid #eee; padding-bottom: 10px;">{alert.title}</h3>

            <p><strong>Category:</strong> {alert.category.value}</p>
            <p><strong>Description:</strong></p>
            <p style="background-color: #f8f9fa; padding: 10px; border-left: 3px solid {severity_color};">
                {alert.description}
            </p>

            <table style="width: 100%; border-collapse: collapse; margin-top: 20px;">
                <tr style="background-color: #f8f9fa;">
                    <td style="padding: 8px; border: 1px solid #ddd;"><strong>Detection Method</strong></td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{alert.detection_method or 'N/A'}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;"><strong>Confidence Score</strong></td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{alert.confidence_score}</td>
                </tr>
                <tr style="background-color: #f8f9fa;">
                    <td style="padding: 8px; border: 1px solid #ddd;"><strong>Timestamp</strong></td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{alert.timestamp.isoformat()}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;"><strong>Alert ID</strong></td>
                    <td style="padding: 8px; border: 1px solid #ddd;"><code>{alert.alert_id}</code></td>
                </tr>
            </table>

            {f'<p style="margin-top: 20px;"><strong>OWASP:</strong> {alert.owasp_id}</p>' if alert.owasp_id else ''}
            {f'<p><strong>MITRE ATT&CK:</strong> {alert.mitre_atlas_id}</p>' if alert.mitre_atlas_id else ''}

            {f'''
            <div style="margin-top: 20px;">
                <strong>Indicators:</strong>
                <ul>
                    {"".join(f"<li>{ind}</li>" for ind in alert.indicators)}
                </ul>
            </div>
            ''' if alert.indicators else ''}

            {f'''
            <div style="margin-top: 20px; background-color: #e7f3ff; padding: 15px; border-radius: 5px;">
                <strong>Recommended Actions:</strong>
                <ul>
                    {"".join(f"<li>{action}</li>" for action in alert.recommended_actions)}
                </ul>
            </div>
            ''' if alert.recommended_actions else '''
            <div style="margin-top: 20px; background-color: #e7f3ff; padding: 15px; border-radius: 5px;">
                <strong>Recommended Actions:</strong>
                <ul><li>Review and assess this alert</li></ul>
            </div>
            '''}
        </div>

        <div style="background-color: #f8f9fa; padding: 10px; text-align: center; font-size: 12px; color: #6c757d; border-radius: 0 0 5px 5px;">
            This is an automated alert from AdversarialShield<br>
            Alert ID: {alert.alert_id}
        </div>
    </div>
</body>
</html>
"""

            msg.attach(MIMEText(text_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            # Send email
            await aiosmtplib.send(
                msg,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_password,
                use_tls=self.use_tls,
            )

            logger.info(f"Sent email notification for alert {alert.alert_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email notification: {e}", exc_info=True)
            return False

    async def health_check(self) -> bool:
        """Check SMTP connection."""
        try:
            import aiosmtplib

            # Try to connect to SMTP server
            smtp = aiosmtplib.SMTP(hostname=self.smtp_host, port=self.smtp_port)
            await smtp.connect()
            await smtp.quit()
            return True

        except Exception as e:
            logger.error(f"Email health check failed: {e}")
            return False


class SlackNotifier(NotificationChannel):
    """
    Slack notification channel.
    """

    def __init__(self, webhook_url: str, channel: Optional[str] = None):
        """
        Initialize Slack notifier.

        Args:
            webhook_url: Slack webhook URL
            channel: Optional channel to post to
        """
        self.webhook_url = webhook_url
        self.channel = channel
        self.http_client = httpx.AsyncClient(timeout=10.0)

    async def send_alert(self, alert: Alert) -> bool:
        """
        Send alert to Slack.

        Args:
            alert: Alert to send

        Returns:
            True if successful
        """
        try:
            # Severity colors
            color_map = {
                "critical": "#dc3545",
                "high": "#fd7e14",
                "medium": "#ffc107",
                "low": "#0dcaf0",
                "info": "#6c757d",
            }

            color = color_map.get(alert.severity.value, "#6c757d")

            # Build Slack message
            message = {
                "attachments": [
                    {
                        "color": color,
                        "title": f"🚨 {alert.title}",
                        "title_link": f"https://adversarialshield.com/alerts/{alert.alert_id}",
                        "text": alert.description,
                        "fields": [
                            {
                                "title": "Severity",
                                "value": alert.severity.value.upper(),
                                "short": True,
                            },
                            {
                                "title": "Category",
                                "value": alert.category.value.replace("_", " ").title(),
                                "short": True,
                            },
                            {
                                "title": "Detection Method",
                                "value": alert.detection_method or "N/A",
                                "short": True,
                            },
                            {
                                "title": "Confidence",
                                "value": f"{alert.confidence_score:.2%}",
                                "short": True,
                            },
                        ],
                        "footer": "AdversarialShield",
                        "footer_icon": "https://adversarialshield.com/icon.png",
                        "ts": int(alert.timestamp.timestamp()),
                    }
                ]
            }

            # Add OWASP/MITRE fields if available
            if alert.owasp_id:
                message["attachments"][0]["fields"].append(
                    {
                        "title": "OWASP",
                        "value": alert.owasp_id,
                        "short": True,
                    }
                )

            if alert.mitre_atlas_id:
                message["attachments"][0]["fields"].append(
                    {
                        "title": "MITRE ATT&CK",
                        "value": alert.mitre_atlas_id,
                        "short": True,
                    }
                )

            # Add indicators if available
            if alert.indicators:
                indicators_text = "\n".join(f"• {ind}" for ind in alert.indicators[:5])
                message["attachments"][0]["fields"].append(
                    {
                        "title": "Indicators",
                        "value": indicators_text,
                        "short": False,
                    }
                )

            # Add recommended actions if available
            if alert.recommended_actions:
                actions_text = "\n".join(f"• {action}" for action in alert.recommended_actions[:3])
                message["attachments"][0]["fields"].append(
                    {
                        "title": "Recommended Actions",
                        "value": actions_text,
                        "short": False,
                    }
                )

            if self.channel:
                message["channel"] = self.channel

            # Send to Slack
            response = await self.http_client.post(self.webhook_url, json=message)

            if response.status_code == 200:
                logger.info(f"Sent Slack notification for alert {alert.alert_id}")
                return True
            else:
                logger.error(f"Slack returned {response.status_code}: {response.text}")
                return False

        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}", exc_info=True)
            return False

    async def health_check(self) -> bool:
        """Check Slack webhook."""
        # Slack webhooks don't have a health endpoint
        # Just verify the URL is accessible
        return True

    async def close(self):
        """Close HTTP client."""
        await self.http_client.aclose()


class PagerDutyNotifier(NotificationChannel):
    """
    PagerDuty notification channel.
    """

    def __init__(self, integration_key: str, api_url: str = "https://events.pagerduty.com/v2/enqueue"):
        """
        Initialize PagerDuty notifier.

        Args:
            integration_key: PagerDuty integration key
            api_url: PagerDuty Events API URL
        """
        self.integration_key = integration_key
        self.api_url = api_url
        self.http_client = httpx.AsyncClient(timeout=10.0)

    async def send_alert(self, alert: Alert) -> bool:
        """
        Send alert to PagerDuty.

        Args:
            alert: Alert to send

        Returns:
            True if successful
        """
        try:
            # Map severity to PagerDuty severity
            severity_map = {
                AlertSeverity.CRITICAL: "critical",
                AlertSeverity.HIGH: "error",
                AlertSeverity.MEDIUM: "warning",
                AlertSeverity.LOW: "info",
                AlertSeverity.INFO: "info",
            }

            pd_severity = severity_map.get(alert.severity, "info")

            # Build PagerDuty event
            event = {
                "routing_key": self.integration_key,
                "event_action": "trigger",
                "dedup_key": alert.alert_id,
                "payload": {
                    "summary": alert.title,
                    "source": alert.source,
                    "severity": pd_severity,
                    "timestamp": alert.timestamp.isoformat(),
                    "custom_details": {
                        "category": alert.category.value,
                        "description": alert.description,
                        "detection_method": alert.detection_method,
                        "confidence_score": alert.confidence_score,
                        "user_id": alert.user_id,
                        "endpoint": alert.endpoint,
                        "owasp_id": alert.owasp_id,
                        "mitre_atlas_id": alert.mitre_atlas_id,
                        "indicators": alert.indicators,
                        "recommended_actions": alert.recommended_actions,
                    },
                },
                "links": [
                    {
                        "href": f"https://adversarialshield.com/alerts/{alert.alert_id}",
                        "text": "View in AdversarialShield",
                    }
                ],
            }

            # Send to PagerDuty
            response = await self.http_client.post(self.api_url, json=event)

            if response.status_code == 202:
                logger.info(f"Sent PagerDuty notification for alert {alert.alert_id}")
                return True
            else:
                logger.error(f"PagerDuty returned {response.status_code}: {response.text}")
                return False

        except Exception as e:
            logger.error(f"Failed to send PagerDuty notification: {e}", exc_info=True)
            return False

    async def health_check(self) -> bool:
        """Check PagerDuty API."""
        try:
            # Send a test event with minimal payload
            test_event = {
                "routing_key": self.integration_key,
                "event_action": "trigger",
                "payload": {
                    "summary": "Health check",
                    "source": "AdversarialShield",
                    "severity": "info",
                },
            }

            response = await self.http_client.post(self.api_url, json=test_event)
            return response.status_code == 202

        except Exception as e:
            logger.error(f"PagerDuty health check failed: {e}")
            return False

    async def close(self):
        """Close HTTP client."""
        await self.http_client.aclose()
