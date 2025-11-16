"""
SIEM connectors for Wazuh, Splunk, and other platforms.
"""
import asyncio
import json
import logging
import socket
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Optional

import httpx

from backend.alerting.alert_manager import Alert, AlertSeverity

logger = logging.getLogger(__name__)


class AlertFormatter(ABC):
    """Base class for alert formatters."""

    @abstractmethod
    def format_alert(self, alert: Alert) -> str:
        """Format alert to specific format."""
        pass


class CEFFormatter(AlertFormatter):
    """
    Common Event Format (CEF) formatter.

    Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """

    def __init__(self, vendor: str = "AdversarialShield", product: str = "LLM Security"):
        """
        Initialize CEF formatter.

        Args:
            vendor: Vendor name
            product: Product name
        """
        self.vendor = vendor
        self.product = product
        self.version = "1.0"

    def format_alert(self, alert: Alert) -> str:
        """
        Format alert to CEF.

        Args:
            alert: Alert to format

        Returns:
            CEF-formatted alert string
        """
        # CEF severity mapping (0-10)
        severity_map = {
            AlertSeverity.INFO: 2,
            AlertSeverity.LOW: 4,
            AlertSeverity.MEDIUM: 6,
            AlertSeverity.HIGH: 8,
            AlertSeverity.CRITICAL: 10,
        }

        cef_severity = severity_map.get(alert.severity, 5)

        # Build extension fields
        extensions = []

        if alert.user_id:
            extensions.append(f"suser={alert.user_id}")

        if alert.endpoint:
            extensions.append(f"request={alert.endpoint}")

        if alert.source:
            extensions.append(f"shost={alert.source}")

        if alert.owasp_id:
            extensions.append(f"cs1Label=OWASP_ID cs1={alert.owasp_id}")

        if alert.mitre_atlas_id:
            extensions.append(f"cs2Label=MITRE_ATLAS cs2={alert.mitre_atlas_id}")

        if alert.detection_method:
            extensions.append(f"cs3Label=Detection cs3={alert.detection_method}")

        extensions.append(f"cn1Label=Confidence cn1={alert.confidence_score}")
        extensions.append(f"deviceCustomDate1Label=Timestamp deviceCustomDate1={alert.timestamp.isoformat()}")

        if alert.indicators:
            indicators_str = ",".join(alert.indicators[:5])  # Limit to 5
            extensions.append(f"cs4Label=Indicators cs4={indicators_str}")

        extension_str = " ".join(extensions)

        # Build CEF message
        cef_message = (
            f"CEF:0|{self.vendor}|{self.product}|{self.version}|"
            f"{alert.category.value}|{alert.title}|{cef_severity}|{extension_str}"
        )

        return cef_message


class LEEFFormatter(AlertFormatter):
    """
    Log Event Extended Format (LEEF) formatter.

    Format: LEEF:Version|Vendor|Product|Version|EventID|Field1=Value1<tab>Field2=Value2
    """

    def __init__(self, vendor: str = "AdversarialShield", product: str = "LLM Security"):
        """
        Initialize LEEF formatter.

        Args:
            vendor: Vendor name
            product: Product name
        """
        self.vendor = vendor
        self.product = product
        self.version = "2.0"

    def format_alert(self, alert: Alert) -> str:
        """
        Format alert to LEEF.

        Args:
            alert: Alert to format

        Returns:
            LEEF-formatted alert string
        """
        # Build fields
        fields = []

        fields.append(f"severity={alert.severity.value}")
        fields.append(f"category={alert.category.value}")
        fields.append(f"title={alert.title}")
        fields.append(f"description={alert.description}")
        fields.append(f"timestamp={alert.timestamp.isoformat()}")

        if alert.user_id:
            fields.append(f"user={alert.user_id}")

        if alert.session_id:
            fields.append(f"session={alert.session_id}")

        if alert.endpoint:
            fields.append(f"endpoint={alert.endpoint}")

        if alert.owasp_id:
            fields.append(f"owasp={alert.owasp_id}")

        if alert.detection_method:
            fields.append(f"detection={alert.detection_method}")

        fields.append(f"confidence={alert.confidence_score}")

        if alert.indicators:
            fields.append(f"indicators={','.join(alert.indicators[:5])}")

        fields_str = "\t".join(fields)

        # Build LEEF message
        leef_message = (
            f"LEEF:{self.version}|{self.vendor}|{self.product}|1.0|"
            f"{alert.alert_id}|{fields_str}"
        )

        return leef_message


class SIEMConnector(ABC):
    """Base class for SIEM connectors."""

    @abstractmethod
    async def send_alert(self, alert: Alert) -> bool:
        """Send alert to SIEM."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check SIEM connection health."""
        pass


class WazuhConnector(SIEMConnector):
    """
    Wazuh SIEM connector.

    Sends alerts to Wazuh via syslog or API.
    """

    def __init__(
        self,
        host: str,
        port: int = 514,
        protocol: str = "udp",
        api_url: Optional[str] = None,
        api_token: Optional[str] = None,
    ):
        """
        Initialize Wazuh connector.

        Args:
            host: Wazuh server host
            port: Syslog port (default 514)
            protocol: Protocol (udp or tcp)
            api_url: Optional Wazuh API URL
            api_token: Optional Wazuh API token
        """
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.api_url = api_url
        self.api_token = api_token
        self.formatter = CEFFormatter()

    async def send_alert(self, alert: Alert) -> bool:
        """
        Send alert to Wazuh.

        Args:
            alert: Alert to send

        Returns:
            True if successful
        """
        try:
            # Format alert as CEF
            cef_message = self.formatter.format_alert(alert)

            # Send via syslog
            if self.protocol == "udp":
                await self._send_udp(cef_message)
            elif self.protocol == "tcp":
                await self._send_tcp(cef_message)
            else:
                logger.error(f"Unsupported protocol: {self.protocol}")
                return False

            logger.info(f"Sent alert {alert.alert_id} to Wazuh via {self.protocol}")
            return True

        except Exception as e:
            logger.error(f"Failed to send alert to Wazuh: {e}", exc_info=True)
            return False

    async def _send_udp(self, message: str):
        """Send message via UDP syslog."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Prepend syslog header
            syslog_message = f"<134>{message}\n"  # Facility 16 (local0), Severity 6 (info)
            sock.sendto(syslog_message.encode(), (self.host, self.port))
        finally:
            sock.close()

    async def _send_tcp(self, message: str):
        """Send message via TCP syslog."""
        reader, writer = await asyncio.open_connection(self.host, self.port)
        try:
            syslog_message = f"<134>{message}\n"
            writer.write(syslog_message.encode())
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def health_check(self) -> bool:
        """
        Check Wazuh connection.

        Returns:
            True if healthy
        """
        try:
            # Try to open connection
            if self.protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.close()
                return True
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port), timeout=5.0
                )
                writer.close()
                await writer.wait_closed()
                return True
        except Exception as e:
            logger.error(f"Wazuh health check failed: {e}")
            return False


class SplunkConnector(SIEMConnector):
    """
    Splunk SIEM connector.

    Sends alerts to Splunk via HTTP Event Collector (HEC).
    """

    def __init__(
        self,
        hec_url: str,
        hec_token: str,
        index: str = "main",
        source: str = "adversarial_shield",
        sourcetype: str = "llm_security_alert",
    ):
        """
        Initialize Splunk connector.

        Args:
            hec_url: Splunk HEC URL (e.g., https://splunk:8088/services/collector)
            hec_token: HEC token
            index: Splunk index
            source: Event source
            sourcetype: Event sourcetype
        """
        self.hec_url = hec_url
        self.hec_token = hec_token
        self.index = index
        self.source = source
        self.sourcetype = sourcetype
        self.http_client = httpx.AsyncClient(timeout=10.0, verify=False)

    async def send_alert(self, alert: Alert) -> bool:
        """
        Send alert to Splunk HEC.

        Args:
            alert: Alert to send

        Returns:
            True if successful
        """
        try:
            # Build Splunk event
            event = {
                "time": alert.timestamp.timestamp(),
                "host": alert.source,
                "source": self.source,
                "sourcetype": self.sourcetype,
                "index": self.index,
                "event": {
                    "alert_id": alert.alert_id,
                    "severity": alert.severity.value,
                    "category": alert.category.value,
                    "title": alert.title,
                    "description": alert.description,
                    "status": alert.status.value,
                    "detection_method": alert.detection_method,
                    "confidence_score": alert.confidence_score,
                    "user_id": alert.user_id,
                    "session_id": alert.session_id,
                    "endpoint": alert.endpoint,
                    "owasp_id": alert.owasp_id,
                    "mitre_atlas_id": alert.mitre_atlas_id,
                    "cwe_id": alert.cwe_id,
                    "indicators": alert.indicators,
                    "evidence": alert.evidence,
                    "recommended_actions": alert.recommended_actions,
                    "tags": alert.tags,
                },
            }

            # Send to HEC
            headers = {
                "Authorization": f"Splunk {self.hec_token}",
                "Content-Type": "application/json",
            }

            response = await self.http_client.post(
                self.hec_url, json=event, headers=headers
            )

            if response.status_code == 200:
                logger.info(f"Sent alert {alert.alert_id} to Splunk")
                return True
            else:
                logger.error(
                    f"Splunk HEC returned {response.status_code}: {response.text}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to send alert to Splunk: {e}", exc_info=True)
            return False

    async def health_check(self) -> bool:
        """
        Check Splunk HEC health.

        Returns:
            True if healthy
        """
        try:
            headers = {
                "Authorization": f"Splunk {self.hec_token}",
            }

            # Try to access HEC health endpoint
            health_url = self.hec_url.replace("/collector", "/health")
            response = await self.http_client.get(health_url, headers=headers)

            return response.status_code == 200

        except Exception as e:
            logger.error(f"Splunk health check failed: {e}")
            return False

    async def close(self):
        """Close HTTP client."""
        await self.http_client.aclose()


class GenericSyslogConnector(SIEMConnector):
    """
    Generic syslog connector for any SIEM that accepts syslog.
    """

    def __init__(
        self,
        host: str,
        port: int = 514,
        protocol: str = "udp",
        format_type: str = "cef",
    ):
        """
        Initialize generic syslog connector.

        Args:
            host: Syslog server host
            port: Syslog port
            protocol: Protocol (udp or tcp)
            format_type: Alert format (cef or leef)
        """
        self.host = host
        self.port = port
        self.protocol = protocol.lower()

        if format_type.lower() == "cef":
            self.formatter = CEFFormatter()
        elif format_type.lower() == "leef":
            self.formatter = LEEFFormatter()
        else:
            raise ValueError(f"Unsupported format type: {format_type}")

    async def send_alert(self, alert: Alert) -> bool:
        """Send alert via syslog."""
        try:
            formatted_message = self.formatter.format_alert(alert)

            if self.protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                syslog_message = f"<134>{formatted_message}\n"
                sock.sendto(syslog_message.encode(), (self.host, self.port))
                sock.close()
            else:
                reader, writer = await asyncio.open_connection(self.host, self.port)
                syslog_message = f"<134>{formatted_message}\n"
                writer.write(syslog_message.encode())
                await writer.drain()
                writer.close()
                await writer.wait_closed()

            logger.info(f"Sent alert {alert.alert_id} to syslog at {self.host}:{self.port}")
            return True

        except Exception as e:
            logger.error(f"Failed to send alert to syslog: {e}", exc_info=True)
            return False

    async def health_check(self) -> bool:
        """Check syslog connection."""
        try:
            if self.protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.close()
                return True
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port), timeout=5.0
                )
                writer.close()
                await writer.wait_closed()
                return True
        except Exception as e:
            logger.error(f"Syslog health check failed: {e}")
            return False
