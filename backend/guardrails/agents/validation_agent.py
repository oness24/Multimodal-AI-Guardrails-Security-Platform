"""
Validation agent for threat validation and coordination.
"""
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ValidationAgent:
    """
    Agent responsible for coordinating threat validation.

    Tracks validation statistics and coordinates between detectors.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize validation agent.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.total_checks = 0
        self.threats_detected = 0
        self.threat_history: List[Dict[str, Any]] = []

    async def validate_threats(
        self, threats: List[Dict[str, Any]], context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate and prioritize detected threats.

        Args:
            threats: List of detected threats
            context: Optional context information

        Returns:
            Validation result with prioritized threats
        """
        self.total_checks += 1

        if threats:
            self.threats_detected += len(threats)

        # Prioritize threats by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        prioritized = sorted(
            threats, key=lambda t: severity_order.get(t.get("severity", "low"), 4)
        )

        # Track threat history
        for threat in threats:
            self.threat_history.append(
                {
                    "type": threat.get("type"),
                    "severity": threat.get("severity"),
                    "confidence": threat.get("confidence"),
                    "timestamp": context.get("timestamp") if context else None,
                }
            )

        # Keep only last 1000 threat records
        if len(self.threat_history) > 1000:
            self.threat_history = self.threat_history[-1000:]

        return {
            "threats": prioritized,
            "total_threats": len(threats),
            "highest_severity": prioritized[0].get("severity") if prioritized else None,
            "recommendation": self._get_recommendation(prioritized),
        }

    def _get_recommendation(self, threats: List[Dict[str, Any]]) -> str:
        """
        Get recommendation based on detected threats.

        Args:
            threats: List of threats

        Returns:
            Recommendation string
        """
        if not threats:
            return "allow"

        highest_severity = threats[0].get("severity", "low")

        if highest_severity == "critical":
            return "block"
        elif highest_severity == "high":
            return "block"
        elif highest_severity == "medium":
            return "warn"
        else:
            return "allow"

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get validation statistics.

        Returns:
            Statistics dictionary
        """
        return {
            "total_checks": self.total_checks,
            "threats_detected": self.threats_detected,
            "detection_rate": (
                self.threats_detected / self.total_checks if self.total_checks > 0 else 0
            ),
            "recent_threats": self.threat_history[-10:],
        }

    def reset_statistics(self) -> None:
        """Reset validation statistics."""
        self.total_checks = 0
        self.threats_detected = 0
        self.threat_history = []
