"""
Policy engine for guardrails decision making.
"""
import logging
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PolicyDecision:
    """Policy decision result."""

    action: str  # allow, warn, block
    reason: str
    applied_policies: List[str]
    severity: str
    confidence: float
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class PolicyEngine:
    """
    Policy engine for making guardrails decisions.

    Evaluates threats against configured policies and determines
    appropriate actions (allow, warn, block).
    """

    # Default policy rules
    DEFAULT_POLICIES = {
        "block_critical_threats": {
            "enabled": True,
            "condition": {"severity": "critical"},
            "action": "block",
            "priority": 1,
        },
        "block_high_confidence_injection": {
            "enabled": True,
            "condition": {"type": "prompt_injection", "confidence_min": 0.8},
            "action": "block",
            "priority": 2,
        },
        "block_pii_leakage": {
            "enabled": True,
            "condition": {"type": "pii_leakage"},
            "action": "block",
            "priority": 2,
        },
        "block_high_toxicity": {
            "enabled": True,
            "condition": {"type": "toxic_output", "severity": "high"},
            "action": "block",
            "priority": 2,
        },
        "warn_medium_threats": {
            "enabled": True,
            "condition": {"severity": "medium"},
            "action": "warn",
            "priority": 3,
        },
        "warn_pii_detection": {
            "enabled": True,
            "condition": {"type": "pii"},
            "action": "warn",
            "priority": 4,
        },
    }

    def __init__(self, policies: Optional[Dict[str, Any]] = None):
        """
        Initialize policy engine.

        Args:
            policies: Optional custom policies (uses defaults if not provided)
        """
        self.policies = policies or self.DEFAULT_POLICIES
        self.blocked_count = 0
        self.warned_count = 0
        self.allowed_count = 0
        self.decision_history: List[Dict[str, Any]] = []

    async def evaluate(
        self,
        input_text: str,
        threats: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Evaluate input against policies.

        Args:
            input_text: Input text being evaluated
            threats: List of detected threats
            context: Optional context information

        Returns:
            Policy decision
        """
        context = context or {}

        # No threats = allow
        if not threats:
            decision = PolicyDecision(
                action="allow",
                reason="No threats detected",
                applied_policies=[],
                severity="low",
                confidence=1.0,
            )
            self.allowed_count += 1
            self._record_decision(decision, threats, context)
            return decision

        # Evaluate each policy against threats
        matching_policies = []
        highest_severity = self._get_highest_severity(threats)
        max_confidence = max(t.get("confidence", 0.0) for t in threats)

        for policy_name, policy_config in self._get_sorted_policies():
            if not policy_config.get("enabled", True):
                continue

            # Check if any threat matches this policy
            if self._matches_policy(threats, policy_config["condition"]):
                matching_policies.append(
                    {
                        "name": policy_name,
                        "action": policy_config["action"],
                        "priority": policy_config.get("priority", 999),
                    }
                )

        # Determine action based on highest priority matching policy
        if matching_policies:
            # Sort by priority (lower number = higher priority)
            matching_policies.sort(key=lambda p: p["priority"])
            primary_policy = matching_policies[0]
            action = primary_policy["action"]
            reason = self._build_reason(threats, matching_policies)
        else:
            # No policies matched, default to allow
            action = "allow"
            reason = "No policies triggered"

        # Update counters
        if action == "block":
            self.blocked_count += 1
        elif action == "warn":
            self.warned_count += 1
        else:
            self.allowed_count += 1

        decision = PolicyDecision(
            action=action,
            reason=reason,
            applied_policies=[p["name"] for p in matching_policies],
            severity=highest_severity,
            confidence=max_confidence,
            metadata={"threat_count": len(threats), "context": context},
        )

        self._record_decision(decision, threats, context)
        logger.info(
            f"Policy decision: {action} (reason: {reason}, policies: {len(matching_policies)})"
        )

        return decision

    async def evaluate_output(
        self,
        output_text: str,
        threats: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Evaluate model output against policies.

        Args:
            output_text: Model output text
            threats: List of detected threats
            context: Optional context information

        Returns:
            Policy decision
        """
        # For now, use same logic as input evaluation
        # Can be customized for output-specific policies
        return await self.evaluate(output_text, threats, context)

    def _get_sorted_policies(self) -> List[tuple]:
        """Get policies sorted by priority."""
        return sorted(
            self.policies.items(), key=lambda x: x[1].get("priority", 999)
        )

    def _matches_policy(
        self, threats: List[Dict[str, Any]], condition: Dict[str, Any]
    ) -> bool:
        """
        Check if any threat matches policy condition.

        Args:
            threats: List of threats
            condition: Policy condition

        Returns:
            True if any threat matches
        """
        for threat in threats:
            matches = True

            # Check each condition field
            for key, value in condition.items():
                if key == "severity":
                    # Exact severity match
                    if threat.get("severity") != value:
                        matches = False
                        break
                elif key == "type":
                    # Threat type match
                    if threat.get("type") != value:
                        matches = False
                        break
                elif key == "confidence_min":
                    # Minimum confidence threshold
                    if threat.get("confidence", 0.0) < value:
                        matches = False
                        break
                elif key == "confidence_max":
                    # Maximum confidence threshold
                    if threat.get("confidence", 1.0) > value:
                        matches = False
                        break

            if matches:
                return True

        return False

    def _get_highest_severity(self, threats: List[Dict[str, Any]]) -> str:
        """Get highest severity from threats."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        if not threats:
            return "low"

        severities = [t.get("severity", "low") for t in threats]
        return min(severities, key=lambda s: severity_order.get(s, 4))

    def _build_reason(
        self, threats: List[Dict[str, Any]], matching_policies: List[Dict[str, Any]]
    ) -> str:
        """Build human-readable reason for decision."""
        threat_types = set(t.get("type") for t in threats)
        policy_names = [p["name"] for p in matching_policies[:2]]  # Top 2 policies

        reason_parts = []

        # Add threat summary
        if len(threats) == 1:
            reason_parts.append(f"Detected {threats[0].get('type')} threat")
        else:
            reason_parts.append(
                f"Detected {len(threats)} threats: {', '.join(threat_types)}"
            )

        # Add policy info
        if policy_names:
            reason_parts.append(f"Triggered policies: {', '.join(policy_names)}")

        return ". ".join(reason_parts)

    def _record_decision(
        self,
        decision: PolicyDecision,
        threats: List[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> None:
        """Record decision in history."""
        self.decision_history.append(
            {
                "decision": decision.to_dict(),
                "threats": threats,
                "context": context,
                "timestamp": context.get("timestamp"),
            }
        )

        # Keep only last 1000 decisions
        if len(self.decision_history) > 1000:
            self.decision_history = self.decision_history[-1000:]

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get policy engine statistics.

        Returns:
            Statistics dictionary
        """
        total_decisions = self.blocked_count + self.warned_count + self.allowed_count

        return {
            "total_decisions": total_decisions,
            "blocked_count": self.blocked_count,
            "warned_count": self.warned_count,
            "allowed_count": self.allowed_count,
            "block_rate": (
                self.blocked_count / total_decisions if total_decisions > 0 else 0
            ),
            "warn_rate": (
                self.warned_count / total_decisions if total_decisions > 0 else 0
            ),
            "recent_decisions": [
                d["decision"] for d in self.decision_history[-10:]
            ],
        }

    async def add_custom_policy(
        self,
        name: str,
        condition: Dict[str, Any],
        action: str,
        priority: int = 999,
    ) -> None:
        """
        Add a custom policy.

        Args:
            name: Policy name
            condition: Policy condition dictionary
            action: Action to take (allow, warn, block)
            priority: Policy priority (lower = higher priority)
        """
        self.policies[name] = {
            "enabled": True,
            "condition": condition,
            "action": action,
            "priority": priority,
        }
        logger.info(f"Added custom policy: {name}")

    async def disable_policy(self, name: str) -> None:
        """Disable a policy."""
        if name in self.policies:
            self.policies[name]["enabled"] = False
            logger.info(f"Disabled policy: {name}")

    async def enable_policy(self, name: str) -> None:
        """Enable a policy."""
        if name in self.policies:
            self.policies[name]["enabled"] = True
            logger.info(f"Enabled policy: {name}")
