"""
Enforcement agent for executing policy decisions.
"""
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class EnforcementAction:
    """Action taken by enforcement agent."""

    action_type: str  # block, modify, warn, allow
    original_content: str
    modified_content: Optional[str]
    reason: str
    timestamp: datetime
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class EnforcementResult:
    """Result from enforcement."""

    allowed: bool
    content: str
    action: EnforcementAction
    warnings: Optional[List[str]] = None


class EnforcementAgent:
    """
    Agent responsible for enforcing policy decisions.

    Executes actions based on policy engine decisions:
    - Block: Prevent content from passing
    - Modify: Alter content to make it safe
    - Warn: Allow but log warning
    - Allow: Pass through unchanged
    """

    # Default blocked message templates
    BLOCKED_MESSAGES = {
        "prompt_injection": "Your request was blocked due to potential prompt injection.",
        "pii": "Your request contains personal information that cannot be processed.",
        "toxicity": "Your request contains inappropriate content.",
        "unauthorized": "You are not authorized to access this information.",
        "rate_limit": "Rate limit exceeded. Please try again later.",
        "default": "Your request could not be processed due to safety concerns.",
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize enforcement agent.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.strict_mode = self.config.get("strict_mode", False)
        self.custom_blocked_messages = self.config.get("blocked_messages", {})
        self.allow_modifications = self.config.get("allow_modifications", True)

        # Statistics
        self.total_enforcements = 0
        self.blocks = 0
        self.modifications = 0
        self.warnings = 0
        self.allows = 0
        self.enforcement_history: List[EnforcementAction] = []

    async def enforce(
        self,
        content: str,
        policy_decision: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> EnforcementResult:
        """
        Enforce policy decision on content.

        Args:
            content: Content to enforce policy on
            policy_decision: Decision from policy engine
            context: Optional context information

        Returns:
            Enforcement result
        """
        self.total_enforcements += 1

        action_type = policy_decision.get("action", "allow")
        reason = policy_decision.get("reason", "Policy enforcement")
        threats = context.get("threats", []) if context else []

        if action_type == "block":
            return await self._handle_block(content, reason, threats, context)

        elif action_type == "modify" or (
            action_type == "warn" and self.allow_modifications
        ):
            return await self._handle_modify(content, reason, threats, context)

        elif action_type == "warn":
            return await self._handle_warn(content, reason, context)

        else:  # allow
            return await self._handle_allow(content, context)

    async def _handle_block(
        self,
        content: str,
        reason: str,
        threats: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]],
    ) -> EnforcementResult:
        """
        Handle block action.

        Args:
            content: Original content
            reason: Block reason
            threats: List of threats
            context: Context information

        Returns:
            Enforcement result
        """
        self.blocks += 1

        # Determine block message based on threat type
        blocked_message = self._get_blocked_message(threats)

        action = EnforcementAction(
            action_type="block",
            original_content=content,
            modified_content=None,
            reason=reason,
            timestamp=datetime.utcnow(),
            metadata={"threats": threats, "context": context},
        )

        self._record_action(action)

        logger.info(f"Blocked content: {reason}")

        return EnforcementResult(
            allowed=False, content=blocked_message, action=action, warnings=None
        )

    async def _handle_modify(
        self,
        content: str,
        reason: str,
        threats: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]],
    ) -> EnforcementResult:
        """
        Handle modify action.

        Args:
            content: Original content
            reason: Modification reason
            threats: List of threats
            context: Context information

        Returns:
            Enforcement result
        """
        self.modifications += 1

        # Apply modifications based on threat types
        modified = content
        warnings = []

        for threat in threats:
            threat_type = threat.get("type")

            if threat_type == "pii":
                # PII entities should already be redacted by response filter
                modified_result = await self._redact_pii(modified, threat)
                modified = modified_result["content"]
                if modified_result["modified"]:
                    warnings.append(f"PII redacted: {modified_result['count']} items")

            elif threat_type == "toxicity":
                # Remove toxic portions
                modified_result = await self._sanitize_toxicity(modified, threat)
                modified = modified_result["content"]
                if modified_result["modified"]:
                    warnings.append("Toxic content removed")

            elif threat_type == "prompt_injection":
                # In strict mode, block injection attempts
                if self.strict_mode:
                    return await self._handle_block(content, reason, threats, context)
                warnings.append("Potential prompt injection detected")

        action = EnforcementAction(
            action_type="modify",
            original_content=content,
            modified_content=modified,
            reason=reason,
            timestamp=datetime.utcnow(),
            metadata={"threats": threats, "warnings": warnings},
        )

        self._record_action(action)

        logger.info(f"Modified content: {reason} ({len(warnings)} modifications)")

        return EnforcementResult(
            allowed=True, content=modified, action=action, warnings=warnings
        )

    async def _handle_warn(
        self, content: str, reason: str, context: Optional[Dict[str, Any]]
    ) -> EnforcementResult:
        """
        Handle warn action.

        Args:
            content: Original content
            reason: Warning reason
            context: Context information

        Returns:
            Enforcement result
        """
        self.warnings += 1

        action = EnforcementAction(
            action_type="warn",
            original_content=content,
            modified_content=None,
            reason=reason,
            timestamp=datetime.utcnow(),
            metadata={"context": context},
        )

        self._record_action(action)

        logger.warning(f"Content warning: {reason}")

        return EnforcementResult(
            allowed=True, content=content, action=action, warnings=[reason]
        )

    async def _handle_allow(
        self, content: str, context: Optional[Dict[str, Any]]
    ) -> EnforcementResult:
        """
        Handle allow action.

        Args:
            content: Original content
            context: Context information

        Returns:
            Enforcement result
        """
        self.allows += 1

        action = EnforcementAction(
            action_type="allow",
            original_content=content,
            modified_content=None,
            reason="No policy violations",
            timestamp=datetime.utcnow(),
            metadata={"context": context},
        )

        self._record_action(action)

        return EnforcementResult(
            allowed=True, content=content, action=action, warnings=None
        )

    def _get_blocked_message(self, threats: List[Dict[str, Any]]) -> str:
        """
        Get appropriate blocked message based on threats.

        Args:
            threats: List of threats

        Returns:
            Blocked message
        """
        if not threats:
            return self._get_message("default")

        # Use highest priority threat type
        primary_threat = threats[0].get("type", "default")

        return self._get_message(primary_threat)

    def _get_message(self, threat_type: str) -> str:
        """Get message for threat type."""
        # Check custom messages first
        if threat_type in self.custom_blocked_messages:
            return self.custom_blocked_messages[threat_type]

        # Fall back to default messages
        return self.BLOCKED_MESSAGES.get(
            threat_type, self.BLOCKED_MESSAGES["default"]
        )

    async def _redact_pii(
        self, content: str, threat: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Redact PII from content.

        Args:
            content: Content with PII
            threat: Threat information with entities

        Returns:
            Redaction result
        """
        # If threat contains entity information, use it for redaction
        entities = threat.get("entities", [])

        if not entities:
            return {"content": content, "modified": False, "count": 0}

        # Sort by position (reverse) to maintain indices
        sorted_entities = sorted(entities, key=lambda e: e.get("start", 0), reverse=True)

        redacted = content
        count = 0

        for entity in sorted_entities:
            start = entity.get("start")
            end = entity.get("end")
            entity_type = entity.get("type", "PII")

            if start is not None and end is not None:
                redacted = (
                    redacted[:start] + f"[{entity_type}]" + redacted[end:]
                )
                count += 1

        return {"content": redacted, "modified": count > 0, "count": count}

    async def _sanitize_toxicity(
        self, content: str, threat: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Sanitize toxic content.

        Args:
            content: Content with toxicity
            threat: Threat information

        Returns:
            Sanitization result
        """
        # Simple approach: replace matched toxic terms
        matched_terms = threat.get("matched_terms", [])

        if not matched_terms:
            return {"content": content, "modified": False}

        sanitized = content
        for term in matched_terms:
            if isinstance(term, str) and term in sanitized:
                # Replace with asterisks
                replacement = "*" * len(term)
                sanitized = sanitized.replace(term, replacement)

        return {"content": sanitized, "modified": sanitized != content}

    def _record_action(self, action: EnforcementAction) -> None:
        """Record enforcement action in history."""
        self.enforcement_history.append(action)

        # Keep only last 1000 actions
        if len(self.enforcement_history) > 1000:
            self.enforcement_history = self.enforcement_history[-1000:]

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get enforcement statistics.

        Returns:
            Statistics dictionary
        """
        return {
            "total_enforcements": self.total_enforcements,
            "blocks": self.blocks,
            "modifications": self.modifications,
            "warnings": self.warnings,
            "allows": self.allows,
            "block_rate": (
                self.blocks / self.total_enforcements
                if self.total_enforcements > 0
                else 0
            ),
            "modification_rate": (
                self.modifications / self.total_enforcements
                if self.total_enforcements > 0
                else 0
            ),
            "recent_actions": [
                {
                    "action_type": a.action_type,
                    "reason": a.reason,
                    "timestamp": a.timestamp.isoformat(),
                }
                for a in self.enforcement_history[-10:]
            ],
        }

    def set_blocked_message(self, threat_type: str, message: str) -> None:
        """
        Set custom blocked message for threat type.

        Args:
            threat_type: Type of threat
            message: Custom message
        """
        self.custom_blocked_messages[threat_type] = message
        logger.info(f"Set custom blocked message for {threat_type}")

    def reset_statistics(self) -> None:
        """Reset enforcement statistics."""
        self.total_enforcements = 0
        self.blocks = 0
        self.modifications = 0
        self.warnings = 0
        self.allows = 0
        self.enforcement_history = []
        logger.info("Enforcement statistics reset")
