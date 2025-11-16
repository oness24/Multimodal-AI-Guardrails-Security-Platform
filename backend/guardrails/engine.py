"""
Guardrails engine orchestrator for AdversarialShield.
Coordinates sanitization, validation, and enforcement agents.
"""
import logging
from typing import Any, Dict, List, Optional

from backend.guardrails.agents.sanitization_agent import SanitizationAgent
from backend.guardrails.agents.validation_agent import ValidationAgent
from backend.guardrails.detectors.prompt_injection_detector import (
    PromptInjectionDetector,
)
from backend.guardrails.detectors.pii_detector import PIIDetector
from backend.guardrails.detectors.toxicity_detector import ToxicityDetector
from backend.guardrails.policies.policy_engine import PolicyEngine

logger = logging.getLogger(__name__)


class GuardrailsEngine:
    """
    Multi-agent guardrails system for AI input/output protection.

    Implements a three-layer defense architecture:
    1. Sanitization Layer - Cleans and normalizes inputs
    2. Validation Layer - Detects threats and policy violations
    3. Enforcement Layer - Blocks or modifies based on policies
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize guardrails engine.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}

        # Initialize agents
        self.sanitization_agent = SanitizationAgent()
        self.validation_agent = ValidationAgent()

        # Initialize detectors
        self.injection_detector = PromptInjectionDetector()
        self.pii_detector = PIIDetector()
        self.toxicity_detector = ToxicityDetector()

        # Initialize policy engine
        self.policy_engine = PolicyEngine(self.config.get("policies"))

        logger.info("GuardrailsEngine initialized")

    async def protect_input(
        self,
        user_input: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run input through guardrails protection pipeline.

        Args:
            user_input: User input to protect
            context: Additional context about the request

        Returns:
            Protection result with sanitized input and threat analysis
        """
        context = context or {}

        logger.debug(f"Protecting input: {user_input[:100]}...")

        # Layer 1: Sanitization
        sanitized_input = await self.sanitization_agent.clean(user_input)

        # Layer 2: Threat Detection
        threats = []

        # Check for prompt injection
        injection_result = await self.injection_detector.detect(sanitized_input)
        if injection_result.detected:
            threats.append(
                {
                    "type": "prompt_injection",
                    "severity": injection_result.severity,
                    "confidence": injection_result.confidence,
                    "technique": injection_result.technique,
                }
            )

        # Check for PII
        pii_result = await self.pii_detector.detect(sanitized_input)
        if pii_result.detected:
            threats.append(
                {
                    "type": "pii",
                    "severity": "medium",
                    "confidence": 1.0,
                    "entities": pii_result.entities,
                }
            )

        # Check for toxicity
        toxicity_result = await self.toxicity_detector.detect(sanitized_input)
        if toxicity_result.detected:
            threats.append(
                {
                    "type": "toxicity",
                    "severity": toxicity_result.severity,
                    "confidence": toxicity_result.confidence,
                    "categories": toxicity_result.categories,
                }
            )

        # Layer 3: Policy Evaluation
        policy_decision = await self.policy_engine.evaluate(
            input_text=sanitized_input,
            threats=threats,
            context=context,
        )

        # Determine action
        safe = len(threats) == 0 or policy_decision.action == "allow"

        return {
            "safe": safe,
            "action": policy_decision.action,  # allow, warn, block
            "sanitized_input": sanitized_input,
            "original_input": user_input,
            "threats": threats,
            "policy_decision": policy_decision.to_dict(),
            "modifications": self.sanitization_agent.get_modifications(),
        }

    async def protect_output(
        self,
        model_output: str,
        original_input: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate model output before returning to user.

        Args:
            model_output: Output from the model
            original_input: Original user input
            context: Additional context

        Returns:
            Validation result with safe/unsafe status
        """
        context = context or {}

        logger.debug(f"Validating output: {model_output[:100]}...")

        threats = []

        # Check for PII leakage in output
        pii_result = await self.pii_detector.detect(model_output)
        if pii_result.detected:
            threats.append(
                {
                    "type": "pii_leakage",
                    "severity": "high",
                    "confidence": 1.0,
                    "entities": pii_result.entities,
                }
            )

        # Check for toxic output
        toxicity_result = await self.toxicity_detector.detect(model_output)
        if toxicity_result.detected:
            threats.append(
                {
                    "type": "toxic_output",
                    "severity": toxicity_result.severity,
                    "confidence": toxicity_result.confidence,
                    "categories": toxicity_result.categories,
                }
            )

        # Policy evaluation for output
        policy_decision = await self.policy_engine.evaluate_output(
            output_text=model_output,
            threats=threats,
            context=context,
        )

        safe = len(threats) == 0 or policy_decision.action == "allow"

        return {
            "safe": safe,
            "action": policy_decision.action,
            "output": model_output,
            "threats": threats,
            "policy_decision": policy_decision.to_dict(),
        }

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get guardrails engine statistics.

        Returns:
            Statistics dictionary
        """
        return {
            "total_checks": self.validation_agent.total_checks,
            "threats_detected": self.validation_agent.threats_detected,
            "blocked_requests": self.policy_engine.blocked_count,
            "warned_requests": self.policy_engine.warned_count,
        }
