"""
Guardrails engine orchestrator for AdversarialShield.
Coordinates sanitization, validation, and enforcement agents.
"""
import logging
from typing import Any, Dict, List, Optional

from backend.guardrails.agents.contextual_validator import ContextualValidator
from backend.guardrails.agents.enforcement_agent import EnforcementAgent
from backend.guardrails.agents.sanitization_agent import SanitizationAgent
from backend.guardrails.agents.validation_agent import ValidationAgent
from backend.guardrails.detectors.pii_detector import PIIDetector
from backend.guardrails.detectors.prompt_injection_detector import (
    PromptInjectionDetector,
)
from backend.guardrails.detectors.toxicity_detector import ToxicityDetector
from backend.guardrails.filters.response_filter import ResponseFilter
from backend.guardrails.policies.policy_engine import PolicyEngine
from backend.guardrails.utils.performance_cache import get_global_cache

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
        self.contextual_validator = ContextualValidator()
        self.enforcement_agent = EnforcementAgent()

        # Initialize detectors
        self.injection_detector = PromptInjectionDetector()
        self.pii_detector = PIIDetector()
        self.toxicity_detector = ToxicityDetector()

        # Initialize filters
        self.response_filter = ResponseFilter()

        # Initialize policy engine
        self.policy_engine = PolicyEngine(self.config.get("policies"))

        # Get global performance cache
        self.cache = get_global_cache()

        logger.info("GuardrailsEngine initialized")

    async def protect_input(
        self,
        user_input: str,
        context: Optional[Dict[str, Any]] = None,
        allowed_context: Optional[Dict[str, Any]] = None,
        rag_context: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Run input through guardrails protection pipeline.

        Args:
            user_input: User input to protect
            context: Additional context about the request
            allowed_context: Allowed context boundaries for contextual validation
            rag_context: Retrieved context from RAG system

        Returns:
            Protection result with sanitized input and threat analysis
        """
        context = context or {}

        logger.debug(f"Protecting input: {user_input[:100]}...")

        # Layer 1: Sanitization
        sanitized_input = await self.sanitization_agent.clean(user_input)

        # Layer 2: Threat Detection (with caching)
        threats = []

        # Check for prompt injection (with cache)
        cached_injection = self.cache.get_detection_result(sanitized_input, "injection")
        if cached_injection:
            injection_result = cached_injection
        else:
            injection_result = await self.injection_detector.detect(sanitized_input)
            self.cache.cache_detection_result(sanitized_input, "injection", injection_result)

        if injection_result.detected:
            threats.append(
                {
                    "type": "prompt_injection",
                    "severity": injection_result.severity,
                    "confidence": injection_result.confidence,
                    "technique": injection_result.technique,
                }
            )

        # Check for PII (with cache)
        cached_pii = self.cache.get_detection_result(sanitized_input, "pii")
        if cached_pii:
            pii_result = cached_pii
        else:
            pii_result = await self.pii_detector.detect(sanitized_input)
            self.cache.cache_detection_result(sanitized_input, "pii", pii_result)

        if pii_result.detected:
            threats.append(
                {
                    "type": "pii",
                    "severity": "medium",
                    "confidence": 1.0,
                    "entities": pii_result.entities,
                }
            )

        # Check for toxicity (with cache)
        cached_toxicity = self.cache.get_detection_result(sanitized_input, "toxicity")
        if cached_toxicity:
            toxicity_result = cached_toxicity
        else:
            toxicity_result = await self.toxicity_detector.detect(sanitized_input)
            self.cache.cache_detection_result(sanitized_input, "toxicity", toxicity_result)

        if toxicity_result.detected:
            threats.append(
                {
                    "type": "toxicity",
                    "severity": toxicity_result.severity,
                    "confidence": toxicity_result.confidence,
                    "categories": toxicity_result.categories,
                }
            )

        # Contextual validation (if RAG context or allowed context provided)
        if rag_context or allowed_context:
            contextual_result = await self.contextual_validator.validate_input_context(
                user_input=sanitized_input,
                allowed_context=allowed_context,
                rag_context=rag_context,
            )

            if not contextual_result.is_valid:
                for violation in contextual_result.violations:
                    threats.append(violation)

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
        rag_context: Optional[List[str]] = None,
        allowed_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate model output before returning to user.

        Args:
            model_output: Output from the model
            original_input: Original user input
            context: Additional context
            rag_context: RAG context used for generation
            allowed_context: Allowed context boundaries

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

        # Contextual validation for output (check for context leakage, hallucination)
        if rag_context or allowed_context:
            contextual_result = await self.contextual_validator.validate_output_context(
                model_output=model_output,
                original_input=original_input,
                rag_context=rag_context,
                allowed_context=allowed_context,
            )

            if not contextual_result.is_valid:
                for violation in contextual_result.violations:
                    threats.append(violation)

        # Policy evaluation for output
        policy_decision = await self.policy_engine.evaluate_output(
            output_text=model_output,
            threats=threats,
            context=context,
        )

        # Response filtering and enforcement
        filter_result = await self.response_filter.filter_response(
            text=model_output,
            context=context,
            pii_entities=pii_result.entities if pii_result.detected else None,
        )

        # If filter blocked the content, override policy decision
        if filter_result.blocked:
            final_output = filter_result.filtered_text
            safe = False
            action = "block"
        else:
            # Enforce policy decision
            enforcement_context = {"threats": threats}
            enforcement_result = await self.enforcement_agent.enforce(
                content=filter_result.filtered_text,
                policy_decision=policy_decision.to_dict(),
                context=enforcement_context,
            )

            final_output = enforcement_result.content
            safe = enforcement_result.allowed
            action = enforcement_result.action.action_type

        return {
            "safe": safe,
            "action": action,
            "output": final_output,
            "original_output": model_output,
            "threats": threats,
            "policy_decision": policy_decision.to_dict(),
            "filter_modifications": filter_result.modifications,
            "enforcement_warnings": enforcement_result.warnings if not filter_result.blocked else None,
        }

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get guardrails engine statistics.

        Returns:
            Statistics dictionary
        """
        policy_stats = await self.policy_engine.get_statistics()
        enforcement_stats = await self.enforcement_agent.get_statistics()
        cache_stats = self.cache.get_statistics()

        return {
            "total_checks": self.validation_agent.total_checks,
            "threats_detected": self.validation_agent.threats_detected,
            "blocked_requests": policy_stats["blocked_count"],
            "warned_requests": policy_stats["warned_count"],
            "enforcement": enforcement_stats,
            "cache": cache_stats,
            "detection_rate": policy_stats["detection_rate"] if "detection_rate" in policy_stats else 0,
        }
