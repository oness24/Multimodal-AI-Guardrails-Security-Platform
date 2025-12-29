"""
Guardrails Engine for real-time threat detection and protection.
"""
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from backend.guardrails.detectors.prompt_injection_detector import PromptInjectionDetector
from backend.guardrails.detectors.pii_detector import PIIDetector
from backend.guardrails.detectors.toxicity_detector import ToxicityDetector
from backend.utils.token_counter import TokenCounter, TokenLimitExceeded


class ThreatSeverity(str, Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ThreatDetection:
    """Detected threat information."""
    threat_type: str
    severity: str
    confidence: float
    description: str
    matched_pattern: Optional[str] = None
    start_pos: Optional[int] = None
    end_pos: Optional[int] = None


@dataclass
class PIIMatch:
    """Detected PII information."""
    pii_type: str
    value: str
    start_pos: int
    end_pos: int
    confidence: float


@dataclass
class TokenInfo:
    """Token count information."""
    token_count: int
    model: str
    context_limit: int
    within_limit: bool


@dataclass
class GuardrailResult:
    """Result of guardrail validation."""
    is_safe: bool
    risk_score: float
    threats: List[ThreatDetection] = field(default_factory=list)
    pii_detected: List[PIIMatch] = field(default_factory=list)
    sanitized_text: Optional[str] = None
    policy_violations: List[str] = field(default_factory=list)
    processing_time_ms: int = 0
    token_info: Optional[TokenInfo] = None


class GuardrailsEngine:
    """
    Main engine for running guardrails on input/output text.
    Orchestrates multiple detectors and policies.
    """

    def __init__(self):
        self.injection_detector = PromptInjectionDetector()
        self.pii_detector = PIIDetector()
        self.toxicity_detector = ToxicityDetector()
        self.token_counter = TokenCounter()
        
        # Default configuration
        self.max_input_length = 10000
        self.max_input_tokens = 8000  # Token limit for DoS prevention
        self.risk_threshold = 0.5
        self.target_model = "gpt-4"  # Default model for token counting

    async def validate(
        self,
        text: str,
        mode: str = "input",
        checks: Optional[List[str]] = None,
        target_model: Optional[str] = None,
    ) -> GuardrailResult:
        """
        Validate text against all configured guardrails.
        
        Args:
            text: Text to validate
            mode: 'input' for user input, 'output' for model output
            checks: Specific checks to run (all if None)
            target_model: Model to use for token counting
            
        Returns:
            GuardrailResult with validation outcome
        """
        start_time = time.time()
        
        threats: List[ThreatDetection] = []
        pii_detected: List[PIIMatch] = []
        policy_violations: List[str] = []
        token_info: Optional[TokenInfo] = None
        
        model = target_model or self.target_model
        
        enabled_checks = checks or [
            "prompt_injection",
            "jailbreak",
            "pii_detection",
            "toxicity",
            "policy_compliance",
            "token_limit",
        ]

        # Token limit check (DoS prevention) - Run first for efficiency
        if "token_limit" in enabled_checks:
            token_count = self.token_counter.count_tokens(text)
            context_limit = self.token_counter.get_context_limit(model)
            within_limit = token_count <= self.max_input_tokens
            
            token_info = TokenInfo(
                token_count=token_count,
                model=model,
                context_limit=context_limit,
                within_limit=within_limit,
            )
            
            if not within_limit:
                threats.append(ThreatDetection(
                    threat_type="token_overflow",
                    severity=ThreatSeverity.HIGH.value,
                    confidence=1.0,
                    description=f"Input exceeds token limit ({token_count}/{self.max_input_tokens} tokens). Possible DoS attempt.",
                ))
                policy_violations.append(
                    f"Token limit exceeded: {token_count} > {self.max_input_tokens}"
                )

        # Run prompt injection detection
        if "prompt_injection" in enabled_checks or "jailbreak" in enabled_checks:
            injection_threats = await self.injection_detector.detect(text)
            threats.extend(injection_threats)

        # Run PII detection
        if "pii_detection" in enabled_checks:
            pii_matches = await self.pii_detector.detect(text)
            pii_detected.extend(pii_matches)

        # Run toxicity detection
        if "toxicity" in enabled_checks:
            toxicity_threats = await self.toxicity_detector.detect(text)
            threats.extend(toxicity_threats)

        # Check policies
        if "policy_compliance" in enabled_checks:
            violations = self._check_policies(text, mode)
            policy_violations.extend(violations)

        # Calculate risk score
        risk_score = self._calculate_risk_score(threats, pii_detected, policy_violations)

        # Determine if safe
        is_safe = risk_score < self.risk_threshold and len(policy_violations) == 0

        # Generate sanitized text if PII detected
        sanitized_text = None
        if pii_detected:
            sanitized_text = self._sanitize_text(text, pii_detected)

        processing_time = int((time.time() - start_time) * 1000)

        return GuardrailResult(
            is_safe=is_safe,
            risk_score=risk_score,
            threats=threats,
            pii_detected=pii_detected,
            sanitized_text=sanitized_text,
            policy_violations=policy_violations,
            processing_time_ms=processing_time,
            token_info=token_info,
        )

    def _check_policies(self, text: str, mode: str) -> List[str]:
        """Check text against configured policies."""
        violations = []

        # Length policy
        if len(text) > self.max_input_length:
            violations.append(
                f"Text exceeds maximum length of {self.max_input_length} characters"
            )

        # Output-specific policies
        if mode == "output":
            # Check for potential code execution
            code_patterns = [
                r"```(?:python|javascript|bash|sh)\n.*exec\(",
                r"<script>",
                r"eval\(",
            ]
            for pattern in code_patterns:
                if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                    violations.append("Output contains potentially executable code")
                    break

        return violations

    def _calculate_risk_score(
        self,
        threats: List[ThreatDetection],
        pii: List[PIIMatch],
        violations: List[str],
    ) -> float:
        """Calculate overall risk score from 0 to 1."""
        score = 0.0

        # Add threat scores
        for threat in threats:
            if threat.severity == ThreatSeverity.CRITICAL.value:
                score += 0.4 * threat.confidence
            elif threat.severity == ThreatSeverity.HIGH.value:
                score += 0.25 * threat.confidence
            elif threat.severity == ThreatSeverity.MEDIUM.value:
                score += 0.15 * threat.confidence
            elif threat.severity == ThreatSeverity.LOW.value:
                score += 0.05 * threat.confidence

        # Add PII score
        score += len(pii) * 0.15

        # Add policy violation score
        score += len(violations) * 0.2

        return min(score, 1.0)

    def _sanitize_text(self, text: str, pii_matches: List[PIIMatch]) -> str:
        """Sanitize text by redacting PII."""
        sanitized = text
        
        # Sort by position descending to maintain correct indices
        sorted_matches = sorted(pii_matches, key=lambda x: x.start_pos, reverse=True)
        
        for match in sorted_matches:
            redaction = f"[REDACTED_{match.pii_type.upper()}]"
            sanitized = sanitized[:match.start_pos] + redaction + sanitized[match.end_pos:]

        return sanitized


# Singleton instance
guardrails_engine = GuardrailsEngine()
