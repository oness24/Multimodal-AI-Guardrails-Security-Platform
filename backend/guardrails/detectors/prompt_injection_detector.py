"""
Pattern-based prompt injection detector.
"""
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """Result from prompt injection detection."""

    detected: bool
    severity: str
    confidence: float
    technique: Optional[str] = None
    matched_patterns: Optional[List[str]] = None
    indicators: Optional[List[str]] = None


class PromptInjectionDetector:
    """
    Pattern-based detector for prompt injection attacks.

    Uses regex patterns and heuristics to detect common injection techniques.
    """

    # Injection patterns organized by technique
    INJECTION_PATTERNS = {
        "instruction_override": [
            r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|directions?)",
            r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)",
            r"forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)",
            r"override\s+(all\s+)?(previous|system)\s+(instructions?|prompts?)",
            r"new\s+(instructions?|task|prompt|directive)",
            r"system\s+(update|override|reset)",
        ],
        "context_manipulation": [
            r"---+\s*(system|admin|root|instruction)",
            r"<\s*system\s*>",
            r"\[system\]",
            r"execute\s+as\s+(admin|root|system)",
            r"sudo\s+",
            r"administrative\s+(mode|access|privileges)",
        ],
        "delimiter_confusion": [
            r"---+\s*end\s+(of\s+)?(prompt|instruction)",
            r"```\s*(system|instruction|prompt)",
            r"<\s*/\s*(instruction|prompt|system)\s*>",
            r"\{%\s*(end|system)",
            r"<!--\s*(end|system)",
        ],
        "role_playing": [
            r"you\s+are\s+(now\s+)?(\w+)\s*(mode|persona)",
            r"act\s+as\s+(a\s+)?(\w+)",
            r"pretend\s+(to\s+be|you\s+are)",
            r"roleplay\s+as",
            r"simulate\s+(being\s+)?(\w+)",
            r"you're\s+(now\s+)?in\s+(\w+)\s+mode",
        ],
        "encoding_attack": [
            r"base64|b64decode",
            r"rot13|rot47",
            r"\\x[0-9a-fA-F]{2}",  # Hex encoding
            r"\\u[0-9a-fA-F]{4}",  # Unicode escape
            r"%[0-9a-fA-F]{2}",  # URL encoding
            r"&#\d+;",  # HTML entities
        ],
        "escape_characters": [
            r"\\n\\r\\t",
            r"\x00",  # Null byte
            r"\\0",
            r"\ufeff",  # Zero-width no-break space
        ],
        "multi_language": [
            r"traduire|übersetzen|翻译|traducir",  # Translate in multiple languages
            r"en\s+français|auf\s+deutsch|in\s+chinese",
        ],
    }

    # High-risk indicators
    HIGH_RISK_INDICATORS = [
        "ignore all previous",
        "disregard previous",
        "forget previous",
        "system override",
        "admin mode",
        "---system",
        "execute as admin",
        "new instructions",
        "DAN mode",
        "jailbreak",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize prompt injection detector.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.sensitivity = self.config.get("sensitivity", "medium")  # low, medium, high
        self.min_confidence = self._get_min_confidence()

        # Compile patterns for performance
        self.compiled_patterns = {}
        for technique, patterns in self.INJECTION_PATTERNS.items():
            self.compiled_patterns[technique] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]

    def _get_min_confidence(self) -> float:
        """Get minimum confidence threshold based on sensitivity."""
        sensitivity_thresholds = {"low": 0.8, "medium": 0.6, "high": 0.4}
        return sensitivity_thresholds.get(self.sensitivity, 0.6)

    async def detect(self, text: str) -> DetectionResult:
        """
        Detect prompt injection attempts in text.

        Args:
            text: Input text to analyze

        Returns:
            Detection result
        """
        text_lower = text.lower()
        matches = []
        techniques_found = []
        indicators = []

        # Check each technique
        for technique, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(text):
                    matches.append(pattern.pattern)
                    if technique not in techniques_found:
                        techniques_found.append(technique)

        # Check high-risk indicators
        for indicator in self.HIGH_RISK_INDICATORS:
            if indicator in text_lower:
                indicators.append(indicator)

        # Calculate confidence score
        confidence = self._calculate_confidence(len(matches), len(indicators), text)

        # Determine if detection threshold is met
        detected = confidence >= self.min_confidence

        # Determine severity
        severity = self._determine_severity(confidence, len(indicators))

        # Get primary technique (most matches)
        primary_technique = None
        if techniques_found:
            # Count matches per technique
            technique_counts = {}
            for technique in techniques_found:
                technique_counts[technique] = sum(
                    1
                    for pattern in self.compiled_patterns[technique]
                    if pattern.search(text)
                )
            primary_technique = max(technique_counts, key=technique_counts.get)

        logger.debug(
            f"Injection detection: detected={detected}, confidence={confidence:.2f}, "
            f"technique={primary_technique}"
        )

        return DetectionResult(
            detected=detected,
            severity=severity,
            confidence=confidence,
            technique=primary_technique,
            matched_patterns=matches[:5] if matches else None,  # Limit to 5
            indicators=indicators[:5] if indicators else None,
        )

    def _calculate_confidence(
        self, num_matches: int, num_indicators: int, text: str
    ) -> float:
        """
        Calculate confidence score for detection.

        Args:
            num_matches: Number of pattern matches
            num_indicators: Number of high-risk indicators
            text: Input text

        Returns:
            Confidence score (0.0 to 1.0)
        """
        # Base confidence from pattern matches
        pattern_score = min(num_matches * 0.2, 0.6)

        # Boost from high-risk indicators
        indicator_score = min(num_indicators * 0.15, 0.4)

        # Check for multiple techniques (increases confidence)
        text_lower = text.lower()
        multiple_techniques_bonus = 0.0

        technique_count = 0
        for technique, patterns in self.compiled_patterns.items():
            if any(pattern.search(text) for pattern in patterns):
                technique_count += 1

        if technique_count >= 2:
            multiple_techniques_bonus = 0.1
        if technique_count >= 3:
            multiple_techniques_bonus = 0.2

        # Combine scores
        confidence = min(
            pattern_score + indicator_score + multiple_techniques_bonus, 1.0
        )

        return round(confidence, 2)

    def _determine_severity(self, confidence: float, num_indicators: int) -> str:
        """
        Determine severity level based on confidence and indicators.

        Args:
            confidence: Confidence score
            num_indicators: Number of high-risk indicators

        Returns:
            Severity level (low, medium, high, critical)
        """
        # Critical: High confidence + multiple indicators
        if confidence >= 0.8 and num_indicators >= 2:
            return "critical"

        # High: High confidence or multiple indicators
        if confidence >= 0.7 or num_indicators >= 2:
            return "high"

        # Medium: Medium confidence
        if confidence >= 0.5:
            return "medium"

        # Low: Low confidence
        return "low"

    async def analyze_detailed(self, text: str) -> Dict[str, Any]:
        """
        Perform detailed analysis of text for prompt injection.

        Args:
            text: Input text to analyze

        Returns:
            Detailed analysis results
        """
        result = await self.detect(text)

        # Get all matching techniques
        all_techniques = {}
        for technique, patterns in self.compiled_patterns.items():
            matches = [
                pattern.pattern for pattern in patterns if pattern.search(text)
            ]
            if matches:
                all_techniques[technique] = {
                    "matches": matches,
                    "count": len(matches),
                }

        return {
            "detected": result.detected,
            "confidence": result.confidence,
            "severity": result.severity,
            "primary_technique": result.technique,
            "all_techniques": all_techniques,
            "high_risk_indicators": result.indicators,
            "matched_patterns": result.matched_patterns,
            "recommendation": "block" if result.detected and result.confidence >= 0.7 else "warn" if result.detected else "allow",
        }
