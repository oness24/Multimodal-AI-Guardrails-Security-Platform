"""
Toxicity detector for identifying harmful content.
"""
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class ToxicityDetectionResult:
    """Result from toxicity detection."""

    detected: bool
    severity: str
    confidence: float
    categories: List[str]
    matched_terms: Optional[List[str]] = None
    score_breakdown: Optional[Dict[str, float]] = None


class ToxicityDetector:
    """
    Pattern-based toxicity detector.

    Detects harmful content categories:
    - Hate speech
    - Violence
    - Sexual content
    - Harassment
    - Self-harm
    - Illegal activities
    """

    # Category patterns (basic implementation - should be expanded)
    TOXICITY_PATTERNS = {
        "hate_speech": [
            r"\b(hate|despise)\s+(all\s+)?(\w+s)\b",
            r"\bk[i1]ll\s+(all\s+)?(\w+s)\b",
            r"\bgenocide\b",
            r"\bethnic\s+cleansing\b",
            r"\bsuperior\s+race\b",
        ],
        "violence": [
            r"\bk[i1]ll\s+(you|him|her|them)\b",
            r"\bmurder\s+(you|someone)\b",
            r"\bbeat\s+(you\s+)?up\b",
            r"\bphysically\s+harm\b",
            r"\bassault\s+(you|someone)\b",
            r"\bshoot\s+(you|up)\b",
            r"\bbomb\s+(threat|making)\b",
        ],
        "sexual_content": [
            r"\bexplicit\s+sexual\b",
            r"\bsexual\s+act\b",
            r"\bpornographic\b",
            r"\bchild\s+pornography\b",
            r"\bsexual\s+abuse\b",
        ],
        "harassment": [
            r"\bstupid\s+(idiot|moron|fool)\b",
            r"\byou\s+suck\b",
            r"\bgo\s+die\b",
            r"\bk[i1]ll\s+yourself\b",
            r"\bunalive\s+yourself\b",
            r"\bworth?less\s+piece\b",
        ],
        "self_harm": [
            r"\bcommit\s+suicide\b",
            r"\bk[i1]ll\s+myself\b",
            r"\bend\s+my\s+life\b",
            r"\bhow\s+to\s+(cut|harm)\s+myself\b",
            r"\bsuicide\s+(methods?|ways?)\b",
        ],
        "illegal_activities": [
            r"\bhow\s+to\s+(make|build)\s+(bomb|explosive)\b",
            r"\bbuy\s+(drugs|weapons)\s+illegally\b",
            r"\bhack\s+(into|someone's)\b",
            r"\bsteal\s+(credit\s+cards?|identit(?:y|ies))\b",
            r"\blaunder\s+money\b",
            r"\bforge\s+(documents?|passport)\b",
        ],
        "extremism": [
            r"\bterrorist\s+(attack|organization)\b",
            r"\bradical\s+ideology\b",
            r"\bextremist\s+(group|views?)\b",
            r"\bjihad\b",
            r"\bwhite\s+(power|supremacy)\b",
        ],
    }

    # Severity weights for categories
    CATEGORY_SEVERITY = {
        "hate_speech": 0.8,
        "violence": 0.9,
        "sexual_content": 0.7,
        "harassment": 0.6,
        "self_harm": 0.9,
        "illegal_activities": 0.85,
        "extremism": 0.95,
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize toxicity detector.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.min_confidence = self.config.get("min_confidence", 0.5)
        self.strict_mode = self.config.get("strict_mode", False)

        # Compile patterns
        self.compiled_patterns = {}
        for category, patterns in self.TOXICITY_PATTERNS.items():
            self.compiled_patterns[category] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]

    async def detect(self, text: str) -> ToxicityDetectionResult:
        """
        Detect toxic content in text.

        Args:
            text: Input text to analyze

        Returns:
            Toxicity detection result
        """
        text_lower = text.lower()
        categories_found: Set[str] = set()
        matched_terms: List[str] = []
        score_breakdown = {}

        # Check each category
        for category, patterns in self.compiled_patterns.items():
            category_matches = 0
            for pattern in patterns:
                matches = pattern.findall(text)
                if matches:
                    category_matches += len(matches)
                    matched_terms.extend(matches[:2])  # Limit to avoid bloat

            if category_matches > 0:
                categories_found.add(category)
                # Calculate category score (more matches = higher score)
                score_breakdown[category] = min(category_matches * 0.3, 1.0)

        # Calculate overall confidence
        confidence = self._calculate_confidence(categories_found, score_breakdown)

        # Determine if detected (above threshold)
        detected = confidence >= self.min_confidence

        # Determine severity
        severity = self._determine_severity(categories_found, confidence)

        logger.debug(
            f"Toxicity detection: detected={detected}, confidence={confidence:.2f}, "
            f"categories={list(categories_found)}"
        )

        return ToxicityDetectionResult(
            detected=detected,
            severity=severity,
            confidence=confidence,
            categories=list(categories_found),
            matched_terms=matched_terms[:5] if matched_terms else None,
            score_breakdown=score_breakdown,
        )

    def _calculate_confidence(
        self, categories: Set[str], score_breakdown: Dict[str, float]
    ) -> float:
        """
        Calculate overall confidence score.

        Args:
            categories: Set of detected categories
            score_breakdown: Score breakdown by category

        Returns:
            Confidence score (0.0 to 1.0)
        """
        if not categories:
            return 0.0

        # Weight by severity
        weighted_score = 0.0
        total_weight = 0.0

        for category in categories:
            severity_weight = self.CATEGORY_SEVERITY.get(category, 0.5)
            category_score = score_breakdown.get(category, 0.0)
            weighted_score += category_score * severity_weight
            total_weight += severity_weight

        if total_weight == 0:
            return 0.0

        confidence = weighted_score / total_weight

        # Boost if multiple categories detected
        if len(categories) >= 2:
            confidence = min(confidence + 0.1, 1.0)
        if len(categories) >= 3:
            confidence = min(confidence + 0.1, 1.0)

        return round(confidence, 2)

    def _determine_severity(self, categories: Set[str], confidence: float) -> str:
        """
        Determine severity level.

        Args:
            categories: Detected categories
            confidence: Confidence score

        Returns:
            Severity level (low, medium, high, critical)
        """
        if not categories:
            return "low"

        # Check for critical categories
        critical_categories = {"violence", "self_harm", "illegal_activities", "extremism"}
        if categories & critical_categories:
            if confidence >= 0.7:
                return "critical"
            return "high"

        # High severity categories
        high_severity = {"hate_speech", "sexual_content"}
        if categories & high_severity:
            if confidence >= 0.7:
                return "high"
            return "medium"

        # Default to medium for other categories
        if confidence >= 0.7:
            return "medium"
        return "low"

    async def analyze_detailed(self, text: str) -> Dict[str, Any]:
        """
        Perform detailed toxicity analysis.

        Args:
            text: Input text

        Returns:
            Detailed analysis results
        """
        result = await self.detect(text)

        # Get category details
        category_details = {}
        for category in result.categories:
            category_details[category] = {
                "severity_weight": self.CATEGORY_SEVERITY.get(category, 0.5),
                "score": result.score_breakdown.get(category, 0.0),
                "description": self._get_category_description(category),
            }

        return {
            "detected": result.detected,
            "confidence": result.confidence,
            "severity": result.severity,
            "categories": result.categories,
            "category_details": category_details,
            "matched_terms": result.matched_terms,
            "recommendation": self._get_recommendation(result),
        }

    def _get_category_description(self, category: str) -> str:
        """Get description for category."""
        descriptions = {
            "hate_speech": "Content promoting hatred or discrimination",
            "violence": "Content describing or promoting violence",
            "sexual_content": "Explicit sexual content",
            "harassment": "Content intended to harass or bully",
            "self_harm": "Content promoting self-harm or suicide",
            "illegal_activities": "Content describing illegal activities",
            "extremism": "Extremist or terrorist content",
        }
        return descriptions.get(category, "Unknown category")

    def _get_recommendation(self, result: ToxicityDetectionResult) -> str:
        """Get action recommendation based on result."""
        if not result.detected:
            return "allow"

        if result.severity in ["critical", "high"]:
            return "block"
        elif result.severity == "medium":
            return "warn"
        else:
            return "allow"

    async def check_categories(
        self, text: str, categories: List[str]
    ) -> Dict[str, bool]:
        """
        Check for specific toxicity categories.

        Args:
            text: Input text
            categories: Categories to check

        Returns:
            Dictionary mapping categories to detection status
        """
        result = await self.detect(text)

        return {category: category in result.categories for category in categories}
