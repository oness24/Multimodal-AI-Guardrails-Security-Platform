"""
Toxicity Detector for identifying harmful content.
"""
import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class ThreatDetection:
    """Detected threat information."""
    threat_type: str
    severity: str
    confidence: float
    description: str
    matched_pattern: Optional[str] = None


class ToxicityDetector:
    """
    Detector for toxic, harmful, or inappropriate content.
    Uses keyword matching and pattern-based detection.
    """

    def __init__(self):
        self.categories = self._load_categories()

    def _load_categories(self) -> dict:
        """Load toxicity detection categories and patterns."""
        return {
            "hate_speech": {
                "keywords": [
                    "hate", "racist", "sexist", "bigot", "discriminate",
                    "supremacy", "slur", "derogatory",
                ],
                "severity": "critical",
                "weight": 1.0,
            },
            "violence": {
                "keywords": [
                    "kill", "murder", "attack", "violence", "assault",
                    "weapon", "bomb", "terrorist", "harm", "hurt",
                ],
                "severity": "critical",
                "weight": 1.0,
            },
            "harassment": {
                "keywords": [
                    "harass", "bully", "threaten", "stalk", "intimidate",
                    "abuse", "torment",
                ],
                "severity": "high",
                "weight": 0.8,
            },
            "self_harm": {
                "keywords": [
                    "suicide", "self-harm", "kill myself", "end my life",
                    "hurt myself",
                ],
                "severity": "critical",
                "weight": 1.0,
            },
            "explicit": {
                "keywords": [
                    "explicit", "nsfw", "pornographic", "sexual content",
                    "adult content",
                ],
                "severity": "high",
                "weight": 0.7,
            },
            "illegal_activity": {
                "keywords": [
                    "illegal", "hack", "exploit", "bypass", "crack",
                    "pirate", "steal", "fraud",
                ],
                "severity": "high",
                "weight": 0.8,
            },
            "misinformation": {
                "keywords": [
                    "fake news", "conspiracy", "hoax", "misinformation",
                    "propaganda",
                ],
                "severity": "medium",
                "weight": 0.6,
            },
            "profanity": {
                "keywords": [
                    # Keeping this minimal and non-explicit
                    "damn", "crap", "hell",
                ],
                "severity": "low",
                "weight": 0.3,
            },
        }

    async def detect(self, text: str) -> List[ThreatDetection]:
        """
        Detect toxic content in text.
        
        Args:
            text: Text to analyze
            
        Returns:
            List of detected threats
        """
        threats = []
        text_lower = text.lower()
        
        category_matches = {}

        for category, config in self.categories.items():
            keywords = config["keywords"]
            matches = []

            for keyword in keywords:
                # Use word boundary matching to avoid partial matches
                pattern = r"\b" + re.escape(keyword) + r"\b"
                if re.search(pattern, text_lower):
                    matches.append(keyword)

            if matches:
                category_matches[category] = {
                    "matches": matches,
                    "severity": config["severity"],
                    "weight": config["weight"],
                }

        # Generate threats from matches
        for category, data in category_matches.items():
            # Calculate confidence based on number of matches and weight
            match_count = len(data["matches"])
            base_confidence = min(0.5 + (match_count * 0.15), 0.95)
            confidence = base_confidence * data["weight"]

            threats.append(
                ThreatDetection(
                    threat_type=f"toxicity_{category}",
                    severity=data["severity"],
                    confidence=confidence,
                    description=f"Potentially toxic content detected: {category.replace('_', ' ')}",
                    matched_pattern=", ".join(data["matches"][:3]),  # Limit to 3 examples
                )
            )

        # Add combined toxicity threat if multiple categories detected
        if len(category_matches) >= 2:
            avg_confidence = sum(
                min(0.5 + (len(d["matches"]) * 0.15), 0.95) * d["weight"]
                for d in category_matches.values()
            ) / len(category_matches)

            # Determine overall severity
            severities = [d["severity"] for d in category_matches.values()]
            if "critical" in severities:
                overall_severity = "critical"
            elif "high" in severities:
                overall_severity = "high"
            else:
                overall_severity = "medium"

            threats.append(
                ThreatDetection(
                    threat_type="toxicity",
                    severity=overall_severity,
                    confidence=min(avg_confidence + 0.1, 0.95),
                    description="Multiple categories of potentially harmful content detected",
                    matched_pattern=", ".join(category_matches.keys()),
                )
            )

        return threats

    def get_toxicity_score(self, text: str) -> float:
        """
        Get an overall toxicity score for text (0-1).
        
        Args:
            text: Text to analyze
            
        Returns:
            Toxicity score from 0 (safe) to 1 (highly toxic)
        """
        text_lower = text.lower()
        total_score = 0.0
        total_weight = 0.0

        for category, config in self.categories.items():
            weight = config["weight"]
            keywords = config["keywords"]

            match_count = sum(
                1 for kw in keywords
                if re.search(r"\b" + re.escape(kw) + r"\b", text_lower)
            )

            if match_count > 0:
                category_score = min(match_count * 0.2, 1.0)
                total_score += category_score * weight
                total_weight += weight

        if total_weight == 0:
            return 0.0

        return min(total_score / total_weight, 1.0)
