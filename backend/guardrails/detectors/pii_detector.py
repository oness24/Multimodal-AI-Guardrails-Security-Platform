"""
PII (Personally Identifiable Information) Detector.
"""
import re
from dataclasses import dataclass
from typing import List


@dataclass
class PIIMatch:
    """Detected PII information."""
    pii_type: str
    value: str
    start_pos: int
    end_pos: int
    confidence: float


class PIIDetector:
    """
    Detector for personally identifiable information.
    Uses regex patterns to identify common PII types.
    """

    def __init__(self):
        self.patterns = self._load_patterns()

    def _load_patterns(self) -> dict:
        """Load PII detection patterns."""
        return {
            "email": {
                "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                "confidence": 0.95,
            },
            "phone_us": {
                "pattern": r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
                "confidence": 0.85,
            },
            "phone_international": {
                "pattern": r"\b\+[0-9]{1,3}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}\b",
                "confidence": 0.80,
            },
            "ssn": {
                "pattern": r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b",
                "confidence": 0.95,
            },
            "credit_card": {
                "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
                "confidence": 0.90,
            },
            "credit_card_formatted": {
                "pattern": r"\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b",
                "confidence": 0.85,
            },
            "ip_address": {
                "pattern": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
                "confidence": 0.80,
            },
            "date_of_birth": {
                "pattern": r"\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12][0-9]|3[01])[/-](?:19|20)[0-9]{2}\b",
                "confidence": 0.70,
            },
            "passport": {
                "pattern": r"\b[A-Z]{1,2}[0-9]{6,9}\b",
                "confidence": 0.60,
            },
            "driver_license": {
                "pattern": r"\b[A-Z][0-9]{7,8}\b",
                "confidence": 0.55,
            },
            "bank_account": {
                "pattern": r"\b[0-9]{8,17}\b",
                "confidence": 0.40,  # Low confidence - needs context
            },
            "aws_key": {
                "pattern": r"\bAKIA[0-9A-Z]{16}\b",
                "confidence": 0.95,
            },
            "aws_secret": {
                "pattern": r"\b[A-Za-z0-9/+=]{40}\b",
                "confidence": 0.60,
            },
            "api_key": {
                "pattern": r"\b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9_-]{20,})['\"]?",
                "confidence": 0.85,
            },
        }

    async def detect(self, text: str) -> List[PIIMatch]:
        """
        Detect PII in text.
        
        Args:
            text: Text to analyze
            
        Returns:
            List of detected PII matches
        """
        matches = []

        for pii_type, config in self.patterns.items():
            pattern = config["pattern"]
            confidence = config["confidence"]

            for match in re.finditer(pattern, text, re.IGNORECASE):
                # Skip low-confidence matches that are likely false positives
                if self._is_likely_false_positive(pii_type, match.group(), text):
                    continue

                matches.append(
                    PIIMatch(
                        pii_type=self._normalize_pii_type(pii_type),
                        value=match.group(),
                        start_pos=match.start(),
                        end_pos=match.end(),
                        confidence=confidence,
                    )
                )

        # Deduplicate overlapping matches
        return self._deduplicate_matches(matches)

    def _normalize_pii_type(self, pii_type: str) -> str:
        """Normalize PII type names."""
        type_map = {
            "phone_us": "phone",
            "phone_international": "phone",
            "credit_card_formatted": "credit_card",
            "aws_key": "api_key",
            "aws_secret": "api_key",
        }
        return type_map.get(pii_type, pii_type)

    def _is_likely_false_positive(self, pii_type: str, value: str, context: str) -> bool:
        """Check if a match is likely a false positive."""
        value_lower = value.lower()
        context_lower = context.lower()

        # Common false positive checks
        if pii_type == "bank_account":
            # Check if it's in a context that suggests it's not a bank account
            non_bank_keywords = ["id", "code", "version", "port", "size", "count"]
            # Get surrounding context
            start_idx = context_lower.find(value_lower)
            if start_idx > 0:
                surrounding = context_lower[max(0, start_idx - 20):start_idx]
                if any(kw in surrounding for kw in non_bank_keywords):
                    return True

        if pii_type in ["passport", "driver_license"]:
            # These patterns can match many things, require more context
            if len(value) < 8:
                return True

        return False

    def _deduplicate_matches(self, matches: List[PIIMatch]) -> List[PIIMatch]:
        """Remove overlapping matches, keeping highest confidence."""
        if not matches:
            return []

        # Sort by start position
        sorted_matches = sorted(matches, key=lambda x: x.start_pos)
        result = [sorted_matches[0]]

        for match in sorted_matches[1:]:
            last = result[-1]
            # Check for overlap
            if match.start_pos < last.end_pos:
                # Keep the one with higher confidence
                if match.confidence > last.confidence:
                    result[-1] = match
            else:
                result.append(match)

        return result

    def redact(self, text: str, matches: List[PIIMatch]) -> str:
        """
        Redact detected PII from text.
        
        Args:
            text: Original text
            matches: List of PII matches to redact
            
        Returns:
            Text with PII redacted
        """
        if not matches:
            return text

        # Sort by position descending to maintain correct indices
        sorted_matches = sorted(matches, key=lambda x: x.start_pos, reverse=True)

        result = text
        for match in sorted_matches:
            redaction = f"[REDACTED_{match.pii_type.upper()}]"
            result = result[:match.start_pos] + redaction + result[match.end_pos:]

        return result
