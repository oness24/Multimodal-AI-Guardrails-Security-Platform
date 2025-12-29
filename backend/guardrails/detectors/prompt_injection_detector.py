"""
Prompt Injection Detector for identifying injection attempts.
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


class PromptInjectionDetector:
    """
    Detector for prompt injection and jailbreak attempts.
    Uses pattern matching and heuristics for detection.
    """

    def __init__(self):
        self.injection_patterns = self._load_injection_patterns()
        self.jailbreak_patterns = self._load_jailbreak_patterns()

    def _load_injection_patterns(self) -> List[dict]:
        """Load prompt injection detection patterns."""
        return [
            {
                "pattern": r"ignore\s+(all\s+)?previous\s+(instructions?|prompts?)",
                "severity": "high",
                "confidence": 0.9,
                "description": "Instruction override attempt",
            },
            {
                "pattern": r"disregard\s+(all\s+)?(above|previous|prior)",
                "severity": "high",
                "confidence": 0.85,
                "description": "Instruction disregard attempt",
            },
            {
                "pattern": r"new\s+task\s*[:.]",
                "severity": "high",
                "confidence": 0.8,
                "description": "New task injection attempt",
            },
            {
                "pattern": r"system\s+override",
                "severity": "critical",
                "confidence": 0.95,
                "description": "System override attempt",
            },
            {
                "pattern": r"forget\s+(your|all)\s+(guidelines?|instructions?|rules?)",
                "severity": "high",
                "confidence": 0.9,
                "description": "Guideline bypass attempt",
            },
            {
                "pattern": r"\[/?inst\]",
                "severity": "medium",
                "confidence": 0.75,
                "description": "Instruction tag injection",
            },
            {
                "pattern": r"developer\s+mode",
                "severity": "high",
                "confidence": 0.85,
                "description": "Developer mode activation attempt",
            },
            {
                "pattern": r"</?(system|user|assistant)>",
                "severity": "high",
                "confidence": 0.9,
                "description": "Role tag injection attempt",
            },
            {
                "pattern": r"---\s*end\s+of\s+(prompt|instructions?)\s*---",
                "severity": "high",
                "confidence": 0.85,
                "description": "Prompt boundary injection",
            },
            {
                "pattern": r"act\s+as\s+(if\s+)?(you\s+(are|were)\s+)?an?\s+",
                "severity": "medium",
                "confidence": 0.7,
                "description": "Role manipulation attempt",
            },
            {
                "pattern": r"pretend\s+(that\s+)?(you\s+)?(are|were|have)",
                "severity": "medium",
                "confidence": 0.7,
                "description": "Pretend role injection",
            },
            {
                "pattern": r"you\s+are\s+now\s+(in\s+)?",
                "severity": "medium",
                "confidence": 0.65,
                "description": "State change injection",
            },
            {
                "pattern": r"from\s+now\s+on",
                "severity": "medium",
                "confidence": 0.6,
                "description": "Behavior modification attempt",
            },
        ]

    def _load_jailbreak_patterns(self) -> List[dict]:
        """Load jailbreak detection patterns."""
        return [
            {
                "pattern": r"dan\s+(mode|prompt)?",
                "severity": "critical",
                "confidence": 0.95,
                "description": "DAN (Do Anything Now) jailbreak attempt",
            },
            {
                "pattern": r"do\s+anything\s+now",
                "severity": "critical",
                "confidence": 0.95,
                "description": "DAN jailbreak attempt",
            },
            {
                "pattern": r"without\s+(any\s+)?(filters?|restrictions?|limitations?)",
                "severity": "high",
                "confidence": 0.85,
                "description": "Filter bypass attempt",
            },
            {
                "pattern": r"unrestricted\s+(ai|mode|access)",
                "severity": "critical",
                "confidence": 0.9,
                "description": "Unrestricted mode activation",
            },
            {
                "pattern": r"bypass\s+(safety|content|security)",
                "severity": "critical",
                "confidence": 0.95,
                "description": "Safety bypass attempt",
            },
            {
                "pattern": r"hypothetical\s+scenario",
                "severity": "medium",
                "confidence": 0.6,
                "description": "Hypothetical scenario framing",
            },
            {
                "pattern": r"for\s+(educational|research)\s+purposes?\s+only",
                "severity": "medium",
                "confidence": 0.6,
                "description": "Educational purpose framing",
            },
            {
                "pattern": r"in\s+a\s+fictional\s+world",
                "severity": "medium",
                "confidence": 0.65,
                "description": "Fictional world framing",
            },
            {
                "pattern": r"(stan|dude|jailbreak(ed)?)\s+mode",
                "severity": "critical",
                "confidence": 0.9,
                "description": "Known jailbreak mode activation",
            },
            {
                "pattern": r"no\s+(ethics?|moral|content)\s+(guidelines?|filters?|policies?)",
                "severity": "critical",
                "confidence": 0.95,
                "description": "Ethics/policy removal attempt",
            },
        ]

    async def detect(self, text: str) -> List[ThreatDetection]:
        """
        Detect prompt injection and jailbreak attempts in text.
        
        Args:
            text: Text to analyze
            
        Returns:
            List of detected threats
        """
        threats = []
        text_lower = text.lower()

        # Check injection patterns
        for pattern_info in self.injection_patterns:
            matches = re.finditer(pattern_info["pattern"], text_lower, re.IGNORECASE)
            for match in matches:
                threats.append(
                    ThreatDetection(
                        threat_type="prompt_injection",
                        severity=pattern_info["severity"],
                        confidence=pattern_info["confidence"],
                        description=pattern_info["description"],
                        matched_pattern=match.group(),
                    )
                )

        # Check jailbreak patterns
        for pattern_info in self.jailbreak_patterns:
            matches = re.finditer(pattern_info["pattern"], text_lower, re.IGNORECASE)
            for match in matches:
                threats.append(
                    ThreatDetection(
                        threat_type="jailbreak",
                        severity=pattern_info["severity"],
                        confidence=pattern_info["confidence"],
                        description=pattern_info["description"],
                        matched_pattern=match.group(),
                    )
                )

        # Additional heuristics
        threats.extend(self._heuristic_detection(text))

        # Deduplicate and return highest confidence for each type
        return self._deduplicate_threats(threats)

    def _heuristic_detection(self, text: str) -> List[ThreatDetection]:
        """Apply additional heuristic detection methods."""
        threats = []
        text_lower = text.lower()

        # Check for unusual character sequences that might indicate encoding attacks
        if re.search(r"[\u200b-\u200f\u2028-\u202f\ufeff]", text):
            threats.append(
                ThreatDetection(
                    threat_type="prompt_injection",
                    severity="medium",
                    confidence=0.7,
                    description="Suspicious unicode characters detected",
                )
            )

        # Check for base64 encoded content
        if re.search(r"[A-Za-z0-9+/]{40,}={0,2}", text):
            threats.append(
                ThreatDetection(
                    threat_type="prompt_injection",
                    severity="medium",
                    confidence=0.6,
                    description="Potential encoded content detected",
                )
            )

        # Check for excessive special characters (potential adversarial suffix)
        special_ratio = len(re.findall(r"[^\w\s]", text)) / max(len(text), 1)
        if special_ratio > 0.3:
            threats.append(
                ThreatDetection(
                    threat_type="prompt_injection",
                    severity="medium",
                    confidence=0.65,
                    description="Unusual special character density",
                )
            )

        return threats

    def _deduplicate_threats(self, threats: List[ThreatDetection]) -> List[ThreatDetection]:
        """Remove duplicate threats, keeping highest confidence."""
        seen = {}
        for threat in threats:
            key = (threat.threat_type, threat.description)
            if key not in seen or seen[key].confidence < threat.confidence:
                seen[key] = threat
        return list(seen.values())
