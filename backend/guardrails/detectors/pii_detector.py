"""
PII (Personally Identifiable Information) detector using Presidio.
"""
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Try to import Presidio, fall back to basic regex if not available
try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False
    logger.warning(
        "Presidio not available. PII detection will use basic pattern matching."
    )

import re


@dataclass
class PIIEntity:
    """Detected PII entity."""

    type: str
    text: str
    score: float
    start: int
    end: int


@dataclass
class PIIDetectionResult:
    """Result from PII detection."""

    detected: bool
    entities: List[PIIEntity]
    entity_types: List[str]
    total_count: int


class PIIDetector:
    """
    PII detector using Presidio Analyzer or fallback regex patterns.

    Detects common PII types:
    - Email addresses
    - Phone numbers
    - Credit card numbers
    - Social Security Numbers
    - IP addresses
    - Names (with Presidio)
    - Addresses (with Presidio)
    """

    # Fallback regex patterns when Presidio is not available
    FALLBACK_PATTERNS = {
        "EMAIL_ADDRESS": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "PHONE_NUMBER": r"\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b",
        "CREDIT_CARD": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b",
        "SSN": r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
        "IP_ADDRESS": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        "URL": r"https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)",
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize PII detector.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.min_score = self.config.get("min_score", 0.5)
        self.use_presidio = self.config.get("use_presidio", True) and PRESIDIO_AVAILABLE

        # Initialize Presidio if available
        if self.use_presidio:
            try:
                # Create NLP engine configuration
                nlp_configuration = {
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
                }

                # Try to create NLP engine provider
                try:
                    provider = NlpEngineProvider(nlp_configuration=nlp_configuration)
                    nlp_engine = provider.create_engine()
                    self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
                    logger.info("Presidio PII detector initialized with spaCy")
                except Exception as e:
                    # Fall back to basic configuration
                    logger.warning(
                        f"Could not initialize spaCy model: {e}. Using basic Presidio configuration."
                    )
                    self.analyzer = AnalyzerEngine()

            except Exception as e:
                logger.error(f"Failed to initialize Presidio: {e}")
                self.use_presidio = False
                logger.info("Falling back to regex-based PII detection")
        else:
            logger.info("Using regex-based PII detection (Presidio not available)")

        # Compile fallback patterns
        self.compiled_patterns = {
            entity_type: re.compile(pattern)
            for entity_type, pattern in self.FALLBACK_PATTERNS.items()
        }

    async def detect(self, text: str) -> PIIDetectionResult:
        """
        Detect PII in text.

        Args:
            text: Input text to analyze

        Returns:
            PII detection result
        """
        if self.use_presidio:
            return await self._detect_with_presidio(text)
        else:
            return await self._detect_with_regex(text)

    async def _detect_with_presidio(self, text: str) -> PIIDetectionResult:
        """
        Detect PII using Presidio Analyzer.

        Args:
            text: Input text

        Returns:
            Detection result
        """
        try:
            # Analyze text
            results = self.analyzer.analyze(
                text=text,
                language="en",
                score_threshold=self.min_score,
            )

            # Convert to our format
            entities = []
            entity_types = set()

            for result in results:
                entity = PIIEntity(
                    type=result.entity_type,
                    text=text[result.start : result.end],
                    score=result.score,
                    start=result.start,
                    end=result.end,
                )
                entities.append(entity)
                entity_types.add(result.entity_type)

            logger.debug(
                f"Presidio detected {len(entities)} PII entities: {list(entity_types)}"
            )

            return PIIDetectionResult(
                detected=len(entities) > 0,
                entities=entities,
                entity_types=list(entity_types),
                total_count=len(entities),
            )

        except Exception as e:
            logger.error(f"Presidio detection failed: {e}. Falling back to regex.")
            return await self._detect_with_regex(text)

    async def _detect_with_regex(self, text: str) -> PIIDetectionResult:
        """
        Detect PII using regex patterns (fallback method).

        Args:
            text: Input text

        Returns:
            Detection result
        """
        entities = []
        entity_types = set()

        for entity_type, pattern in self.compiled_patterns.items():
            matches = pattern.finditer(text)
            for match in matches:
                entity = PIIEntity(
                    type=entity_type,
                    text=match.group(0),
                    score=1.0,  # Regex matches are considered 100% confident
                    start=match.start(),
                    end=match.end(),
                )
                entities.append(entity)
                entity_types.add(entity_type)

        logger.debug(
            f"Regex detected {len(entities)} PII entities: {list(entity_types)}"
        )

        return PIIDetectionResult(
            detected=len(entities) > 0,
            entities=entities,
            entity_types=list(entity_types),
            total_count=len(entities),
        )

    async def anonymize(self, text: str, replacement: str = "[REDACTED]") -> str:
        """
        Anonymize detected PII in text.

        Args:
            text: Input text
            replacement: Replacement string for PII

        Returns:
            Anonymized text
        """
        result = await self.detect(text)

        if not result.detected:
            return text

        # Sort entities by start position in reverse order
        # This allows us to replace from end to start without offset issues
        sorted_entities = sorted(result.entities, key=lambda e: e.start, reverse=True)

        anonymized = text
        for entity in sorted_entities:
            anonymized = (
                anonymized[: entity.start]
                + f"{replacement}({entity.type})"
                + anonymized[entity.end :]
            )

        return anonymized

    async def get_entity_details(
        self, text: str, entity_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Get detailed information about detected entities.

        Args:
            text: Input text
            entity_types: Optional filter for specific entity types

        Returns:
            Detailed entity information
        """
        result = await self.detect(text)

        # Filter by entity types if specified
        entities = result.entities
        if entity_types:
            entities = [e for e in entities if e.type in entity_types]

        # Group by type
        by_type = {}
        for entity in entities:
            if entity.type not in by_type:
                by_type[entity.type] = []
            by_type[entity.type].append(
                {
                    "text": entity.text,
                    "score": entity.score,
                    "position": (entity.start, entity.end),
                }
            )

        return {
            "total_entities": len(entities),
            "entity_types": list(by_type.keys()),
            "entities_by_type": by_type,
            "contains_high_risk": any(
                e.type in ["CREDIT_CARD", "SSN", "PASSWORD"] for e in entities
            ),
        }
