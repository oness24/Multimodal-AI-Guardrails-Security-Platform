"""
Contextual validator for RAG-aware guardrails.
"""
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ContextualValidationResult:
    """Result from contextual validation."""

    is_valid: bool
    violations: List[Dict[str, Any]]
    confidence: float
    metadata: Optional[Dict[str, Any]] = None


class ContextualValidator:
    """
    Validator for context-aware guardrails.

    Validates inputs/outputs against provided context to detect:
    - Context manipulation attempts
    - Out-of-scope queries
    - Context leakage
    - RAG poisoning attempts
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize contextual validator.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.strict_mode = self.config.get("strict_mode", False)
        self.allow_out_of_scope = self.config.get("allow_out_of_scope", True)
        self.max_context_deviation = self.config.get("max_context_deviation", 0.7)

    async def validate_input_context(
        self,
        user_input: str,
        allowed_context: Optional[Dict[str, Any]] = None,
        rag_context: Optional[List[str]] = None,
    ) -> ContextualValidationResult:
        """
        Validate user input against allowed context.

        Args:
            user_input: User input to validate
            allowed_context: Dictionary defining allowed context boundaries
            rag_context: Retrieved context from RAG system

        Returns:
            Contextual validation result
        """
        violations = []
        confidence = 1.0

        # Check 1: Context manipulation detection
        if rag_context:
            manipulation = await self._detect_context_manipulation(
                user_input, rag_context
            )
            if manipulation["detected"]:
                violations.append(
                    {
                        "type": "context_manipulation",
                        "severity": "high",
                        "description": manipulation["description"],
                        "confidence": manipulation["confidence"],
                    }
                )
                confidence = min(confidence, 1 - manipulation["confidence"])

        # Check 2: Scope validation
        if allowed_context and "allowed_topics" in allowed_context:
            scope_check = await self._validate_scope(
                user_input, allowed_context["allowed_topics"]
            )
            if not scope_check["in_scope"] and not self.allow_out_of_scope:
                violations.append(
                    {
                        "type": "out_of_scope",
                        "severity": "medium",
                        "description": "Query outside allowed topic scope",
                        "confidence": scope_check["confidence"],
                    }
                )

        # Check 3: Context boundary violations
        if allowed_context and "boundaries" in allowed_context:
            boundary_check = await self._check_boundaries(
                user_input, allowed_context["boundaries"]
            )
            if boundary_check["violated"]:
                violations.append(
                    {
                        "type": "boundary_violation",
                        "severity": "high",
                        "description": boundary_check["description"],
                        "confidence": boundary_check["confidence"],
                    }
                )

        # Check 4: RAG poisoning attempts
        if rag_context:
            poisoning = await self._detect_rag_poisoning(user_input, rag_context)
            if poisoning["detected"]:
                violations.append(
                    {
                        "type": "rag_poisoning",
                        "severity": "critical",
                        "description": "Potential RAG poisoning attempt",
                        "confidence": poisoning["confidence"],
                    }
                )

        is_valid = len(violations) == 0

        logger.debug(
            f"Contextual validation: valid={is_valid}, violations={len(violations)}"
        )

        return ContextualValidationResult(
            is_valid=is_valid,
            violations=violations,
            confidence=confidence,
            metadata={
                "has_rag_context": rag_context is not None,
                "has_allowed_context": allowed_context is not None,
            },
        )

    async def validate_output_context(
        self,
        model_output: str,
        original_input: str,
        rag_context: Optional[List[str]] = None,
        allowed_context: Optional[Dict[str, Any]] = None,
    ) -> ContextualValidationResult:
        """
        Validate model output stays within context boundaries.

        Args:
            model_output: Model's output
            original_input: Original user input
            rag_context: Retrieved context used for generation
            allowed_context: Allowed context boundaries

        Returns:
            Contextual validation result
        """
        violations = []
        confidence = 1.0

        # Check 1: Context leakage detection
        if rag_context:
            leakage = await self._detect_context_leakage(model_output, rag_context)
            if leakage["detected"]:
                violations.append(
                    {
                        "type": "context_leakage",
                        "severity": "high",
                        "description": "Model output leaks RAG context",
                        "confidence": leakage["confidence"],
                        "leaked_items": leakage.get("leaked_items", []),
                    }
                )

        # Check 2: Hallucination detection (output deviates from context)
        if rag_context:
            hallucination = await self._detect_hallucination(
                model_output, rag_context, original_input
            )
            if hallucination["detected"]:
                violations.append(
                    {
                        "type": "hallucination",
                        "severity": "medium",
                        "description": "Output deviates significantly from provided context",
                        "confidence": hallucination["confidence"],
                    }
                )

        # Check 3: Unauthorized information disclosure
        if allowed_context and "restricted_info" in allowed_context:
            disclosure = await self._detect_unauthorized_disclosure(
                model_output, allowed_context["restricted_info"]
            )
            if disclosure["detected"]:
                violations.append(
                    {
                        "type": "unauthorized_disclosure",
                        "severity": "critical",
                        "description": "Output contains restricted information",
                        "confidence": disclosure["confidence"],
                    }
                )

        is_valid = len(violations) == 0

        return ContextualValidationResult(
            is_valid=is_valid,
            violations=violations,
            confidence=confidence,
            metadata={"output_length": len(model_output)},
        )

    async def _detect_context_manipulation(
        self, user_input: str, rag_context: List[str]
    ) -> Dict[str, Any]:
        """
        Detect attempts to manipulate RAG context.

        Args:
            user_input: User input
            rag_context: RAG context

        Returns:
            Detection result
        """
        input_lower = user_input.lower()

        # Patterns indicating context manipulation
        manipulation_patterns = [
            "ignore the context",
            "disregard the documents",
            "forget the retrieved",
            "override the context",
            "instead of using the context",
            "don't use the provided",
            "bypass the context",
        ]

        detected = any(pattern in input_lower for pattern in manipulation_patterns)

        # Check if input tries to inject new context
        injection_keywords = ["new context:", "updated context:", "replace context"]
        has_injection = any(keyword in input_lower for keyword in injection_keywords)

        confidence = 0.0
        description = ""

        if detected or has_injection:
            confidence = 0.8 if detected else 0.6
            description = "Input attempts to manipulate or override RAG context"

        return {
            "detected": detected or has_injection,
            "confidence": confidence,
            "description": description,
        }

    async def _validate_scope(
        self, user_input: str, allowed_topics: List[str]
    ) -> Dict[str, Any]:
        """
        Validate if input is within allowed topic scope.

        Args:
            user_input: User input
            allowed_topics: List of allowed topics

        Returns:
            Scope validation result
        """
        input_lower = user_input.lower()

        # Simple keyword-based scope checking
        # In production, use semantic similarity with embeddings
        in_scope = False
        matched_topic = None

        for topic in allowed_topics:
            topic_keywords = topic.lower().split()
            if any(keyword in input_lower for keyword in topic_keywords):
                in_scope = True
                matched_topic = topic
                break

        return {
            "in_scope": in_scope,
            "matched_topic": matched_topic,
            "confidence": 0.7 if in_scope else 0.5,  # Low confidence for simple matching
        }

    async def _check_boundaries(
        self, user_input: str, boundaries: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Check if input violates context boundaries.

        Args:
            user_input: User input
            boundaries: Boundary definitions

        Returns:
            Boundary check result
        """
        input_lower = user_input.lower()
        violated = False
        description = ""
        confidence = 0.0

        # Check forbidden keywords
        if "forbidden_keywords" in boundaries:
            for keyword in boundaries["forbidden_keywords"]:
                if keyword.lower() in input_lower:
                    violated = True
                    description = f"Contains forbidden keyword: {keyword}"
                    confidence = 0.9
                    break

        # Check required context elements
        if "required_context" in boundaries and not violated:
            required = boundaries["required_context"]
            if not any(req.lower() in input_lower for req in required):
                violated = True
                description = "Missing required context elements"
                confidence = 0.7

        return {
            "violated": violated,
            "description": description,
            "confidence": confidence,
        }

    async def _detect_rag_poisoning(
        self, user_input: str, rag_context: List[str]
    ) -> Dict[str, Any]:
        """
        Detect RAG poisoning attempts.

        Args:
            user_input: User input
            rag_context: RAG context

        Returns:
            Detection result
        """
        input_lower = user_input.lower()

        # Patterns indicating RAG poisoning attempts
        poisoning_patterns = [
            "add to your knowledge",
            "remember that",
            "update your information",
            "correct information:",
            "actually,",
            "the real answer is",
            "ignore what the document says",
        ]

        detected = any(pattern in input_lower for pattern in poisoning_patterns)

        # Check for contradictions to context
        contradiction_keywords = [
            "that's wrong",
            "incorrect",
            "actually",
            "the truth is",
        ]
        has_contradiction = any(kw in input_lower for kw in contradiction_keywords)

        confidence = 0.0
        if detected:
            confidence = 0.85
        elif has_contradiction:
            confidence = 0.6

        return {
            "detected": detected or has_contradiction,
            "confidence": confidence,
        }

    async def _detect_context_leakage(
        self, model_output: str, rag_context: List[str]
    ) -> Dict[str, Any]:
        """
        Detect if model output leaks RAG context verbatim.

        Args:
            model_output: Model output
            rag_context: RAG context

        Returns:
            Detection result
        """
        output_lower = model_output.lower()
        leaked_items = []

        # Check for verbatim context in output
        # This would leak internal documents/context
        for i, context_item in enumerate(rag_context):
            context_lower = context_item.lower()

            # Check if significant chunks appear verbatim
            # Split into sentences and check overlap
            context_sentences = [
                s.strip()
                for s in context_lower.split(".")
                if len(s.strip()) > 20
            ]

            for sentence in context_sentences:
                if sentence in output_lower:
                    leaked_items.append(
                        {"context_index": i, "leaked_text": sentence[:100]}
                    )

        detected = len(leaked_items) > 0
        confidence = min(len(leaked_items) * 0.3, 1.0) if detected else 0.0

        return {
            "detected": detected,
            "confidence": confidence,
            "leaked_items": leaked_items[:3],  # Limit to 3 examples
        }

    async def _detect_hallucination(
        self, model_output: str, rag_context: List[str], original_input: str
    ) -> Dict[str, Any]:
        """
        Detect if output hallucinates beyond provided context.

        Args:
            model_output: Model output
            rag_context: RAG context
            original_input: Original input

        Returns:
            Detection result
        """
        # Simple heuristic: Check if output contains factual statements
        # not present in context
        # In production, use semantic similarity with embeddings

        output_lower = model_output.lower()
        context_text = " ".join(rag_context).lower()

        # Keywords indicating factual statements
        factual_indicators = [
            " is ",
            " are ",
            " was ",
            " were ",
            " has ",
            " have ",
            "according to",
            "data shows",
            "research indicates",
        ]

        has_factual_claims = any(
            indicator in output_lower for indicator in factual_indicators
        )

        # Very simple overlap check (in production, use embeddings)
        if has_factual_claims and len(context_text) > 0:
            # Calculate rough word overlap
            output_words = set(output_lower.split())
            context_words = set(context_text.split())

            common_words = output_words & context_words
            overlap_ratio = len(common_words) / len(output_words) if output_words else 0

            # If overlap is too low, might be hallucinating
            detected = overlap_ratio < self.max_context_deviation
            confidence = 1 - overlap_ratio if detected else 0.0

            return {"detected": detected, "confidence": min(confidence, 0.8)}

        return {"detected": False, "confidence": 0.0}

    async def _detect_unauthorized_disclosure(
        self, model_output: str, restricted_info: List[str]
    ) -> Dict[str, Any]:
        """
        Detect unauthorized information disclosure.

        Args:
            model_output: Model output
            restricted_info: List of restricted information patterns

        Returns:
            Detection result
        """
        output_lower = model_output.lower()

        detected = False
        confidence = 0.0

        for restricted in restricted_info:
            if restricted.lower() in output_lower:
                detected = True
                confidence = 0.95
                break

        return {"detected": detected, "confidence": confidence}
