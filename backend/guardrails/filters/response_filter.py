"""
Advanced response filtering and sanitization.
"""
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class FilterResult:
    """Result from response filtering."""

    filtered_text: str
    modifications: List[Dict[str, Any]]
    blocked: bool
    reason: Optional[str] = None


class ResponseFilter:
    """
    Advanced filter for model outputs.

    Filters and sanitizes model responses for:
    - PII redaction
    - Toxic content removal
    - Unsafe code/commands
    - Restricted keywords
    - Format violations
    """

    # Unsafe code patterns
    UNSAFE_CODE_PATTERNS = {
        "shell_injection": [
            r";\s*rm\s+-rf",
            r";\s*sudo\s+",
            r"\|\s*bash",
            r"eval\s*\(",
            r"exec\s*\(",
            r"__import__\s*\(",
            r"system\s*\(",
        ],
        "sql_injection": [
            r";\s*DROP\s+TABLE",
            r";\s*DELETE\s+FROM",
            r"UNION\s+SELECT",
            r"--\s*$",
        ],
        "path_traversal": [
            r"\.\./",
            r"\.\.\\",
        ],
    }

    # Restricted output patterns
    RESTRICTED_PATTERNS = [
        r"<script[^>]*>.*?</script>",  # Script tags
        r"javascript:",  # JavaScript protocol
        r"on\w+\s*=",  # Event handlers
        r"<iframe",  # Iframes
        r"eval\(",  # eval calls
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize response filter.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.enable_pii_redaction = self.config.get("enable_pii_redaction", True)
        self.enable_code_filtering = self.config.get("enable_code_filtering", True)
        self.enable_format_validation = self.config.get(
            "enable_format_validation", True
        )
        self.blocked_keywords = set(self.config.get("blocked_keywords", []))
        self.max_length = self.config.get("max_length", 5000)

        # Compile patterns for performance
        self.compiled_unsafe_patterns = {}
        for category, patterns in self.UNSAFE_CODE_PATTERNS.items():
            self.compiled_unsafe_patterns[category] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]

        self.compiled_restricted = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.RESTRICTED_PATTERNS
        ]

    async def filter_response(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
        pii_entities: Optional[List[Any]] = None,
    ) -> FilterResult:
        """
        Filter and sanitize model response.

        Args:
            text: Response text to filter
            context: Optional context
            pii_entities: Optional PII entities detected

        Returns:
            Filter result with modifications
        """
        filtered = text
        modifications = []
        blocked = False
        reason = None

        # Step 1: Length validation
        if len(filtered) > self.max_length:
            filtered = filtered[: self.max_length]
            modifications.append(
                {
                    "type": "truncation",
                    "original_length": len(text),
                    "new_length": self.max_length,
                }
            )

        # Step 2: PII redaction
        if self.enable_pii_redaction and pii_entities:
            result = self._redact_pii(filtered, pii_entities)
            if result["modified"]:
                filtered = result["text"]
                modifications.append(
                    {
                        "type": "pii_redaction",
                        "entities_redacted": result["count"],
                        "entity_types": result["types"],
                    }
                )

        # Step 3: Unsafe code filtering
        if self.enable_code_filtering:
            result = await self._filter_unsafe_code(filtered)
            if result["blocked"]:
                blocked = True
                reason = f"Contains unsafe code: {result['category']}"
                return FilterResult(
                    filtered_text="[BLOCKED: Unsafe code detected]",
                    modifications=modifications,
                    blocked=True,
                    reason=reason,
                )
            elif result["modified"]:
                filtered = result["text"]
                modifications.append(
                    {
                        "type": "code_filtering",
                        "patterns_removed": result["patterns_removed"],
                    }
                )

        # Step 4: Restricted pattern removal
        result = self._remove_restricted_patterns(filtered)
        if result["modified"]:
            filtered = result["text"]
            modifications.append(
                {
                    "type": "restricted_pattern_removal",
                    "patterns_removed": result["count"],
                }
            )

        # Step 5: Blocked keywords check
        if self.blocked_keywords:
            result = self._check_blocked_keywords(filtered)
            if result["found"]:
                blocked = True
                reason = f"Contains blocked keywords: {result['keywords']}"
                return FilterResult(
                    filtered_text="[BLOCKED: Restricted content]",
                    modifications=modifications,
                    blocked=True,
                    reason=reason,
                )

        # Step 6: Format validation
        if self.enable_format_validation:
            result = await self._validate_format(filtered, context)
            if not result["valid"]:
                modifications.append(
                    {
                        "type": "format_correction",
                        "issues": result["issues"],
                    }
                )
                filtered = result["corrected_text"]

        logger.debug(
            f"Response filtering: blocked={blocked}, modifications={len(modifications)}"
        )

        return FilterResult(
            filtered_text=filtered,
            modifications=modifications,
            blocked=blocked,
            reason=reason,
        )

    def _redact_pii(
        self, text: str, pii_entities: List[Any]
    ) -> Dict[str, Any]:
        """
        Redact PII from text.

        Args:
            text: Input text
            pii_entities: Detected PII entities

        Returns:
            Redaction result
        """
        redacted = text
        count = 0
        types = set()

        # Sort entities by start position in reverse order
        sorted_entities = sorted(pii_entities, key=lambda e: e.start, reverse=True)

        for entity in sorted_entities:
            # Redact the entity
            redacted = (
                redacted[: entity.start]
                + f"[REDACTED-{entity.type}]"
                + redacted[entity.end :]
            )
            count += 1
            types.add(entity.type)

        return {
            "modified": count > 0,
            "text": redacted,
            "count": count,
            "types": list(types),
        }

    async def _filter_unsafe_code(self, text: str) -> Dict[str, Any]:
        """
        Filter unsafe code patterns.

        Args:
            text: Input text

        Returns:
            Filtering result
        """
        # Check for critical unsafe patterns (block immediately)
        for category, patterns in self.compiled_unsafe_patterns.items():
            for pattern in patterns:
                if pattern.search(text):
                    logger.warning(
                        f"Blocked response containing unsafe {category} pattern"
                    )
                    return {
                        "blocked": True,
                        "modified": False,
                        "text": text,
                        "category": category,
                        "patterns_removed": 0,
                    }

        return {
            "blocked": False,
            "modified": False,
            "text": text,
            "category": None,
            "patterns_removed": 0,
        }

    def _remove_restricted_patterns(self, text: str) -> Dict[str, Any]:
        """
        Remove restricted patterns from text.

        Args:
            text: Input text

        Returns:
            Removal result
        """
        cleaned = text
        count = 0

        for pattern in self.compiled_restricted:
            matches = pattern.findall(cleaned)
            if matches:
                cleaned = pattern.sub("[REMOVED]", cleaned)
                count += len(matches)

        return {"modified": count > 0, "text": cleaned, "count": count}

    def _check_blocked_keywords(self, text: str) -> Dict[str, Any]:
        """
        Check for blocked keywords.

        Args:
            text: Input text

        Returns:
            Check result
        """
        text_lower = text.lower()
        found_keywords = []

        for keyword in self.blocked_keywords:
            if keyword.lower() in text_lower:
                found_keywords.append(keyword)

        return {"found": len(found_keywords) > 0, "keywords": found_keywords[:3]}

    async def _validate_format(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate response format.

        Args:
            text: Response text
            context: Optional context

        Returns:
            Validation result
        """
        issues = []
        corrected = text

        # Check for balanced markdown code blocks
        code_block_pattern = r"```"
        code_blocks = re.findall(code_block_pattern, text)
        if len(code_blocks) % 2 != 0:
            issues.append("unbalanced_code_blocks")
            corrected += "\n```"  # Close the block

        # Check for balanced quotes
        quote_count = text.count('"')
        if quote_count % 2 != 0:
            issues.append("unbalanced_quotes")

        # Check for excessive newlines
        if "\n\n\n\n" in text:
            issues.append("excessive_newlines")
            corrected = re.sub(r"\n{4,}", "\n\n\n", corrected)

        # Check for trailing whitespace
        if corrected != corrected.rstrip():
            issues.append("trailing_whitespace")
            corrected = corrected.rstrip()

        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "corrected_text": corrected,
        }

    async def filter_streaming_chunk(
        self, chunk: str, state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Filter streaming response chunk.

        Args:
            chunk: Response chunk
            state: Streaming state

        Returns:
            Filtered chunk and updated state
        """
        # Accumulate chunks in state
        if "accumulated" not in state:
            state["accumulated"] = ""

        state["accumulated"] += chunk

        # Check accumulated text length
        if len(state["accumulated"]) > self.max_length:
            return {
                "chunk": "",
                "blocked": True,
                "reason": "Exceeded max length",
                "state": state,
            }

        # Quick safety check on chunk
        for category, patterns in self.compiled_unsafe_patterns.items():
            for pattern in patterns:
                if pattern.search(chunk):
                    return {
                        "chunk": "",
                        "blocked": True,
                        "reason": f"Unsafe {category} detected",
                        "state": state,
                    }

        # Check for blocked keywords
        if self.blocked_keywords:
            chunk_lower = chunk.lower()
            for keyword in self.blocked_keywords:
                if keyword.lower() in chunk_lower:
                    return {
                        "chunk": "",
                        "blocked": True,
                        "reason": f"Blocked keyword: {keyword}",
                        "state": state,
                    }

        return {"chunk": chunk, "blocked": False, "reason": None, "state": state}

    async def apply_custom_filter(
        self, text: str, filter_func: Any
    ) -> FilterResult:
        """
        Apply custom filter function.

        Args:
            text: Input text
            filter_func: Custom filter function (text -> FilterResult)

        Returns:
            Filter result
        """
        try:
            result = await filter_func(text)
            return result
        except Exception as e:
            logger.error(f"Custom filter failed: {e}")
            return FilterResult(
                filtered_text=text,
                modifications=[],
                blocked=False,
                reason=None,
            )

    def add_blocked_keyword(self, keyword: str) -> None:
        """Add a keyword to the blocked list."""
        self.blocked_keywords.add(keyword)
        logger.info(f"Added blocked keyword: {keyword}")

    def remove_blocked_keyword(self, keyword: str) -> None:
        """Remove a keyword from the blocked list."""
        self.blocked_keywords.discard(keyword)
        logger.info(f"Removed blocked keyword: {keyword}")

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get filter statistics.

        Returns:
            Statistics dictionary
        """
        return {
            "blocked_keywords_count": len(self.blocked_keywords),
            "unsafe_code_categories": list(self.compiled_unsafe_patterns.keys()),
            "restricted_patterns_count": len(self.compiled_restricted),
            "config": {
                "pii_redaction_enabled": self.enable_pii_redaction,
                "code_filtering_enabled": self.enable_code_filtering,
                "format_validation_enabled": self.enable_format_validation,
                "max_length": self.max_length,
            },
        }
