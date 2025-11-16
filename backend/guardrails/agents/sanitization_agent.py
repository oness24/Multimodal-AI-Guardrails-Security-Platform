"""
Sanitization agent for cleaning and normalizing user inputs.
"""
import html
import logging
import re
import unicodedata
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SanitizationAgent:
    """
    Agent responsible for cleaning and normalizing user inputs.

    Performs multiple sanitization operations:
    - HTML/script tag removal
    - Unicode normalization
    - Control character removal
    - Whitespace normalization
    - Length validation
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize sanitization agent.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.max_length = self.config.get("max_length", 10000)
        self.normalize_unicode = self.config.get("normalize_unicode", True)
        self.remove_html = self.config.get("remove_html", True)
        self.modifications: List[Dict[str, Any]] = []

    async def clean(self, text: str) -> str:
        """
        Clean and sanitize input text.

        Args:
            text: Input text to sanitize

        Returns:
            Sanitized text
        """
        self.modifications = []
        original_text = text

        # Step 1: Length validation
        if len(text) > self.max_length:
            text = text[: self.max_length]
            self.modifications.append(
                {
                    "type": "truncation",
                    "reason": f"Input exceeded max length of {self.max_length}",
                    "original_length": len(original_text),
                    "new_length": len(text),
                }
            )

        # Step 2: HTML entity decoding
        decoded_text = html.unescape(text)
        if decoded_text != text:
            self.modifications.append(
                {"type": "html_decode", "reason": "Decoded HTML entities"}
            )
            text = decoded_text

        # Step 3: Remove HTML/script tags if enabled
        if self.remove_html:
            cleaned = self._remove_html_tags(text)
            if cleaned != text:
                self.modifications.append(
                    {"type": "html_removal", "reason": "Removed HTML/script tags"}
                )
                text = cleaned

        # Step 4: Unicode normalization
        if self.normalize_unicode:
            normalized = self._normalize_unicode(text)
            if normalized != text:
                self.modifications.append(
                    {"type": "unicode_normalization", "reason": "Normalized Unicode"}
                )
                text = normalized

        # Step 5: Remove control characters
        cleaned_control = self._remove_control_characters(text)
        if cleaned_control != text:
            self.modifications.append(
                {
                    "type": "control_char_removal",
                    "reason": "Removed control characters",
                }
            )
            text = cleaned_control

        # Step 6: Normalize whitespace
        normalized_ws = self._normalize_whitespace(text)
        if normalized_ws != text:
            self.modifications.append(
                {"type": "whitespace_normalization", "reason": "Normalized whitespace"}
            )
            text = normalized_ws

        # Step 7: Remove zero-width characters
        cleaned_zw = self._remove_zero_width_chars(text)
        if cleaned_zw != text:
            self.modifications.append(
                {
                    "type": "zero_width_removal",
                    "reason": "Removed zero-width characters",
                }
            )
            text = cleaned_zw

        if text != original_text:
            logger.debug(
                f"Sanitization applied {len(self.modifications)} modifications"
            )

        return text

    def _remove_html_tags(self, text: str) -> str:
        """
        Remove HTML and script tags from text.

        Args:
            text: Input text

        Returns:
            Text with HTML tags removed
        """
        # Remove script tags and content
        text = re.sub(
            r"<script[^>]*>.*?</script>", "", text, flags=re.IGNORECASE | re.DOTALL
        )

        # Remove style tags and content
        text = re.sub(
            r"<style[^>]*>.*?</style>", "", text, flags=re.IGNORECASE | re.DOTALL
        )

        # Remove HTML tags
        text = re.sub(r"<[^>]+>", "", text)

        return text

    def _normalize_unicode(self, text: str) -> str:
        """
        Normalize Unicode characters to NFC form.

        Args:
            text: Input text

        Returns:
            Normalized text
        """
        return unicodedata.normalize("NFC", text)

    def _remove_control_characters(self, text: str) -> str:
        """
        Remove control characters except newline, tab, and carriage return.

        Args:
            text: Input text

        Returns:
            Text with control characters removed
        """
        # Keep \n, \r, \t but remove other control characters
        return "".join(
            char
            for char in text
            if unicodedata.category(char)[0] != "C" or char in "\n\r\t"
        )

    def _normalize_whitespace(self, text: str) -> str:
        """
        Normalize whitespace characters.

        Args:
            text: Input text

        Returns:
            Text with normalized whitespace
        """
        # Replace multiple spaces with single space
        text = re.sub(r" +", " ", text)

        # Replace multiple newlines with max 2 newlines
        text = re.sub(r"\n{3,}", "\n\n", text)

        # Trim leading/trailing whitespace
        text = text.strip()

        return text

    def _remove_zero_width_chars(self, text: str) -> str:
        """
        Remove zero-width characters that might be used for obfuscation.

        Args:
            text: Input text

        Returns:
            Text with zero-width characters removed
        """
        zero_width_chars = [
            "\u200b",  # Zero-width space
            "\u200c",  # Zero-width non-joiner
            "\u200d",  # Zero-width joiner
            "\ufeff",  # Zero-width no-break space
            "\u00ad",  # Soft hyphen
        ]

        for char in zero_width_chars:
            text = text.replace(char, "")

        return text

    def get_modifications(self) -> List[Dict[str, Any]]:
        """
        Get list of modifications made during sanitization.

        Returns:
            List of modification records
        """
        return self.modifications

    async def validate_length(self, text: str, max_length: Optional[int] = None) -> bool:
        """
        Validate text length.

        Args:
            text: Text to validate
            max_length: Maximum allowed length (defaults to configured max_length)

        Returns:
            True if valid length, False otherwise
        """
        limit = max_length or self.max_length
        return len(text) <= limit

    async def estimate_tokens(self, text: str) -> int:
        """
        Estimate token count for text (rough approximation).

        Args:
            text: Text to estimate tokens for

        Returns:
            Estimated token count
        """
        # Rough estimate: ~4 characters per token
        return len(text) // 4
