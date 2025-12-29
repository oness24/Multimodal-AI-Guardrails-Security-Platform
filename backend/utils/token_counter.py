"""
Token Counter utility for accurate token counting.
Prevents DoS attacks via context overflow and enables cost estimation.
"""
import re
from functools import lru_cache
from typing import List, Optional, Union

# Try to import tiktoken, fall back to estimation if not available
try:
    import tiktoken
    TIKTOKEN_AVAILABLE = True
except ImportError:
    TIKTOKEN_AVAILABLE = False


# Model to encoding mapping
MODEL_ENCODINGS = {
    # OpenAI GPT-4 models
    "gpt-4": "cl100k_base",
    "gpt-4-turbo": "cl100k_base",
    "gpt-4-turbo-preview": "cl100k_base",
    "gpt-4o": "o200k_base",
    "gpt-4o-mini": "o200k_base",
    "gpt-4-vision-preview": "cl100k_base",
    # OpenAI GPT-3.5 models
    "gpt-3.5-turbo": "cl100k_base",
    "gpt-3.5-turbo-16k": "cl100k_base",
    # OpenAI Embedding models
    "text-embedding-3-small": "cl100k_base",
    "text-embedding-3-large": "cl100k_base",
    "text-embedding-ada-002": "cl100k_base",
    # Anthropic Claude models (approximate with cl100k)
    "claude-3-opus-20240229": "cl100k_base",
    "claude-3-sonnet-20240229": "cl100k_base",
    "claude-3-haiku-20240307": "cl100k_base",
    "claude-3-5-sonnet-20241022": "cl100k_base",
}

# Default encoding for unknown models
DEFAULT_ENCODING = "cl100k_base"

# Context length limits per model
MODEL_CONTEXT_LIMITS = {
    # OpenAI models
    "gpt-4": 8192,
    "gpt-4-turbo": 128000,
    "gpt-4-turbo-preview": 128000,
    "gpt-4o": 128000,
    "gpt-4o-mini": 128000,
    "gpt-4-vision-preview": 128000,
    "gpt-3.5-turbo": 16385,
    "gpt-3.5-turbo-16k": 16385,
    # Anthropic models
    "claude-3-opus-20240229": 200000,
    "claude-3-sonnet-20240229": 200000,
    "claude-3-haiku-20240307": 200000,
    "claude-3-5-sonnet-20241022": 200000,
    # Local models (Ollama)
    "llama2": 4096,
    "llama3": 8192,
    "mistral": 8192,
    "codellama": 16384,
}

DEFAULT_CONTEXT_LIMIT = 4096


@lru_cache(maxsize=10)
def _get_encoding(encoding_name: str):
    """Get tiktoken encoding with caching."""
    if TIKTOKEN_AVAILABLE:
        return tiktoken.get_encoding(encoding_name)
    return None


def _estimate_tokens_simple(text: str) -> int:
    """
    Simple token estimation when tiktoken is not available.
    Roughly 4 characters per token for English text.
    """
    # Count words and special characters
    words = len(text.split())
    special_chars = len(re.findall(r'[^\w\s]', text))
    
    # Estimate: ~1.3 tokens per word + special characters
    return int(words * 1.3 + special_chars)


class TokenCounter:
    """
    Token counter for LLM inputs/outputs.
    Uses tiktoken when available, falls back to estimation.
    """

    def __init__(self, model: Optional[str] = None):
        self.model = model
        self._encoding_name = MODEL_ENCODINGS.get(model or "", DEFAULT_ENCODING)
        self._encoding = _get_encoding(self._encoding_name) if TIKTOKEN_AVAILABLE else None

    def count_tokens(self, text: str) -> int:
        """Count tokens in a text string."""
        if not text:
            return 0
        
        if self._encoding:
            return len(self._encoding.encode(text))
        return _estimate_tokens_simple(text)

    def count_message_tokens(self, messages: List[dict]) -> int:
        """
        Count tokens in a list of chat messages.
        Accounts for message formatting overhead.
        """
        total = 0
        
        for message in messages:
            # Each message has ~4 tokens overhead for role, separators
            total += 4
            
            role = message.get("role", "")
            content = message.get("content", "")
            
            total += self.count_tokens(role)
            
            # Handle string content
            if isinstance(content, str):
                total += self.count_tokens(content)
            # Handle multimodal content (list of content parts)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict):
                        if part.get("type") == "text":
                            total += self.count_tokens(part.get("text", ""))
                        elif part.get("type") == "image_url":
                            # Images use ~85 tokens for low detail, ~765 for high
                            detail = part.get("image_url", {}).get("detail", "auto")
                            total += 85 if detail == "low" else 765
            
            # Function/tool calls add overhead
            if "function_call" in message or "tool_calls" in message:
                total += 50  # Approximate overhead for function calls
        
        # Add 3 tokens for assistant reply priming
        total += 3
        
        return total

    def get_context_limit(self, model: Optional[str] = None) -> int:
        """Get the context length limit for a model."""
        model = model or self.model
        return MODEL_CONTEXT_LIMITS.get(model or "", DEFAULT_CONTEXT_LIMIT)

    def check_within_limit(
        self,
        text_or_messages: Union[str, List[dict]],
        model: Optional[str] = None,
        reserved_output_tokens: int = 1000,
    ) -> tuple[bool, int, int]:
        """
        Check if input is within the model's context limit.
        
        Args:
            text_or_messages: Input text or messages to check
            model: Model to check against (uses instance model if not specified)
            reserved_output_tokens: Tokens to reserve for model output
            
        Returns:
            (is_within_limit, token_count, available_tokens)
        """
        model = model or self.model
        context_limit = self.get_context_limit(model)
        available = context_limit - reserved_output_tokens
        
        if isinstance(text_or_messages, str):
            token_count = self.count_tokens(text_or_messages)
        else:
            token_count = self.count_message_tokens(text_or_messages)
        
        return token_count <= available, token_count, available

    def truncate_to_limit(
        self,
        text: str,
        max_tokens: int,
        truncation_indicator: str = "... [truncated]",
    ) -> str:
        """
        Truncate text to fit within token limit.
        
        Args:
            text: Text to truncate
            max_tokens: Maximum tokens allowed
            truncation_indicator: Text to append when truncated
            
        Returns:
            Truncated text
        """
        current_tokens = self.count_tokens(text)
        
        if current_tokens <= max_tokens:
            return text
        
        indicator_tokens = self.count_tokens(truncation_indicator)
        target_tokens = max_tokens - indicator_tokens
        
        if target_tokens <= 0:
            return truncation_indicator
        
        # Binary search for the right length
        if self._encoding:
            tokens = self._encoding.encode(text)
            truncated_tokens = tokens[:target_tokens]
            truncated_text = self._encoding.decode(truncated_tokens)
            return truncated_text + truncation_indicator
        else:
            # Approximate truncation for estimation mode
            ratio = target_tokens / current_tokens
            char_limit = int(len(text) * ratio)
            return text[:char_limit] + truncation_indicator


class TokenLimitExceeded(Exception):
    """Raised when input exceeds token limit."""
    def __init__(self, token_count: int, limit: int, model: str):
        self.token_count = token_count
        self.limit = limit
        self.model = model
        super().__init__(
            f"Input ({token_count} tokens) exceeds limit ({limit} tokens) for model {model}"
        )


# Convenience functions
def count_tokens(text: str, model: Optional[str] = None) -> int:
    """Count tokens in text."""
    counter = TokenCounter(model)
    return counter.count_tokens(text)


def count_message_tokens(messages: List[dict], model: Optional[str] = None) -> int:
    """Count tokens in chat messages."""
    counter = TokenCounter(model)
    return counter.count_message_tokens(messages)


def check_token_limit(
    text_or_messages: Union[str, List[dict]],
    model: str,
    reserved_output: int = 1000,
) -> tuple[bool, int, int]:
    """Check if input is within model's context limit."""
    counter = TokenCounter(model)
    return counter.check_within_limit(text_or_messages, model, reserved_output)


def get_model_context_limit(model: str) -> int:
    """Get context limit for a model."""
    return MODEL_CONTEXT_LIMITS.get(model, DEFAULT_CONTEXT_LIMIT)


def is_tiktoken_available() -> bool:
    """Check if tiktoken is available for accurate counting."""
    return TIKTOKEN_AVAILABLE
