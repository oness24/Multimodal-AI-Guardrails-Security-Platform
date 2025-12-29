"""
Base LLM client interface and shared functionality.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import AsyncGenerator, List, Optional


class LLMProvider(str, Enum):
    """Supported LLM providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"


@dataclass
class Message:
    """Chat message structure."""
    role: str  # system, user, assistant
    content: str


@dataclass
class LLMResponse:
    """Standardized LLM response."""
    content: str
    model: str
    provider: LLMProvider
    usage: Optional[dict] = None
    finish_reason: Optional[str] = None
    metadata: Optional[dict] = None


class BaseLLMClient(ABC):
    """Abstract base class for LLM clients."""

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None):
        self.api_key = api_key
        self.base_url = base_url

    @property
    @abstractmethod
    def provider(self) -> LLMProvider:
        """Return the provider type."""
        pass

    @property
    @abstractmethod
    def available_models(self) -> List[str]:
        """Return list of available models."""
        pass

    @abstractmethod
    async def chat(
        self,
        messages: List[Message],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs,
    ) -> LLMResponse:
        """Send a chat completion request."""
        pass

    @abstractmethod
    async def chat_stream(
        self,
        messages: List[Message],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs,
    ) -> AsyncGenerator[str, None]:
        """Stream a chat completion response."""
        pass

    def format_messages(self, messages: List[Message]) -> List[dict]:
        """Convert Message objects to API format."""
        return [{"role": m.role, "content": m.content} for m in messages]

    async def test_connection(self) -> bool:
        """Test if the client can connect to the provider."""
        try:
            response = await self.chat(
                messages=[Message(role="user", content="Hello")],
                max_tokens=5,
            )
            return bool(response.content)
        except Exception:
            return False
