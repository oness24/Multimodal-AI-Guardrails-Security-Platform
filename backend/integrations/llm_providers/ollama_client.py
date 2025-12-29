"""
Ollama local LLM client implementation.
"""
import httpx
from typing import AsyncGenerator, List, Optional

from backend.core.config import settings
from backend.integrations.llm_providers.base import (
    BaseLLMClient,
    LLMProvider,
    LLMResponse,
    Message,
)from backend.utils.rate_limiter import (
    RateLimitExceeded,
    get_rate_limiter,
)

class OllamaClient(BaseLLMClient):
    """Ollama local LLM client."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        super().__init__(api_key, base_url)
        self.base_url = base_url or settings.ollama_base_url
        self.default_model = "llama2"

    @property
    def provider(self) -> LLMProvider:
        return LLMProvider.OLLAMA

    @property
    def available_models(self) -> List[str]:
        return [
            "llama2",
            "llama2:70b",
            "mistral",
            "mixtral",
            "codellama",
            "phi",
            "neural-chat",
            "starling-lm",
        ]

    async def list_local_models(self) -> List[str]:
        """Get list of models available locally in Ollama."""
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{self.base_url}/api/tags")
            if response.status_code == 200:
                data = response.json()
                return [model["name"] for model in data.get("models", [])]
            return []

    async def chat(
        self,
        messages: List[Message],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        skip_rate_limit: bool = False,
        **kwargs,
    ) -> LLMResponse:
        """Send a chat completion request to Ollama."""
        model = model or self.default_model
        rate_limiter = get_rate_limiter()
        
        # Rate limiting for local models (prevents overwhelming local resources)
        if not skip_rate_limit:
            if not await rate_limiter.acquire_with_wait(timeout=60.0):
                raise RateLimitExceeded("Rate limit exceeded for local model")

        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": model,
                    "messages": self.format_messages(messages),
                    "stream": False,
                    "options": {
                        "temperature": temperature,
                        **({"num_predict": max_tokens} if max_tokens else {}),
                    },
                },
            )
            response.raise_for_status()
            data = response.json()
            
            input_tokens = data.get("prompt_eval_count", 0)
            output_tokens = data.get("eval_count", 0)
            
            # Record usage (cost is 0 for local models)
            rate_limiter.record_usage(
                provider=self.provider.value,
                model=model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                endpoint="chat",
            )

            return LLMResponse(
                content=data.get("message", {}).get("content", ""),
                model=model,
                provider=self.provider,
                usage={
                    "prompt_tokens": input_tokens,
                    "completion_tokens": output_tokens,
                    "total_tokens": input_tokens + output_tokens,
                },
                finish_reason="stop" if data.get("done") else None,
            )

    async def chat_stream(
        self,
        messages: List[Message],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs,
    ) -> AsyncGenerator[str, None]:
        """Stream a chat completion response from Ollama."""
        model = model or self.default_model

        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/api/chat",
                json={
                    "model": model,
                    "messages": self.format_messages(messages),
                    "stream": True,
                    "options": {
                        "temperature": temperature,
                        **({"num_predict": max_tokens} if max_tokens else {}),
                    },
                },
            ) as response:
                import json
                async for line in response.aiter_lines():
                    if line:
                        data = json.loads(line)
                        if content := data.get("message", {}).get("content"):
                            yield content

    async def pull_model(self, model: str) -> bool:
        """Pull a model to local Ollama instance."""
        async with httpx.AsyncClient(timeout=600.0) as client:
            response = await client.post(
                f"{self.base_url}/api/pull",
                json={"name": model},
            )
            return response.status_code == 200

    async def test_connection(self) -> bool:
        """Test if Ollama is running and accessible."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                return response.status_code == 200
        except Exception:
            return False
