"""
OpenAI API client implementation.
"""
from typing import AsyncGenerator, List, Optional

from openai import AsyncOpenAI

from backend.core.config import settings
from backend.integrations.llm_providers.base import (
    BaseLLMClient,
    LLMProvider,
    LLMResponse,
    Message,
)from backend.utils.rate_limiter import (
    BudgetExceeded,
    RateLimitExceeded,
    get_rate_limiter,
)
from backend.utils.token_counter import TokenCounter, count_message_tokens

class OpenAIClient(BaseLLMClient):
    """OpenAI API client."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        super().__init__(api_key, base_url)
        self.client = AsyncOpenAI(
            api_key=api_key or settings.openai_api_key,
            base_url=base_url,
        )
        self.default_model = "gpt-4"

    @property
    def provider(self) -> LLMProvider:
        return LLMProvider.OPENAI

    @property
    def available_models(self) -> List[str]:
        return [
            "gpt-4",
            "gpt-4-turbo",
            "gpt-4-turbo-preview",
            "gpt-3.5-turbo",
            "gpt-3.5-turbo-16k",
            "gpt-4-vision-preview",
        ]

    async def chat(
        self,
        messages: List[Message],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        skip_rate_limit: bool = False,
        **kwargs,
    ) -> LLMResponse:
        """Send a chat completion request to OpenAI."""
        model = model or self.default_model
        rate_limiter = get_rate_limiter()
        
        # Estimate tokens for budget check
        formatted_messages = self.format_messages(messages)
        input_tokens = count_message_tokens(formatted_messages, model)
        estimated_output = max_tokens or 500
        estimated_cost = rate_limiter.estimate_cost(model, input_tokens, estimated_output)
        
        # Check budget before making request
        if not skip_rate_limit:
            budget_ok, reason = rate_limiter.check_budget(estimated_cost)
            if not budget_ok:
                raise BudgetExceeded(reason)
            
            # Acquire rate limit token
            if not await rate_limiter.acquire_with_wait(timeout=30.0):
                raise RateLimitExceeded("Rate limit exceeded, please try again later")

        response = await self.client.chat.completions.create(
            model=model,
            messages=formatted_messages,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )
        
        # Record actual usage
        actual_input = response.usage.prompt_tokens if response.usage else input_tokens
        actual_output = response.usage.completion_tokens if response.usage else 0
        rate_limiter.record_usage(
            provider=self.provider.value,
            model=response.model,
            input_tokens=actual_input,
            output_tokens=actual_output,
            endpoint="chat",
        )

        return LLMResponse(
            content=response.choices[0].message.content or "",
            model=response.model,
            provider=self.provider,
            usage={
                "prompt_tokens": actual_input,
                "completion_tokens": actual_output,
                "total_tokens": actual_input + actual_output,
            },
            finish_reason=response.choices[0].finish_reason,
        )

    async def chat_stream(
        self,
        messages: List[Message],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs,
    ) -> AsyncGenerator[str, None]:
        """Stream a chat completion response from OpenAI."""
        model = model or self.default_model

        stream = await self.client.chat.completions.create(
            model=model,
            messages=self.format_messages(messages),
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
            **kwargs,
        )

        async for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

    async def get_embeddings(
        self,
        texts: List[str],
        model: str = "text-embedding-3-small",
    ) -> List[List[float]]:
        """Get embeddings for texts."""
        response = await self.client.embeddings.create(
            model=model,
            input=texts,
        )
        return [data.embedding for data in response.data]
