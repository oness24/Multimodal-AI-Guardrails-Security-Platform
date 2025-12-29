"""
Anthropic Claude API client implementation.
"""
from typing import AsyncGenerator, List, Optional

from anthropic import AsyncAnthropic

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
from backend.utils.token_counter import count_message_tokens

class AnthropicClient(BaseLLMClient):
    """Anthropic Claude API client."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        super().__init__(api_key, base_url)
        self.client = AsyncAnthropic(
            api_key=api_key or settings.anthropic_api_key,
        )
        self.default_model = "claude-3-sonnet-20240229"

    @property
    def provider(self) -> LLMProvider:
        return LLMProvider.ANTHROPIC

    @property
    def available_models(self) -> List[str]:
        return [
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229",
            "claude-3-haiku-20240307",
            "claude-2.1",
            "claude-2.0",
        ]

    def _extract_system_message(self, messages: List[Message]) -> tuple[Optional[str], List[Message]]:
        """Extract system message from messages list."""
        system_content = None
        filtered_messages = []

        for msg in messages:
            if msg.role == "system":
                system_content = msg.content
            else:
                filtered_messages.append(msg)

        return system_content, filtered_messages

    async def chat(
        self,
        messages: List[Message],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        skip_rate_limit: bool = False,
        **kwargs,
    ) -> LLMResponse:
        """Send a chat completion request to Anthropic."""
        model = model or self.default_model
        max_tokens = max_tokens or 4096
        rate_limiter = get_rate_limiter()

        system_content, filtered_messages = self._extract_system_message(messages)
        
        # Estimate tokens for budget check
        formatted_messages = self.format_messages(filtered_messages)
        input_tokens = count_message_tokens(formatted_messages, model)
        if system_content:
            input_tokens += len(system_content.split()) * 2  # Rough estimate
        estimated_cost = rate_limiter.estimate_cost(model, input_tokens, max_tokens)
        
        # Check budget before making request
        if not skip_rate_limit:
            budget_ok, reason = rate_limiter.check_budget(estimated_cost)
            if not budget_ok:
                raise BudgetExceeded(reason)
            
            # Acquire rate limit token
            if not await rate_limiter.acquire_with_wait(timeout=30.0):
                raise RateLimitExceeded("Rate limit exceeded, please try again later")

        response = await self.client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system_content or "",
            messages=formatted_messages,
            temperature=temperature,
            **kwargs,
        )
        
        # Record actual usage
        actual_input = response.usage.input_tokens
        actual_output = response.usage.output_tokens
        rate_limiter.record_usage(
            provider=self.provider.value,
            model=response.model,
            input_tokens=actual_input,
            output_tokens=actual_output,
            endpoint="chat",
        )

        return LLMResponse(
            content=response.content[0].text if response.content else "",
            model=response.model,
            provider=self.provider,
            usage={
                "input_tokens": actual_input,
                "output_tokens": actual_output,
                "total_tokens": actual_input + actual_output,
            },
            finish_reason=response.stop_reason,
        )

    async def chat_stream(
        self,
        messages: List[Message],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs,
    ) -> AsyncGenerator[str, None]:
        """Stream a chat completion response from Anthropic."""
        model = model or self.default_model
        max_tokens = max_tokens or 4096

        system_content, filtered_messages = self._extract_system_message(messages)

        async with self.client.messages.stream(
            model=model,
            max_tokens=max_tokens,
            system=system_content or "",
            messages=self.format_messages(filtered_messages),
            temperature=temperature,
            **kwargs,
        ) as stream:
            async for text in stream.text_stream:
                yield text
