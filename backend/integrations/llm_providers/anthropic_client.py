"""
Anthropic Claude API client for AdversarialShield.
"""
import asyncio
from typing import List, Optional

from anthropic import AsyncAnthropic, AnthropicError

from backend.core.config import settings


class AnthropicClient:
    """Async client for Anthropic Claude API."""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Anthropic client.

        Args:
            api_key: Anthropic API key. If not provided, uses settings.
        """
        self.api_key = api_key or settings.anthropic_api_key
        if not self.api_key:
            raise ValueError("Anthropic API key not configured")

        self.client = AsyncAnthropic(api_key=self.api_key)
        self.default_model = "claude-3-opus-20240229"

    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1000,
        system_prompt: Optional[str] = None,
    ) -> str:
        """
        Generate text using Anthropic API.

        Args:
            prompt: User prompt
            model: Model to use (defaults to claude-3-opus)
            temperature: Sampling temperature (0.0 to 1.0)
            max_tokens: Maximum tokens to generate
            system_prompt: Optional system prompt

        Returns:
            Generated text

        Raises:
            AnthropicError: If API call fails
        """
        try:
            kwargs = {
                "model": model or self.default_model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
                "max_tokens": max_tokens,
            }

            if system_prompt:
                kwargs["system"] = system_prompt

            response = await self.client.messages.create(**kwargs)

            return response.content[0].text

        except AnthropicError as e:
            raise Exception(f"Anthropic API error: {str(e)}") from e

    async def generate_with_retry(
        self,
        prompt: str,
        max_retries: int = 3,
        **kwargs,
    ) -> str:
        """
        Generate text with retry logic.

        Args:
            prompt: User prompt
            max_retries: Maximum number of retries
            **kwargs: Additional arguments for generate()

        Returns:
            Generated text

        Raises:
            Exception: If all retries fail
        """
        last_error = None

        for attempt in range(max_retries):
            try:
                return await self.generate(prompt, **kwargs)
            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    # Exponential backoff
                    await asyncio.sleep(2**attempt)
                continue

        raise Exception(f"Failed after {max_retries} retries: {last_error}")

    async def batch_generate(
        self,
        prompts: List[str],
        **kwargs,
    ) -> List[str]:
        """
        Generate text for multiple prompts concurrently.

        Args:
            prompts: List of prompts
            **kwargs: Additional arguments for generate()

        Returns:
            List of generated texts
        """
        tasks = [self.generate(prompt, **kwargs) for prompt in prompts]
        return await asyncio.gather(*tasks)

    async def test_connection(self) -> bool:
        """
        Test if API key is valid.

        Returns:
            True if connection successful
        """
        try:
            await self.generate("Hello", max_tokens=5)
            return True
        except Exception:
            return False
