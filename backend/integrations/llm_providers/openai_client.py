"""
OpenAI API client for AdversarialShield.
"""
import asyncio
from typing import Dict, List, Optional

from openai import AsyncOpenAI, OpenAIError

from backend.core.config import settings


class OpenAIClient:
    """Async client for OpenAI API."""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize OpenAI client.

        Args:
            api_key: OpenAI API key. If not provided, uses settings.
        """
        self.api_key = api_key or settings.openai_api_key
        if not self.api_key:
            raise ValueError("OpenAI API key not configured")

        self.client = AsyncOpenAI(api_key=self.api_key)
        self.default_model = settings.default_llm_model

    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1000,
        system_prompt: Optional[str] = None,
    ) -> str:
        """
        Generate text using OpenAI API.

        Args:
            prompt: User prompt
            model: Model to use (defaults to settings.default_llm_model)
            temperature: Sampling temperature (0.0 to 2.0)
            max_tokens: Maximum tokens to generate
            system_prompt: Optional system prompt

        Returns:
            Generated text

        Raises:
            OpenAIError: If API call fails
        """
        messages: List[Dict[str, str]] = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        messages.append({"role": "user", "content": prompt})

        try:
            response = await self.client.chat.completions.create(
                model=model or self.default_model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )

            return response.choices[0].message.content or ""

        except OpenAIError as e:
            raise Exception(f"OpenAI API error: {str(e)}") from e

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
