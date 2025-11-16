"""
Ollama local LLM client for AdversarialShield.
"""
import asyncio
from typing import List, Optional

import aiohttp

from backend.core.config import settings


class OllamaClient:
    """Async client for Ollama local LLM."""

    def __init__(self, base_url: Optional[str] = None):
        """
        Initialize Ollama client.

        Args:
            base_url: Ollama server URL. If not provided, uses settings.
        """
        self.base_url = base_url or settings.ollama_base_url
        self.default_model = "llama2"

    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.7,
        system_prompt: Optional[str] = None,
    ) -> str:
        """
        Generate text using Ollama API.

        Args:
            prompt: User prompt
            model: Model to use (defaults to llama2)
            temperature: Sampling temperature
            system_prompt: Optional system prompt

        Returns:
            Generated text

        Raises:
            Exception: If API call fails
        """
        url = f"{self.base_url}/api/generate"

        payload = {
            "model": model or self.default_model,
            "prompt": prompt,
            "temperature": temperature,
            "stream": False,
        }

        if system_prompt:
            payload["system"] = system_prompt

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status != 200:
                        raise Exception(f"Ollama API error: {response.status}")

                    data = await response.json()
                    return data.get("response", "")

        except aiohttp.ClientError as e:
            raise Exception(f"Ollama connection error: {str(e)}") from e

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
        Test if Ollama server is accessible.

        Returns:
            True if connection successful
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.base_url}/api/tags") as response:
                    return response.status == 200
        except Exception:
            return False

    async def list_models(self) -> List[str]:
        """
        List available models.

        Returns:
            List of model names
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.base_url}/api/tags") as response:
                    if response.status == 200:
                        data = await response.json()
                        return [model["name"] for model in data.get("models", [])]
            return []
        except Exception:
            return []
