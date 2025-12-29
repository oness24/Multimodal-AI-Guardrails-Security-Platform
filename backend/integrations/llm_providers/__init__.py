"""
LLM provider integrations.
"""
from backend.integrations.llm_providers.base import (
    BaseLLMClient,
    LLMProvider,
    LLMResponse,
    Message,
)
from backend.integrations.llm_providers.openai_client import OpenAIClient
from backend.integrations.llm_providers.anthropic_client import AnthropicClient
from backend.integrations.llm_providers.ollama_client import OllamaClient


def get_llm_client(provider: str, **kwargs) -> BaseLLMClient:
    """
    Factory function to get an LLM client by provider name.
    
    Args:
        provider: Provider name ('openai', 'anthropic', 'ollama')
        **kwargs: Additional arguments to pass to the client
        
    Returns:
        LLM client instance
    """
    providers = {
        "openai": OpenAIClient,
        "anthropic": AnthropicClient,
        "ollama": OllamaClient,
    }
    
    if provider not in providers:
        raise ValueError(f"Unknown provider: {provider}. Supported: {list(providers.keys())}")
    
    return providers[provider](**kwargs)


__all__ = [
    "BaseLLMClient",
    "LLMProvider",
    "LLMResponse",
    "Message",
    "OpenAIClient",
    "AnthropicClient",
    "OllamaClient",
    "get_llm_client",
]
