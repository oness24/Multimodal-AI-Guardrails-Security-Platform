"""
Configuration management for AdversarialShield.
Uses pydantic-settings for environment variable management.
"""
from functools import lru_cache
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Environment
    environment: str = Field(default="development")

    # API Configuration
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    api_workers: int = Field(default=4)
    api_title: str = Field(default="AdversarialShield API")
    api_version: str = Field(default="0.1.0")
    api_description: str = Field(
        default="Multimodal AI Security Testing & Guardrails Platform"
    )

    # Database URLs
    database_url: str = Field(
        default="postgresql://postgres:postgres@localhost:5432/adversarial_shield"
    )
    redis_url: str = Field(default="redis://localhost:6379/0")
    mongodb_url: str = Field(default="mongodb://localhost:27017/adversarial_shield")

    # Security
    secret_key: str = Field(default="change-this-in-production")
    jwt_algorithm: str = Field(default="HS256")
    jwt_expiration_minutes: int = Field(default=60)

    # LLM API Keys
    openai_api_key: Optional[str] = Field(default=None)
    anthropic_api_key: Optional[str] = Field(default=None)
    huggingface_api_key: Optional[str] = Field(default=None)

    # Ollama
    ollama_base_url: str = Field(default="http://localhost:11434")

    # SIEM Integration
    wazuh_api_url: Optional[str] = Field(default=None)
    wazuh_api_username: Optional[str] = Field(default=None)
    wazuh_api_password: Optional[str] = Field(default=None)
    splunk_api_url: Optional[str] = Field(default=None)
    splunk_api_token: Optional[str] = Field(default=None)

    # Logging
    log_level: str = Field(default="INFO")
    log_format: str = Field(default="json")

    # Rate Limiting
    rate_limit_per_minute: int = Field(default=100)

    # Model Configuration
    default_llm_model: str = Field(default="gpt-4")
    default_embedding_model: str = Field(
        default="sentence-transformers/all-MiniLM-L6-v2"
    )
    default_vision_model: str = Field(default="gpt-4-vision-preview")

    # Attack Generation
    max_attack_generation_concurrent: int = Field(default=10)
    attack_timeout_seconds: int = Field(default=300)

    # Guardrails
    injection_detection_threshold: float = Field(default=0.7)
    anomaly_detection_threshold: float = Field(default=0.8)
    pii_detection_enabled: bool = Field(default=True)
    toxicity_detection_enabled: bool = Field(default=True)

    # Monitoring
    prometheus_enabled: bool = Field(default=True)
    prometheus_port: int = Field(default=9090)

    # Feature Flags
    enable_multimodal_attacks: bool = Field(default=True)
    enable_static_analysis: bool = Field(default=True)
    enable_dynamic_analysis: bool = Field(default=True)
    enable_threat_modeling: bool = Field(default=True)

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        """Validate environment value."""
        allowed = ["development", "staging", "production", "test"]
        if v not in allowed:
            raise ValueError(f"Environment must be one of {allowed}")
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        allowed = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        v = v.upper()
        if v not in allowed:
            raise ValueError(f"Log level must be one of {allowed}")
        return v

    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.environment == "development"

    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.environment == "production"

    @property
    def is_test(self) -> bool:
        """Check if running in test mode."""
        return self.environment == "test"


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    Using lru_cache ensures settings are only loaded once.
    """
    return Settings()


# Global settings instance
settings = get_settings()
