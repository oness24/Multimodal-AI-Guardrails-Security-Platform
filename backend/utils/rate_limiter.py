"""
Rate Limiter and Cost Tracker for LLM API calls.
Prevents cost overruns and ensures fair API usage.
"""
import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, Optional

from backend.core.config import settings


class LLMProvider(str, Enum):
    """Supported LLM providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"


# Cost per 1K tokens (in USD) - Updated Dec 2024
MODEL_COSTS: Dict[str, Dict[str, float]] = {
    # OpenAI Models
    "gpt-4": {"input": 0.03, "output": 0.06},
    "gpt-4-turbo": {"input": 0.01, "output": 0.03},
    "gpt-4-turbo-preview": {"input": 0.01, "output": 0.03},
    "gpt-4o": {"input": 0.005, "output": 0.015},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
    "gpt-3.5-turbo-16k": {"input": 0.003, "output": 0.004},
    "gpt-4-vision-preview": {"input": 0.01, "output": 0.03},
    "text-embedding-3-small": {"input": 0.00002, "output": 0.0},
    "text-embedding-3-large": {"input": 0.00013, "output": 0.0},
    # Anthropic Models
    "claude-3-opus-20240229": {"input": 0.015, "output": 0.075},
    "claude-3-sonnet-20240229": {"input": 0.003, "output": 0.015},
    "claude-3-haiku-20240307": {"input": 0.00025, "output": 0.00125},
    "claude-3-5-sonnet-20241022": {"input": 0.003, "output": 0.015},
    # Ollama (local - no cost)
    "llama2": {"input": 0.0, "output": 0.0},
    "llama3": {"input": 0.0, "output": 0.0},
    "mistral": {"input": 0.0, "output": 0.0},
    "codellama": {"input": 0.0, "output": 0.0},
}

# Default cost for unknown models
DEFAULT_COST = {"input": 0.01, "output": 0.03}


@dataclass
class UsageRecord:
    """Record of a single API call."""
    timestamp: datetime
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    endpoint: str = "chat"


@dataclass
class BudgetConfig:
    """Budget configuration for cost control."""
    daily_limit_usd: float = 10.0
    monthly_limit_usd: float = 100.0
    per_request_limit_usd: float = 1.0
    alert_threshold_percent: float = 80.0


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""
    requests_per_minute: int = 60
    requests_per_day: int = 10000
    tokens_per_minute: int = 100000
    concurrent_requests: int = 10


@dataclass
class CostSummary:
    """Summary of costs for a time period."""
    total_cost_usd: float
    total_requests: int
    total_input_tokens: int
    total_output_tokens: int
    by_model: Dict[str, float] = field(default_factory=dict)
    by_provider: Dict[str, float] = field(default_factory=dict)


class RateLimiter:
    """
    Token bucket rate limiter with cost tracking.
    Thread-safe for async operations.
    """

    def __init__(
        self,
        rate_config: Optional[RateLimitConfig] = None,
        budget_config: Optional[BudgetConfig] = None,
    ):
        self.rate_config = rate_config or RateLimitConfig()
        self.budget_config = budget_config or BudgetConfig()
        
        # Token bucket state
        self._tokens = float(self.rate_config.requests_per_minute)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
        
        # Concurrent request tracking
        self._semaphore = asyncio.Semaphore(self.rate_config.concurrent_requests)
        
        # Usage tracking
        self._usage_history: list[UsageRecord] = []
        self._daily_cost: float = 0.0
        self._monthly_cost: float = 0.0
        self._daily_requests: int = 0
        self._last_reset_day: int = datetime.now().day
        self._last_reset_month: int = datetime.now().month

    async def acquire(self) -> bool:
        """
        Acquire permission to make a request.
        Returns True if allowed, False if rate limited.
        """
        async with self._lock:
            self._refill_tokens()
            self._check_reset_counters()
            
            # Check daily request limit
            if self._daily_requests >= self.rate_config.requests_per_day:
                return False
            
            # Check token bucket
            if self._tokens < 1:
                return False
            
            self._tokens -= 1
            self._daily_requests += 1
            return True

    async def acquire_with_wait(self, timeout: float = 30.0) -> bool:
        """
        Acquire permission, waiting if necessary.
        Returns True if acquired within timeout, False otherwise.
        """
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            if await self.acquire():
                return True
            await asyncio.sleep(0.1)  # Wait 100ms before retry
        return False

    def _refill_tokens(self) -> None:
        """Refill token bucket based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        
        # Refill rate: requests_per_minute / 60 per second
        refill_rate = self.rate_config.requests_per_minute / 60.0
        self._tokens = min(
            float(self.rate_config.requests_per_minute),
            self._tokens + (elapsed * refill_rate)
        )
        self._last_refill = now

    def _check_reset_counters(self) -> None:
        """Reset daily/monthly counters if needed."""
        now = datetime.now()
        
        if now.day != self._last_reset_day:
            self._daily_cost = 0.0
            self._daily_requests = 0
            self._last_reset_day = now.day
        
        if now.month != self._last_reset_month:
            self._monthly_cost = 0.0
            self._last_reset_month = now.month

    def check_budget(self, estimated_cost: float) -> tuple[bool, str]:
        """
        Check if a request is within budget.
        Returns (allowed, reason).
        """
        self._check_reset_counters()
        
        if estimated_cost > self.budget_config.per_request_limit_usd:
            return False, f"Request cost ${estimated_cost:.4f} exceeds per-request limit ${self.budget_config.per_request_limit_usd:.2f}"
        
        if self._daily_cost + estimated_cost > self.budget_config.daily_limit_usd:
            return False, f"Daily budget exhausted (${self._daily_cost:.2f}/${self.budget_config.daily_limit_usd:.2f})"
        
        if self._monthly_cost + estimated_cost > self.budget_config.monthly_limit_usd:
            return False, f"Monthly budget exhausted (${self._monthly_cost:.2f}/${self.budget_config.monthly_limit_usd:.2f})"
        
        return True, "OK"

    def estimate_cost(
        self,
        model: str,
        input_tokens: int,
        estimated_output_tokens: int = 500,
    ) -> float:
        """Estimate cost for a request before making it."""
        costs = MODEL_COSTS.get(model, DEFAULT_COST)
        input_cost = (input_tokens / 1000) * costs["input"]
        output_cost = (estimated_output_tokens / 1000) * costs["output"]
        return input_cost + output_cost

    def record_usage(
        self,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        endpoint: str = "chat",
    ) -> UsageRecord:
        """Record actual usage after a request completes."""
        costs = MODEL_COSTS.get(model, DEFAULT_COST)
        cost = (input_tokens / 1000) * costs["input"] + (output_tokens / 1000) * costs["output"]
        
        record = UsageRecord(
            timestamp=datetime.now(),
            provider=provider,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost,
            endpoint=endpoint,
        )
        
        self._usage_history.append(record)
        self._daily_cost += cost
        self._monthly_cost += cost
        
        # Keep only last 10000 records in memory
        if len(self._usage_history) > 10000:
            self._usage_history = self._usage_history[-5000:]
        
        return record

    def get_daily_summary(self) -> CostSummary:
        """Get cost summary for today."""
        self._check_reset_counters()
        today = datetime.now().date()
        
        today_records = [
            r for r in self._usage_history
            if r.timestamp.date() == today
        ]
        
        return self._summarize_records(today_records)

    def get_monthly_summary(self) -> CostSummary:
        """Get cost summary for this month."""
        self._check_reset_counters()
        this_month = datetime.now().month
        this_year = datetime.now().year
        
        month_records = [
            r for r in self._usage_history
            if r.timestamp.month == this_month and r.timestamp.year == this_year
        ]
        
        return self._summarize_records(month_records)

    def _summarize_records(self, records: list[UsageRecord]) -> CostSummary:
        """Summarize a list of usage records."""
        by_model: Dict[str, float] = {}
        by_provider: Dict[str, float] = {}
        total_cost = 0.0
        total_input = 0
        total_output = 0
        
        for r in records:
            total_cost += r.cost_usd
            total_input += r.input_tokens
            total_output += r.output_tokens
            by_model[r.model] = by_model.get(r.model, 0.0) + r.cost_usd
            by_provider[r.provider] = by_provider.get(r.provider, 0.0) + r.cost_usd
        
        return CostSummary(
            total_cost_usd=total_cost,
            total_requests=len(records),
            total_input_tokens=total_input,
            total_output_tokens=total_output,
            by_model=by_model,
            by_provider=by_provider,
        )

    def get_budget_status(self) -> dict:
        """Get current budget status."""
        self._check_reset_counters()
        
        daily_percent = (self._daily_cost / self.budget_config.daily_limit_usd) * 100
        monthly_percent = (self._monthly_cost / self.budget_config.monthly_limit_usd) * 100
        
        return {
            "daily": {
                "used_usd": round(self._daily_cost, 4),
                "limit_usd": self.budget_config.daily_limit_usd,
                "percent_used": round(daily_percent, 1),
                "remaining_usd": round(self.budget_config.daily_limit_usd - self._daily_cost, 4),
            },
            "monthly": {
                "used_usd": round(self._monthly_cost, 4),
                "limit_usd": self.budget_config.monthly_limit_usd,
                "percent_used": round(monthly_percent, 1),
                "remaining_usd": round(self.budget_config.monthly_limit_usd - self._monthly_cost, 4),
            },
            "alerts": {
                "daily_alert": daily_percent >= self.budget_config.alert_threshold_percent,
                "monthly_alert": monthly_percent >= self.budget_config.alert_threshold_percent,
            },
            "requests_today": self._daily_requests,
        }


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get or create the global rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        # Load config from settings if available
        rate_config = RateLimitConfig(
            requests_per_minute=getattr(settings, 'rate_limit_rpm', 60),
            requests_per_day=getattr(settings, 'rate_limit_daily', 10000),
            concurrent_requests=getattr(settings, 'max_concurrent_requests', 10),
        )
        budget_config = BudgetConfig(
            daily_limit_usd=getattr(settings, 'daily_budget_usd', 10.0),
            monthly_limit_usd=getattr(settings, 'monthly_budget_usd', 100.0),
            per_request_limit_usd=getattr(settings, 'per_request_limit_usd', 1.0),
        )
        _rate_limiter = RateLimiter(rate_config, budget_config)
    return _rate_limiter


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded."""
    pass


class BudgetExceeded(Exception):
    """Raised when budget limit is exceeded."""
    pass
