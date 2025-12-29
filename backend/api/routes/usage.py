"""
Usage and cost tracking API routes.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from backend.utils.rate_limiter import get_rate_limiter, BudgetConfig


router = APIRouter(prefix="/usage", tags=["usage"])


class BudgetUpdateRequest(BaseModel):
    """Request to update budget limits."""
    daily_limit_usd: Optional[float] = None
    monthly_limit_usd: Optional[float] = None
    per_request_limit_usd: Optional[float] = None
    alert_threshold_percent: Optional[float] = None


class UsageSummaryResponse(BaseModel):
    """Response with usage summary."""
    total_cost_usd: float
    total_requests: int
    total_input_tokens: int
    total_output_tokens: int
    by_model: dict
    by_provider: dict


class BudgetStatusResponse(BaseModel):
    """Response with budget status."""
    daily: dict
    monthly: dict
    alerts: dict
    requests_today: int


@router.get("/status", response_model=BudgetStatusResponse)
async def get_usage_status():
    """
    Get current usage and budget status.
    
    Returns daily/monthly usage, limits, and alert status.
    """
    rate_limiter = get_rate_limiter()
    status = rate_limiter.get_budget_status()
    return BudgetStatusResponse(**status)


@router.get("/daily", response_model=UsageSummaryResponse)
async def get_daily_usage():
    """
    Get usage summary for today.
    
    Returns breakdown by model and provider.
    """
    rate_limiter = get_rate_limiter()
    summary = rate_limiter.get_daily_summary()
    return UsageSummaryResponse(
        total_cost_usd=summary.total_cost_usd,
        total_requests=summary.total_requests,
        total_input_tokens=summary.total_input_tokens,
        total_output_tokens=summary.total_output_tokens,
        by_model=summary.by_model,
        by_provider=summary.by_provider,
    )


@router.get("/monthly", response_model=UsageSummaryResponse)
async def get_monthly_usage():
    """
    Get usage summary for this month.
    
    Returns breakdown by model and provider.
    """
    rate_limiter = get_rate_limiter()
    summary = rate_limiter.get_monthly_summary()
    return UsageSummaryResponse(
        total_cost_usd=summary.total_cost_usd,
        total_requests=summary.total_requests,
        total_input_tokens=summary.total_input_tokens,
        total_output_tokens=summary.total_output_tokens,
        by_model=summary.by_model,
        by_provider=summary.by_provider,
    )


@router.post("/budget")
async def update_budget(request: BudgetUpdateRequest):
    """
    Update budget limits.
    
    Allows adjusting daily, monthly, and per-request limits.
    """
    rate_limiter = get_rate_limiter()
    
    if request.daily_limit_usd is not None:
        if request.daily_limit_usd <= 0:
            raise HTTPException(status_code=400, detail="Daily limit must be positive")
        rate_limiter.budget_config.daily_limit_usd = request.daily_limit_usd
    
    if request.monthly_limit_usd is not None:
        if request.monthly_limit_usd <= 0:
            raise HTTPException(status_code=400, detail="Monthly limit must be positive")
        rate_limiter.budget_config.monthly_limit_usd = request.monthly_limit_usd
    
    if request.per_request_limit_usd is not None:
        if request.per_request_limit_usd <= 0:
            raise HTTPException(status_code=400, detail="Per-request limit must be positive")
        rate_limiter.budget_config.per_request_limit_usd = request.per_request_limit_usd
    
    if request.alert_threshold_percent is not None:
        if not 0 < request.alert_threshold_percent <= 100:
            raise HTTPException(status_code=400, detail="Alert threshold must be between 0 and 100")
        rate_limiter.budget_config.alert_threshold_percent = request.alert_threshold_percent
    
    return {
        "message": "Budget updated successfully",
        "new_limits": {
            "daily_limit_usd": rate_limiter.budget_config.daily_limit_usd,
            "monthly_limit_usd": rate_limiter.budget_config.monthly_limit_usd,
            "per_request_limit_usd": rate_limiter.budget_config.per_request_limit_usd,
            "alert_threshold_percent": rate_limiter.budget_config.alert_threshold_percent,
        }
    }


@router.get("/estimate")
async def estimate_cost(
    model: str = "gpt-4",
    input_tokens: int = 1000,
    output_tokens: int = 500,
):
    """
    Estimate cost for a request.
    
    Useful for planning before running expensive operations.
    """
    rate_limiter = get_rate_limiter()
    estimated_cost = rate_limiter.estimate_cost(model, input_tokens, output_tokens)
    
    budget_ok, reason = rate_limiter.check_budget(estimated_cost)
    
    return {
        "model": model,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "estimated_cost_usd": round(estimated_cost, 6),
        "within_budget": budget_ok,
        "budget_message": reason,
    }


@router.post("/reset-daily")
async def reset_daily_counters():
    """
    Reset daily usage counters.
    
    Use with caution - this allows exceeding daily limits.
    """
    rate_limiter = get_rate_limiter()
    rate_limiter._daily_cost = 0.0
    rate_limiter._daily_requests = 0
    
    return {"message": "Daily counters reset successfully"}
