"""
Integration tests for Jailbreak API endpoints.
"""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_jailbreak_patterns_empty(client: AsyncClient):
    """Test listing jailbreak patterns when none exist."""
    response = await client.get("/api/v1/redteam/jailbreak/patterns")

    assert response.status_code == 200
    patterns = response.json()
    assert isinstance(patterns, list)


@pytest.mark.asyncio
async def test_get_top_jailbreaks_empty(client: AsyncClient):
    """Test getting top jailbreaks when none exist."""
    response = await client.get("/api/v1/redteam/jailbreak/top")

    assert response.status_code == 200
    patterns = response.json()
    assert isinstance(patterns, list)


@pytest.mark.asyncio
async def test_get_jailbreak_stats_empty(client: AsyncClient):
    """Test getting jailbreak stats when none exist."""
    response = await client.get("/api/v1/redteam/jailbreak/stats")

    assert response.status_code == 200
    stats = response.json()

    assert "total_jailbreak_attempts" in stats
    assert "successful_jailbreaks" in stats
    assert "overall_success_rate" in stats
    assert "pattern_stats" in stats

    assert stats["total_jailbreak_attempts"] == 0
    assert stats["successful_jailbreaks"] == 0
