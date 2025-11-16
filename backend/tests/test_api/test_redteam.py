"""
Integration tests for Red Team API endpoints.
"""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_techniques(client: AsyncClient):
    """Test listing available attack techniques."""
    response = await client.get("/api/v1/redteam/techniques")

    assert response.status_code == 200
    techniques = response.json()

    assert isinstance(techniques, list)
    assert len(techniques) > 0
    assert "context_manipulation" in techniques
    assert "instruction_override" in techniques


@pytest.mark.asyncio
async def test_list_patterns_empty(client: AsyncClient):
    """Test listing patterns when database is empty."""
    response = await client.get("/api/v1/redteam/patterns")

    assert response.status_code == 200
    patterns = response.json()

    assert isinstance(patterns, list)


@pytest.mark.asyncio
async def test_list_patterns_with_data(client: AsyncClient, sample_attack_pattern):
    """Test listing patterns with sample data."""
    response = await client.get("/api/v1/redteam/patterns")

    assert response.status_code == 200
    patterns = response.json()

    assert len(patterns) > 0
    pattern = patterns[0]

    assert "id" in pattern
    assert "name" in pattern
    assert "technique" in pattern
    assert pattern["name"] == sample_attack_pattern.name


@pytest.mark.asyncio
async def test_get_pattern_by_id(client: AsyncClient, sample_attack_pattern):
    """Test getting a specific pattern by ID."""
    pattern_id = str(sample_attack_pattern.id)
    response = await client.get(f"/api/v1/redteam/patterns/{pattern_id}")

    assert response.status_code == 200
    pattern = response.json()

    assert pattern["id"] == pattern_id
    assert pattern["name"] == sample_attack_pattern.name
    assert pattern["technique"] == sample_attack_pattern.technique


@pytest.mark.asyncio
async def test_get_pattern_not_found(client: AsyncClient):
    """Test getting a non-existent pattern."""
    fake_id = "00000000-0000-0000-0000-000000000000"
    response = await client.get(f"/api/v1/redteam/patterns/{fake_id}")

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_filter_patterns_by_technique(client: AsyncClient, sample_attack_pattern):
    """Test filtering patterns by technique."""
    response = await client.get(
        "/api/v1/redteam/patterns",
        params={"technique": "context_manipulation"},
    )

    assert response.status_code == 200
    patterns = response.json()

    assert len(patterns) > 0
    assert all(p["technique"] == "context_manipulation" for p in patterns)


@pytest.mark.asyncio
async def test_filter_patterns_by_severity(client: AsyncClient, sample_attack_pattern):
    """Test filtering patterns by severity."""
    response = await client.get(
        "/api/v1/redteam/patterns",
        params={"severity": "high"},
    )

    assert response.status_code == 200
    patterns = response.json()

    if len(patterns) > 0:
        assert all(p["severity"] == "high" for p in patterns)


@pytest.mark.asyncio
async def test_list_attack_logs_empty(client: AsyncClient):
    """Test listing attack logs when none exist."""
    response = await client.get("/api/v1/redteam/logs")

    assert response.status_code == 200
    logs = response.json()

    assert isinstance(logs, list)


@pytest.mark.asyncio
async def test_get_attack_stats_empty(client: AsyncClient):
    """Test getting statistics when no attacks logged."""
    response = await client.get("/api/v1/redteam/stats")

    assert response.status_code == 200
    stats = response.json()

    assert "total_attacks" in stats
    assert "successful_attacks" in stats
    assert "overall_success_rate" in stats
    assert "technique_stats" in stats

    assert stats["total_attacks"] == 0
    assert stats["successful_attacks"] == 0
    assert stats["overall_success_rate"] == 0.0
