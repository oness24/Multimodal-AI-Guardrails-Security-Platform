"""
Tests for response filter.
"""
import pytest

from backend.guardrails.filters.response_filter import ResponseFilter
from backend.guardrails.detectors.pii_detector import PIIEntity


@pytest.fixture
def response_filter():
    """Create response filter for testing."""
    return ResponseFilter()


@pytest.mark.asyncio
async def test_filter_initialization(response_filter):
    """Test filter initialization."""
    assert response_filter.enable_pii_redaction is True
    assert response_filter.enable_code_filtering is True
    assert response_filter.max_length == 5000


@pytest.mark.asyncio
async def test_clean_text_no_modifications(response_filter):
    """Test filtering clean text."""
    result = await response_filter.filter_response("Hello, this is a test.")

    assert result.blocked is False
    assert result.filtered_text == "Hello, this is a test."
    assert len(result.modifications) == 0


@pytest.mark.asyncio
async def test_pii_redaction(response_filter):
    """Test PII redaction."""
    entities = [
        PIIEntity(type="EMAIL_ADDRESS", text="test@example.com", score=1.0, start=12, end=28)
    ]

    result = await response_filter.filter_response(
        text="My email is test@example.com",
        pii_entities=entities,
    )

    assert result.blocked is False
    assert "[REDACTED-EMAIL_ADDRESS]" in result.filtered_text
    assert "test@example.com" not in result.filtered_text
    assert any(m["type"] == "pii_redaction" for m in result.modifications)


@pytest.mark.asyncio
async def test_unsafe_code_blocking(response_filter):
    """Test blocking of unsafe code."""
    result = await response_filter.filter_response(
        text="You can run this command: rm -rf / to clean up"
    )

    assert result.blocked is True
    assert "BLOCKED" in result.filtered_text


@pytest.mark.asyncio
async def test_sql_injection_blocking(response_filter):
    """Test blocking of SQL injection patterns."""
    result = await response_filter.filter_response(
        text="Execute this SQL: ; DROP TABLE users;"
    )

    assert result.blocked is True


@pytest.mark.asyncio
async def test_restricted_pattern_removal(response_filter):
    """Test removal of restricted patterns."""
    result = await response_filter.filter_response(
        text="Click here: <script>alert('xss')</script>"
    )

    assert result.blocked is False  # Removed, not blocked
    assert "<script>" not in result.filtered_text
    assert any(m["type"] == "restricted_pattern_removal" for m in result.modifications)


@pytest.mark.asyncio
async def test_blocked_keywords():
    """Test blocked keywords functionality."""
    filter_with_blocked = ResponseFilter(
        {"blocked_keywords": ["confidential", "secret"]}
    )

    result = await filter_with_blocked.filter_response(
        text="This is a confidential document"
    )

    assert result.blocked is True
    assert "BLOCKED" in result.filtered_text


@pytest.mark.asyncio
async def test_length_truncation():
    """Test length truncation."""
    long_text = "A" * 10000

    result = await ResponseFilter({"max_length": 100}).filter_response(long_text)

    assert len(result.filtered_text) == 100
    assert any(m["type"] == "truncation" for m in result.modifications)


@pytest.mark.asyncio
async def test_format_validation(response_filter):
    """Test format validation."""
    text_with_issues = "Some text ```unclosed code block\n\n\n\n\nExcessive newlines"

    result = await response_filter.filter_response(text_with_issues)

    assert any(m["type"] == "format_correction" for m in result.modifications)


@pytest.mark.asyncio
async def test_streaming_chunk_filter(response_filter):
    """Test streaming chunk filtering."""
    state = {}

    # Clean chunk
    result = await response_filter.filter_streaming_chunk("Hello ", state)
    assert result["blocked"] is False
    assert result["chunk"] == "Hello "

    # Unsafe chunk
    result = await response_filter.filter_streaming_chunk("rm -rf /", state)
    assert result["blocked"] is True


@pytest.mark.asyncio
async def test_add_remove_blocked_keyword(response_filter):
    """Test adding/removing blocked keywords."""
    response_filter.add_blocked_keyword("test_keyword")

    result = await response_filter.filter_response("This has test_keyword in it")
    assert result.blocked is True

    response_filter.remove_blocked_keyword("test_keyword")

    result = await response_filter.filter_response("This has test_keyword in it")
    assert result.blocked is False


@pytest.mark.asyncio
async def test_get_statistics(response_filter):
    """Test getting filter statistics."""
    stats = response_filter.get_statistics()

    assert "blocked_keywords_count" in stats
    assert "unsafe_code_categories" in stats
    assert "config" in stats


@pytest.mark.asyncio
async def test_multiple_modifications(response_filter):
    """Test multiple modifications in one filter operation."""
    entities = [
        PIIEntity(type="EMAIL_ADDRESS", text="test@example.com", score=1.0, start=12, end=28)
    ]

    text = "My email is test@example.com <script>alert('xss')</script>    extra   spaces"

    result = await response_filter.filter_response(
        text=text,
        pii_entities=entities,
    )

    assert result.blocked is False
    assert len(result.modifications) >= 2  # PII redaction + restricted pattern removal


@pytest.mark.asyncio
async def test_path_traversal_detection(response_filter):
    """Test path traversal pattern detection."""
    result = await response_filter.filter_response(
        text="Access the file at ../../../etc/passwd"
    )

    assert result.blocked is True
