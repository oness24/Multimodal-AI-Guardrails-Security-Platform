"""
Tests for sanitization agent.
"""
import pytest

from backend.guardrails.agents.sanitization_agent import SanitizationAgent


@pytest.fixture
def sanitizer():
    """Create sanitization agent for testing."""
    return SanitizationAgent()


@pytest.mark.asyncio
async def test_sanitizer_initialization(sanitizer):
    """Test sanitization agent initialization."""
    assert sanitizer.max_length == 10000
    assert sanitizer.normalize_unicode is True
    assert sanitizer.remove_html is True


@pytest.mark.asyncio
async def test_clean_simple_text(sanitizer):
    """Test cleaning simple text (no changes needed)."""
    text = "Hello, this is a simple test."
    result = await sanitizer.clean(text)

    assert result == text
    assert len(sanitizer.get_modifications()) == 0


@pytest.mark.asyncio
async def test_remove_html_tags(sanitizer):
    """Test HTML tag removal."""
    text = "Hello <b>world</b>! <script>alert('xss')</script>"
    result = await sanitizer.clean(text)

    assert "<b>" not in result
    assert "<script>" not in result
    assert "Hello world!" in result
    assert len(sanitizer.get_modifications()) > 0


@pytest.mark.asyncio
async def test_html_entity_decoding(sanitizer):
    """Test HTML entity decoding."""
    text = "&lt;script&gt;alert(&quot;test&quot;)&lt;/script&gt;"
    result = await sanitizer.clean(text)

    # Should decode entities, then remove tags
    assert "&lt;" not in result
    assert "&gt;" not in result


@pytest.mark.asyncio
async def test_unicode_normalization(sanitizer):
    """Test Unicode normalization."""
    # Text with combining characters
    text = "café"  # Using combining accent
    result = await sanitizer.clean(text)

    assert result == "café"  # Should be normalized


@pytest.mark.asyncio
async def test_control_character_removal(sanitizer):
    """Test control character removal."""
    text = "Hello\x00World\x01Test"
    result = await sanitizer.clean(text)

    assert "\x00" not in result
    assert "\x01" not in result
    assert "HelloWorldTest" in result


@pytest.mark.asyncio
async def test_whitespace_normalization(sanitizer):
    """Test whitespace normalization."""
    text = "Hello    world\n\n\n\ntest"
    result = await sanitizer.clean(text)

    assert "    " not in result
    assert "\n\n\n\n" not in result
    assert "Hello world" in result


@pytest.mark.asyncio
async def test_zero_width_character_removal(sanitizer):
    """Test zero-width character removal."""
    text = "Hello\u200bWorld\u200cTest\ufeff"
    result = await sanitizer.clean(text)

    assert "\u200b" not in result
    assert "\u200c" not in result
    assert "\ufeff" not in result
    assert "HelloWorldTest" in result


@pytest.mark.asyncio
async def test_length_truncation(sanitizer):
    """Test length truncation."""
    long_text = "A" * 15000
    result = await sanitizer.clean(long_text)

    assert len(result) == 10000
    modifications = sanitizer.get_modifications()
    assert any(m["type"] == "truncation" for m in modifications)


@pytest.mark.asyncio
async def test_modification_tracking(sanitizer):
    """Test modification tracking."""
    text = "<b>Hello</b>   world\u200b"
    result = await sanitizer.clean(text)

    modifications = sanitizer.get_modifications()

    # Should have multiple modifications
    assert len(modifications) > 0

    # Check modification types
    mod_types = [m["type"] for m in modifications]
    assert "html_removal" in mod_types
    assert "whitespace_normalization" in mod_types
    assert "zero_width_removal" in mod_types


@pytest.mark.asyncio
async def test_validate_length(sanitizer):
    """Test length validation."""
    short_text = "Hello"
    long_text = "A" * 15000

    assert await sanitizer.validate_length(short_text) is True
    assert await sanitizer.validate_length(long_text) is False
    assert await sanitizer.validate_length(long_text, max_length=20000) is True


@pytest.mark.asyncio
async def test_estimate_tokens(sanitizer):
    """Test token estimation."""
    text = "Hello world, this is a test."

    tokens = await sanitizer.estimate_tokens(text)

    # Should be roughly len(text) / 4
    assert tokens > 0
    assert tokens < len(text)


@pytest.mark.asyncio
async def test_custom_config():
    """Test sanitizer with custom configuration."""
    config = {"max_length": 100, "remove_html": False}
    sanitizer = SanitizationAgent(config)

    assert sanitizer.max_length == 100
    assert sanitizer.remove_html is False

    # HTML should not be removed
    text = "<b>Hello</b>"
    result = await sanitizer.clean(text)
    assert "<b>" in result


@pytest.mark.asyncio
async def test_empty_input(sanitizer):
    """Test handling of empty input."""
    text = ""
    result = await sanitizer.clean(text)

    assert result == ""


@pytest.mark.asyncio
async def test_complex_sanitization(sanitizer):
    """Test complex sanitization with multiple issues."""
    text = """
    <script>alert('xss')</script>
    &lt;test&gt;
    Hello    world
    \u200bTest\x00
    Multiple\n\n\n\nlines
    """

    result = await sanitizer.clean(text)

    # Verify all issues are handled
    assert "<script>" not in result
    assert "&lt;" not in result
    assert "    " not in result
    assert "\u200b" not in result
    assert "\x00" not in result
    assert "\n\n\n\n" not in result

    modifications = sanitizer.get_modifications()
    assert len(modifications) >= 3
