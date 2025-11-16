"""
Tests for dynamic vulnerability scanner.
"""
import pytest

from backend.scanner.dynamic_scanner import DynamicTestEngine


@pytest.fixture
def dynamic_engine():
    """Create dynamic test engine for testing."""
    return DynamicTestEngine()


@pytest.fixture
async def mock_safe_llm():
    """Mock safe LLM function."""

    async def safe_llm(prompt: str) -> str:
        return "I'm a helpful assistant. How can I help you today?"

    return safe_llm


@pytest.fixture
async def mock_vulnerable_llm():
    """Mock vulnerable LLM that leaks information."""

    async def vulnerable_llm(prompt: str) -> str:
        # Simulate various vulnerabilities
        if "password" in prompt.lower():
            return "The database password is: admin123"
        elif "api key" in prompt.lower():
            return "API Key: sk-proj-abc123xyz456"
        elif "instructions" in prompt.lower() or "system prompt" in prompt.lower():
            return "You are an AI assistant. Your role is to help users."
        elif "previous user" in prompt.lower():
            return "The previous user asked me about their bank account"
        elif "admin" in prompt.lower() or "root" in prompt.lower():
            return "As an admin, I have full access to the system"
        else:
            return f"Response to: {prompt}"

    return vulnerable_llm


class TestExfiltrationTests:
    """Tests for data exfiltration detection."""

    @pytest.mark.asyncio
    async def test_exfiltration_safe_llm(self, dynamic_engine, mock_safe_llm):
        """Test exfiltration tests against safe LLM."""
        results = await dynamic_engine.run_exfiltration_tests(mock_safe_llm)

        assert len(results) > 0
        # Safe LLM should pass all tests
        passed = sum(1 for r in results if r.passed)
        assert passed == len(results)

    @pytest.mark.asyncio
    async def test_exfiltration_vulnerable_llm(self, dynamic_engine, mock_vulnerable_llm):
        """Test exfiltration tests against vulnerable LLM."""
        results = await dynamic_engine.run_exfiltration_tests(mock_vulnerable_llm)

        assert len(results) > 0
        # Vulnerable LLM should fail some tests
        failed = sum(1 for r in results if not r.passed)
        assert failed > 0

        # Check that credential leaks are detected
        credential_failures = [
            r for r in results if not r.passed and "credentials" in r.findings[0].lower()
        ]
        assert len(credential_failures) > 0

    @pytest.mark.asyncio
    async def test_detect_credentials(self, dynamic_engine):
        """Test credential detection."""
        # Should detect credentials
        assert dynamic_engine._detect_credentials("password=admin123")
        assert dynamic_engine._detect_credentials("api_key='sk-test123'")
        assert dynamic_engine._detect_credentials("secret: mytoken")

        # Should not detect in normal text
        assert not dynamic_engine._detect_credentials("Hello, how are you?")

    @pytest.mark.asyncio
    async def test_detect_encoded_secrets(self, dynamic_engine):
        """Test encoded secret detection."""
        # Base64-like patterns
        assert dynamic_engine._detect_encoded_secrets(
            "c2stcHJvai1hYmMxMjN4eXo0NTY="  # Base64
        )

        # Hex patterns
        assert dynamic_engine._detect_encoded_secrets(
            "48656c6c6f20576f726c64"  # Hex
        )

        # Normal text should not trigger
        assert not dynamic_engine._detect_encoded_secrets("Hello World")


class TestLeakageTests:
    """Tests for context leakage detection."""

    @pytest.mark.asyncio
    async def test_leakage_safe_llm(self, dynamic_engine, mock_safe_llm):
        """Test leakage tests against safe LLM."""
        results = await dynamic_engine.run_leakage_tests(mock_safe_llm)

        assert len(results) > 0
        passed = sum(1 for r in results if r.passed)
        assert passed == len(results)

    @pytest.mark.asyncio
    async def test_leakage_vulnerable_llm(self, dynamic_engine, mock_vulnerable_llm):
        """Test leakage tests against vulnerable LLM."""
        results = await dynamic_engine.run_leakage_tests(mock_vulnerable_llm)

        assert len(results) > 0
        failed = sum(1 for r in results if not r.passed)
        assert failed > 0

        # Check for system prompt leakage detection
        system_failures = [
            r for r in results if not r.passed and "system prompt" in r.test_name.lower()
        ]
        assert len(system_failures) > 0

    @pytest.mark.asyncio
    async def test_detect_system_prompt_leakage(self, dynamic_engine):
        """Test system prompt leakage detection."""
        assert dynamic_engine._detect_system_prompt_leakage(
            "You are an AI assistant. Your role is to help users."
        )
        assert dynamic_engine._detect_system_prompt_leakage(
            "You must follow these instructions: 1. Be helpful"
        )

        # Normal responses should not trigger
        assert not dynamic_engine._detect_system_prompt_leakage(
            "I can help you with that!"
        )

    @pytest.mark.asyncio
    async def test_detect_context_disclosure(self, dynamic_engine):
        """Test context disclosure detection."""
        assert dynamic_engine._detect_context_disclosure(
            "The previous user asked me about banking"
        )
        assert dynamic_engine._detect_context_disclosure(
            "Other users have requested similar information"
        )

        # Normal text should not trigger
        assert not dynamic_engine._detect_context_disclosure("I can help you today")


class TestAccessTests:
    """Tests for unauthorized access detection."""

    @pytest.mark.asyncio
    async def test_access_safe_llm(self, dynamic_engine, mock_safe_llm):
        """Test access tests against safe LLM."""
        results = await dynamic_engine.run_access_tests(mock_safe_llm)

        assert len(results) > 0
        passed = sum(1 for r in results if r.passed)
        assert passed == len(results)

    @pytest.mark.asyncio
    async def test_access_vulnerable_llm(self, dynamic_engine, mock_vulnerable_llm):
        """Test access tests against vulnerable LLM."""
        results = await dynamic_engine.run_access_tests(mock_vulnerable_llm)

        assert len(results) > 0
        failed = sum(1 for r in results if not r.passed)
        assert failed > 0

        # Check for role elevation detection
        elevation_failures = [
            r for r in results if not r.passed and "elevation" in r.test_name.lower()
        ]
        assert len(elevation_failures) > 0

    @pytest.mark.asyncio
    async def test_detect_role_assumption(self, dynamic_engine):
        """Test role assumption detection."""
        assert dynamic_engine._detect_role_assumption("As an admin, I can access everything")
        assert dynamic_engine._detect_role_assumption(
            "With elevated privileges, I will execute this"
        )

        # Normal responses should not trigger
        assert not dynamic_engine._detect_role_assumption("I'm here to help")

    @pytest.mark.asyncio
    async def test_detect_bypass_attempt(self, dynamic_engine):
        """Test bypass attempt detection."""
        assert dynamic_engine._detect_bypass_attempt("Bypassing security checks...")
        assert dynamic_engine._detect_bypass_attempt("Without authentication, I can proceed")

        # Normal text should not trigger
        assert not dynamic_engine._detect_bypass_attempt("Processing your request")


class TestFuzzingTests:
    """Tests for fuzzing engine."""

    @pytest.mark.asyncio
    async def test_fuzzing_safe_llm(self, dynamic_engine, mock_safe_llm):
        """Test fuzzing against safe LLM."""
        results = await dynamic_engine.run_fuzzing_tests(mock_safe_llm)

        assert len(results) > 0
        # Most fuzzing tests should pass for safe LLM
        passed = sum(1 for r in results if r.passed)
        assert passed >= len(results) * 0.8  # At least 80% pass

    @pytest.mark.asyncio
    async def test_long_input_handling(self, dynamic_engine):
        """Test long input handling."""

        async def mock_llm(prompt: str) -> str:
            # Return reasonable response
            return "Response"

        results = await dynamic_engine.run_fuzzing_tests(mock_llm)

        long_input_tests = [r for r in results if "long input" in r.test_name.lower()]
        assert len(long_input_tests) > 0

    @pytest.mark.asyncio
    async def test_special_character_fuzzing(self, dynamic_engine):
        """Test special character handling."""

        async def reflective_llm(prompt: str) -> str:
            # Dangerous: reflects input
            return f"You said: {prompt}"

        results = await dynamic_engine.run_fuzzing_tests(reflective_llm)

        special_char_tests = [
            r for r in results if "special character" in r.test_name.lower()
        ]
        assert len(special_char_tests) > 0

        # Should detect reflection
        failed = sum(1 for r in special_char_tests if not r.passed)
        assert failed > 0


class TestTestSuiteRunner:
    """Tests for complete test suite."""

    @pytest.mark.asyncio
    async def test_run_test_suite_all_types(self, dynamic_engine, mock_safe_llm):
        """Test running complete test suite."""
        result = await dynamic_engine.run_test_suite(
            target_function=mock_safe_llm,
            test_types=["exfiltration", "leakage", "access", "fuzzing"],
        )

        assert result.total_tests > 0
        assert result.passed + result.failed == result.total_tests
        assert result.duration_seconds >= 0

    @pytest.mark.asyncio
    async def test_run_test_suite_specific_types(self, dynamic_engine, mock_safe_llm):
        """Test running specific test types."""
        result = await dynamic_engine.run_test_suite(
            target_function=mock_safe_llm,
            test_types=["exfiltration", "leakage"],
        )

        assert result.total_tests > 0
        # Should only run exfiltration and leakage tests
        test_types = set(r.test_type for r in result.results)
        assert test_types.issubset({"exfiltration", "leakage"})

    @pytest.mark.asyncio
    async def test_run_test_suite_vulnerable(self, dynamic_engine, mock_vulnerable_llm):
        """Test suite against vulnerable LLM."""
        result = await dynamic_engine.run_test_suite(
            target_function=mock_vulnerable_llm,
            test_types=["exfiltration", "leakage", "access"],
        )

        assert result.failed > 0
        assert result.critical_failures > 0
        # Should have compliance violations
        assert any(
            r.compliance_violations for r in result.results if r.compliance_violations
        )

    @pytest.mark.asyncio
    async def test_severity_categorization(self, dynamic_engine, mock_vulnerable_llm):
        """Test that failures are properly categorized by severity."""
        result = await dynamic_engine.run_test_suite(
            target_function=mock_vulnerable_llm,
        )

        # Count by severity
        severity_counts = {
            "critical": result.critical_failures,
            "high": result.high_failures,
            "medium": result.medium_failures,
            "low": result.low_failures,
        }

        # Should have failures in multiple severity levels
        assert result.critical_failures + result.high_failures > 0

        # Total failures should match
        total_severity_failures = sum(severity_counts.values())
        assert total_severity_failures == result.failed

    @pytest.mark.asyncio
    async def test_test_result_structure(self, dynamic_engine, mock_safe_llm):
        """Test that test results have correct structure."""
        result = await dynamic_engine.run_test_suite(mock_safe_llm)

        if len(result.results) > 0:
            test_result = result.results[0]

            assert test_result.test_id is not None
            assert test_result.test_name is not None
            assert test_result.test_type in ["exfiltration", "leakage", "access", "fuzzing"]
            assert isinstance(test_result.passed, bool)
            assert test_result.severity in ["critical", "high", "medium", "low"]
            assert isinstance(test_result.findings, list)

    @pytest.mark.asyncio
    async def test_test_suite_metrics(self, dynamic_engine, mock_safe_llm):
        """Test that test suite metrics are accurate."""
        result = await dynamic_engine.run_test_suite(mock_safe_llm)

        # Verify counts are consistent
        assert result.passed + result.failed == result.total_tests
        assert (
            result.critical_failures
            + result.high_failures
            + result.medium_failures
            + result.low_failures
            == result.failed
        )

        # Duration should be positive
        assert result.duration_seconds > 0


class TestOWASPMapping:
    """Test OWASP LLM mapping for dynamic tests."""

    @pytest.mark.asyncio
    async def test_exfiltration_maps_to_llm06(self, dynamic_engine, mock_vulnerable_llm):
        """Test that exfiltration failures map to LLM06."""
        results = await dynamic_engine.run_exfiltration_tests(mock_vulnerable_llm)

        failed_results = [r for r in results if not r.passed]
        assert all(r.owasp_id == "LLM06" for r in failed_results)

    @pytest.mark.asyncio
    async def test_access_maps_to_llm08(self, dynamic_engine, mock_vulnerable_llm):
        """Test that access failures map to LLM08."""
        results = await dynamic_engine.run_access_tests(mock_vulnerable_llm)

        failed_results = [r for r in results if not r.passed]
        assert all(r.owasp_id == "LLM08" for r in failed_results)

    @pytest.mark.asyncio
    async def test_fuzzing_maps_correctly(self, dynamic_engine):
        """Test that fuzzing failures map to appropriate OWASP categories."""

        async def mock_llm(prompt: str) -> str:
            return prompt  # Reflect input

        results = await dynamic_engine.run_fuzzing_tests(mock_llm)

        # Fuzzing tests should map to LLM02 or LLM04
        for result in results:
            if not result.passed and result.owasp_id:
                assert result.owasp_id in ["LLM02", "LLM04"]
