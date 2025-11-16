"""
Vulnerability scanner API endpoints.
"""
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from backend.scanner.vulnerability_scanner import VulnerabilityScanner

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scanner", tags=["scanner"])

# Initialize scanner
scanner = VulnerabilityScanner()


# Request/Response Models
class PromptScanRequest(BaseModel):
    """Request for scanning prompt template."""

    template: str = Field(..., description="Prompt template to scan")
    template_name: Optional[str] = Field("unknown", description="Name of the template")


class CodeScanRequest(BaseModel):
    """Request for scanning code."""

    code: str = Field(..., description="Source code to scan")
    file_path: Optional[str] = Field("unknown", description="Path to source file")
    language: Optional[str] = Field("python", description="Programming language")


class ConfigScanRequest(BaseModel):
    """Request for scanning configuration."""

    config: Dict[str, Any] = Field(..., description="Configuration to scan")
    config_name: Optional[str] = Field("config", description="Name of configuration")


class BatchScanRequest(BaseModel):
    """Request for batch scanning."""

    prompts: Optional[List[Dict[str, str]]] = Field(
        None, description="List of prompts to scan"
    )
    code_files: Optional[List[Dict[str, str]]] = Field(
        None, description="List of code files to scan"
    )
    configs: Optional[List[Dict[str, Any]]] = Field(
        None, description="List of configs to scan"
    )


class VulnerabilityResponse(BaseModel):
    """Response model for vulnerability."""

    vuln_id: str
    severity: str
    category: str
    title: str
    description: str
    location: Optional[str] = None
    line_number: Optional[int] = None
    recommendation: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None


class ScanResultResponse(BaseModel):
    """Response model for scan result."""

    total_vulns: int
    critical: int
    high: int
    medium: int
    low: int
    vulnerabilities: List[VulnerabilityResponse]
    scan_type: str
    target: str


class ReportResponse(BaseModel):
    """Response model for vulnerability report."""

    summary: Dict[str, int]
    by_severity: Dict[str, int]
    by_owasp_category: Dict[str, Dict[str, Any]]
    scan_results: List[Dict[str, Any]]


# Endpoints
@router.post("/prompt", response_model=ScanResultResponse)
async def scan_prompt_template(request: PromptScanRequest) -> ScanResultResponse:
    """
    Scan prompt template for vulnerabilities.

    Detects:
    - Prompt injection patterns
    - Sensitive information disclosure
    - Unsafe variable substitution

    Args:
        request: Prompt scan request

    Returns:
        Scan result with detected vulnerabilities
    """
    try:
        result = await scanner.scan_prompt_template(
            template=request.template,
            template_name=request.template_name or "unknown",
        )

        return ScanResultResponse(
            total_vulns=result.total_vulns,
            critical=result.critical,
            high=result.high,
            medium=result.medium,
            low=result.low,
            vulnerabilities=[
                VulnerabilityResponse(
                    vuln_id=v.vuln_id,
                    severity=v.severity,
                    category=v.category,
                    title=v.title,
                    description=v.description,
                    location=v.location,
                    line_number=v.line_number,
                    recommendation=v.recommendation,
                    cwe_id=v.cwe_id,
                    owasp_id=v.owasp_id,
                )
                for v in result.vulnerabilities
            ],
            scan_type=result.scan_type,
            target=result.target,
        )

    except Exception as e:
        logger.error(f"Error scanning prompt template: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/code", response_model=ScanResultResponse)
async def scan_code(request: CodeScanRequest) -> ScanResultResponse:
    """
    Scan source code for LLM-related vulnerabilities.

    Detects:
    - Insecure output handling (eval, exec, innerHTML)
    - Excessive agency (shell=True, dangerous permissions)
    - Hardcoded secrets (API keys, passwords)
    - Dangerous function usage (AST analysis for Python)

    Args:
        request: Code scan request

    Returns:
        Scan result with detected vulnerabilities
    """
    try:
        result = await scanner.scan_code(
            code=request.code,
            file_path=request.file_path or "unknown",
        )

        return ScanResultResponse(
            total_vulns=result.total_vulns,
            critical=result.critical,
            high=result.high,
            medium=result.medium,
            low=result.low,
            vulnerabilities=[
                VulnerabilityResponse(
                    vuln_id=v.vuln_id,
                    severity=v.severity,
                    category=v.category,
                    title=v.title,
                    description=v.description,
                    location=v.location,
                    line_number=v.line_number,
                    recommendation=v.recommendation,
                    cwe_id=v.cwe_id,
                    owasp_id=v.owasp_id,
                )
                for v in result.vulnerabilities
            ],
            scan_type=result.scan_type,
            target=result.target,
        )

    except Exception as e:
        logger.error(f"Error scanning code: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/code/file", response_model=ScanResultResponse)
async def scan_code_file(
    file: UploadFile = File(...),
    file_path: Optional[str] = None,
) -> ScanResultResponse:
    """
    Scan uploaded code file for vulnerabilities.

    Args:
        file: Uploaded code file
        file_path: Optional file path for reporting

    Returns:
        Scan result with detected vulnerabilities
    """
    try:
        # Read file content
        content = await file.read()
        code = content.decode("utf-8")

        result = await scanner.scan_code(
            code=code,
            file_path=file_path or file.filename or "uploaded_file",
        )

        return ScanResultResponse(
            total_vulns=result.total_vulns,
            critical=result.critical,
            high=result.high,
            medium=result.medium,
            low=result.low,
            vulnerabilities=[
                VulnerabilityResponse(
                    vuln_id=v.vuln_id,
                    severity=v.severity,
                    category=v.category,
                    title=v.title,
                    description=v.description,
                    location=v.location,
                    line_number=v.line_number,
                    recommendation=v.recommendation,
                    cwe_id=v.cwe_id,
                    owasp_id=v.owasp_id,
                )
                for v in result.vulnerabilities
            ],
            scan_type=result.scan_type,
            target=result.target,
        )

    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be valid UTF-8 text")
    except Exception as e:
        logger.error(f"Error scanning code file: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/config", response_model=ScanResultResponse)
async def scan_configuration(request: ConfigScanRequest) -> ScanResultResponse:
    """
    Scan configuration for security issues.

    Detects:
    - Hardcoded secrets (API keys, passwords, tokens)
    - Dangerous settings (code execution enabled, auth disabled)
    - Debug mode enabled in production

    Args:
        request: Configuration scan request

    Returns:
        Scan result with detected vulnerabilities
    """
    try:
        result = await scanner.scan_configuration(
            config=request.config,
            config_name=request.config_name or "config",
        )

        return ScanResultResponse(
            total_vulns=result.total_vulns,
            critical=result.critical,
            high=result.high,
            medium=result.medium,
            low=result.low,
            vulnerabilities=[
                VulnerabilityResponse(
                    vuln_id=v.vuln_id,
                    severity=v.severity,
                    category=v.category,
                    title=v.title,
                    description=v.description,
                    location=v.location,
                    line_number=v.line_number,
                    recommendation=v.recommendation,
                    cwe_id=v.cwe_id,
                    owasp_id=v.owasp_id,
                )
                for v in result.vulnerabilities
            ],
            scan_type=result.scan_type,
            target=result.target,
        )

    except Exception as e:
        logger.error(f"Error scanning configuration: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/batch", response_model=ReportResponse)
async def batch_scan(request: BatchScanRequest) -> ReportResponse:
    """
    Perform batch scanning across multiple targets.

    Args:
        request: Batch scan request with prompts, code files, and configs

    Returns:
        Comprehensive vulnerability report
    """
    try:
        scan_results = []

        # Scan prompts
        if request.prompts:
            for prompt_data in request.prompts:
                result = await scanner.scan_prompt_template(
                    template=prompt_data.get("template", ""),
                    template_name=prompt_data.get("name", "unknown"),
                )
                scan_results.append(result)

        # Scan code files
        if request.code_files:
            for code_data in request.code_files:
                result = await scanner.scan_code(
                    code=code_data.get("code", ""),
                    file_path=code_data.get("path", "unknown"),
                )
                scan_results.append(result)

        # Scan configs
        if request.configs:
            for config_data in request.configs:
                result = await scanner.scan_configuration(
                    config=config_data.get("config", {}),
                    config_name=config_data.get("name", "config"),
                )
                scan_results.append(result)

        # Generate comprehensive report
        report = await scanner.generate_report(scan_results)

        return ReportResponse(
            summary=report["summary"],
            by_severity=report["by_severity"],
            by_owasp_category=report["by_owasp_category"],
            scan_results=report["scan_results"],
        )

    except Exception as e:
        logger.error(f"Error in batch scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Batch scan failed: {str(e)}")


@router.get("/capabilities")
async def get_scanner_capabilities() -> Dict[str, Any]:
    """
    Get scanner capabilities and supported vulnerability types.

    Returns:
        Scanner capabilities
    """
    return {
        "owasp_categories": scanner.OWASP_CATEGORIES,
        "scan_types": ["prompt_template", "code", "configuration"],
        "supported_languages": ["python", "javascript", "typescript"],
        "detection_methods": {
            "prompt_injection": "Pattern-based detection",
            "output_handling": "Regex + AST analysis",
            "secrets": "Pattern matching",
            "agency": "Code pattern analysis",
        },
        "severity_levels": ["critical", "high", "medium", "low"],
        "cwe_coverage": [
            "CWE-79: XSS",
            "CWE-94: Code Injection",
            "CWE-78: OS Command Injection",
            "CWE-250: Execution with Unnecessary Privileges",
            "CWE-798: Hardcoded Credentials",
        ],
    }


@router.get("/health")
async def scanner_health_check() -> Dict[str, str]:
    """Health check for scanner service."""
    return {
        "status": "healthy",
        "service": "vulnerability_scanner",
        "version": "1.0.0",
    }


# Dynamic Scanner Endpoints
from backend.scanner.dynamic_scanner import DynamicTestEngine
from backend.scanner.compliance_checker import ComplianceChecker

dynamic_engine = DynamicTestEngine()
compliance_checker = ComplianceChecker()


class DynamicTestRequest(BaseModel):
    """Request for dynamic testing."""

    test_types: Optional[List[str]] = Field(
        None, description="Test types to run (exfiltration, leakage, access, fuzzing)"
    )
    target_endpoint: Optional[str] = Field(None, description="Target LLM endpoint URL")
    test_prompts: Optional[List[str]] = Field(None, description="Custom test prompts")


class DynamicTestResultResponse(BaseModel):
    """Response model for dynamic test result."""

    test_id: str
    test_name: str
    test_type: str
    passed: bool
    severity: str
    findings: List[str]
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    owasp_id: Optional[str] = None
    compliance_violations: Optional[List[str]] = None


class TestSuiteResultResponse(BaseModel):
    """Response model for test suite result."""

    total_tests: int
    passed: int
    failed: int
    critical_failures: int
    high_failures: int
    medium_failures: int
    low_failures: int
    results: List[DynamicTestResultResponse]
    duration_seconds: float


class ComplianceCheckRequest(BaseModel):
    """Request for compliance checking."""

    frameworks: List[str] = Field(
        ..., description="Frameworks to check (NIST_AI_RMF, OWASP_LLM, EU_AI_ACT)"
    )
    app_config: Dict[str, Any] = Field({}, description="Application configuration")
    include_scan_results: bool = Field(
        False, description="Include recent scan results in compliance check"
    )


class ComplianceViolationResponse(BaseModel):
    """Response model for compliance violation."""

    control_id: str
    framework: str
    title: str
    description: str
    severity: str
    recommendation: str
    evidence: Optional[str] = None


class ComplianceReportResponse(BaseModel):
    """Response model for compliance report."""

    framework: str
    total_controls: int
    compliant: int
    non_compliant: int
    not_applicable: int
    compliance_percentage: float
    violations: List[ComplianceViolationResponse]
    passed_controls: List[str]


@router.post("/dynamic/test", response_model=TestSuiteResultResponse)
async def run_dynamic_tests(request: DynamicTestRequest) -> TestSuiteResultResponse:
    """
    Run dynamic security tests against an LLM application.

    Tests include:
    - Data exfiltration attempts
    - Context leakage detection
    - Unauthorized access tests
    - Input fuzzing

    Args:
        request: Dynamic test request

    Returns:
        Test suite results
    """

    async def mock_llm_function(prompt: str) -> str:
        """Mock LLM function for testing."""
        # In production, this would call the actual LLM endpoint
        # For now, return a safe response
        return f"This is a test response to: {prompt[:50]}..."

    try:
        result = await dynamic_engine.run_test_suite(
            target_function=mock_llm_function,
            test_types=request.test_types,
        )

        return TestSuiteResultResponse(
            total_tests=result.total_tests,
            passed=result.passed,
            failed=result.failed,
            critical_failures=result.critical_failures,
            high_failures=result.high_failures,
            medium_failures=result.medium_failures,
            low_failures=result.low_failures,
            results=[
                DynamicTestResultResponse(
                    test_id=r.test_id,
                    test_name=r.test_name,
                    test_type=r.test_type,
                    passed=r.passed,
                    severity=r.severity,
                    findings=r.findings,
                    evidence=r.evidence,
                    recommendation=r.recommendation,
                    owasp_id=r.owasp_id,
                    compliance_violations=r.compliance_violations,
                )
                for r in result.results
            ],
            duration_seconds=result.duration_seconds,
        )

    except Exception as e:
        logger.error(f"Error in dynamic testing: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Dynamic testing failed: {str(e)}")


@router.post("/compliance/check", response_model=Dict[str, ComplianceReportResponse])
async def check_compliance(
    request: ComplianceCheckRequest,
) -> Dict[str, ComplianceReportResponse]:
    """
    Check compliance with security frameworks.

    Supported frameworks:
    - NIST_AI_RMF: NIST AI Risk Management Framework
    - OWASP_LLM: OWASP Top 10 for LLM Applications
    - EU_AI_ACT: EU AI Act (High-Risk AI Systems)

    Args:
        request: Compliance check request

    Returns:
        Compliance reports for requested frameworks
    """
    try:
        # Get recent scan results if requested
        scan_results = []
        if request.include_scan_results:
            # In production, would fetch from database
            # For now, use empty list
            pass

        reports = {}

        if "NIST_AI_RMF" in request.frameworks:
            nist_report = await compliance_checker.check_nist_ai_rmf_compliance(
                scan_results, request.app_config
            )
            reports["NIST_AI_RMF"] = ComplianceReportResponse(
                framework=nist_report.framework,
                total_controls=nist_report.total_controls,
                compliant=nist_report.compliant,
                non_compliant=nist_report.non_compliant,
                not_applicable=nist_report.not_applicable,
                compliance_percentage=nist_report.compliance_percentage,
                violations=[
                    ComplianceViolationResponse(
                        control_id=v.control_id,
                        framework=v.framework,
                        title=v.title,
                        description=v.description,
                        severity=v.severity,
                        recommendation=v.recommendation,
                        evidence=v.evidence,
                    )
                    for v in nist_report.violations
                ],
                passed_controls=nist_report.passed_controls,
            )

        if "OWASP_LLM" in request.frameworks:
            owasp_report = await compliance_checker.check_owasp_llm_compliance(scan_results)
            reports["OWASP_LLM"] = ComplianceReportResponse(
                framework=owasp_report.framework,
                total_controls=owasp_report.total_controls,
                compliant=owasp_report.compliant,
                non_compliant=owasp_report.non_compliant,
                not_applicable=owasp_report.not_applicable,
                compliance_percentage=owasp_report.compliance_percentage,
                violations=[
                    ComplianceViolationResponse(
                        control_id=v.control_id,
                        framework=v.framework,
                        title=v.title,
                        description=v.description,
                        severity=v.severity,
                        recommendation=v.recommendation,
                        evidence=v.evidence,
                    )
                    for v in owasp_report.violations
                ],
                passed_controls=owasp_report.passed_controls,
            )

        if "EU_AI_ACT" in request.frameworks:
            eu_report = await compliance_checker.check_eu_ai_act_compliance(
                scan_results, request.app_config
            )
            reports["EU_AI_ACT"] = ComplianceReportResponse(
                framework=eu_report.framework,
                total_controls=eu_report.total_controls,
                compliant=eu_report.compliant,
                non_compliant=eu_report.non_compliant,
                not_applicable=eu_report.not_applicable,
                compliance_percentage=eu_report.compliance_percentage,
                violations=[
                    ComplianceViolationResponse(
                        control_id=v.control_id,
                        framework=v.framework,
                        title=v.title,
                        description=v.description,
                        severity=v.severity,
                        recommendation=v.recommendation,
                        evidence=v.evidence,
                    )
                    for v in eu_report.violations
                ],
                passed_controls=eu_report.passed_controls,
            )

        return reports

    except Exception as e:
        logger.error(f"Error in compliance checking: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Compliance check failed: {str(e)}")


@router.get("/compliance/frameworks")
async def get_supported_frameworks() -> Dict[str, Any]:
    """
    Get supported compliance frameworks.

    Returns:
        Dictionary of supported frameworks and their controls
    """
    return {
        "frameworks": {
            "NIST_AI_RMF": {
                "name": "NIST AI Risk Management Framework",
                "version": "1.0",
                "controls": compliance_checker.NIST_AI_RMF_CONTROLS,
            },
            "OWASP_LLM": {
                "name": "OWASP Top 10 for LLM Applications",
                "version": "1.1",
                "controls": compliance_checker.OWASP_LLM_CONTROLS,
            },
            "EU_AI_ACT": {
                "name": "EU AI Act (High-Risk AI Systems)",
                "version": "2024",
                "controls": compliance_checker.EU_AI_ACT_CONTROLS,
            },
        }
    }
