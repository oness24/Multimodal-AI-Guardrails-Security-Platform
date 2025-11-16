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
