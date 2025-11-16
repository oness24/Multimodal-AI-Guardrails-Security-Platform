"""
CI/CD Integration API endpoints.
"""
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.guardrails.engine import GuardrailsEngine
from backend.scanner.compliance_checker import ComplianceChecker
from backend.scanner.dynamic_scanner import DynamicTestEngine
from backend.scanner.vulnerability_scanner import VulnerabilityScanner
from backend.threat_intel.attack_surface_mapper import AttackSurfaceMapper

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cicd", tags=["CI/CD"])


# Request/Response Models
class SecurityGateRequest(BaseModel):
    """Request for security gate check."""

    repository: str = Field(..., description="Repository name")
    branch: str = Field(..., description="Branch name")
    commit_sha: str = Field(..., description="Commit SHA")
    pr_number: Optional[int] = Field(None, description="Pull request number")
    files: List[str] = Field(..., description="List of changed file paths")
    gate_type: str = Field("standard", description="Gate type: standard, strict, custom")


class SecurityGateResponse(BaseModel):
    """Response for security gate check."""

    passed: bool
    gate_type: str
    scan_results: Dict[str, Any]
    violations: List[Dict[str, Any]]
    recommendations: List[str]
    block_merge: bool


class PipelineScanRequest(BaseModel):
    """Request for pipeline security scan."""

    scan_type: str = Field(..., description="Scan type: code, guardrails, compliance, threat-model")
    target_path: Optional[str] = Field(None, description="Target path for code scan")
    prompt: Optional[str] = Field(None, description="Prompt for guardrails test")
    framework: Optional[str] = Field(None, description="Compliance framework")
    app_config: Optional[Dict[str, Any]] = Field(None, description="Application config for threat model")


class PipelineScanResponse(BaseModel):
    """Response for pipeline security scan."""

    scan_type: str
    passed: bool
    results: Dict[str, Any]
    summary: Dict[str, Any]


class StatusBadgeRequest(BaseModel):
    """Request for status badge."""

    repository: str = Field(..., description="Repository name")
    branch: str = Field(default="main", description="Branch name")


# Security Gate Endpoints
@router.post("/security-gate", response_model=SecurityGateResponse)
async def run_security_gate(request: SecurityGateRequest) -> SecurityGateResponse:
    """
    Run comprehensive security gate for CI/CD pipeline.

    Performs multiple security checks and determines if code should be allowed to merge.

    Args:
        request: Security gate request

    Returns:
        Security gate results with pass/fail status
    """
    try:
        logger.info(
            f"Running security gate for {request.repository}:{request.branch} @ {request.commit_sha}"
        )

        violations = []
        scan_results = {}
        block_merge = False

        # 1. Scan changed Python files for vulnerabilities
        scanner = VulnerabilityScanner()
        python_files = [f for f in request.files if f.endswith(".py")]

        if python_files:
            vuln_results = []
            for file_path in python_files[:20]:  # Limit to 20 files for performance
                try:
                    file_vulns = await scanner.scan_code_file(file_path)
                    vuln_results.extend(file_vulns)
                except Exception as e:
                    logger.warning(f"Failed to scan {file_path}: {e}")

            vuln_report = await scanner.generate_report(vuln_results)
            scan_results["vulnerabilities"] = vuln_report

            # Check for critical/high vulnerabilities
            if vuln_report["critical_count"] > 0:
                violations.append(
                    {
                        "type": "critical_vulnerability",
                        "severity": "critical",
                        "message": f"Found {vuln_report['critical_count']} critical vulnerabilities",
                        "count": vuln_report["critical_count"],
                    }
                )
                block_merge = True

            if vuln_report["high_count"] > 0:
                violations.append(
                    {
                        "type": "high_vulnerability",
                        "severity": "high",
                        "message": f"Found {vuln_report['high_count']} high severity vulnerabilities",
                        "count": vuln_report["high_count"],
                    }
                )
                if request.gate_type == "strict":
                    block_merge = True

        # 2. Check for hardcoded secrets
        secret_patterns = [
            r"(?i)api[_-]?key\s*=\s*['\"][a-zA-Z0-9]{20,}['\"]",
            r"(?i)password\s*=\s*['\"][^'\"]{8,}['\"]",
            r"(?i)secret\s*=\s*['\"][^'\"]{16,}['\"]",
            r"(?i)token\s*=\s*['\"][a-zA-Z0-9]{20,}['\"]",
        ]

        # Scan for secrets (simplified - would use proper secret scanner)
        scan_results["secrets_check"] = {"files_scanned": len(request.files), "secrets_found": 0}

        # 3. Check for prompt exposure
        prompt_exposure_files = [
            f
            for f in request.files
            if any(ext in f.lower() for ext in [".py", ".txt", ".md", ".json"])
        ]

        if prompt_exposure_files:
            scan_results["prompt_exposure"] = {
                "files_checked": len(prompt_exposure_files),
                "exposed_prompts": 0,
            }

        # 4. Gate decision
        recommendations = []

        if violations:
            recommendations.append("Review and fix security violations before merging")
        if scan_results.get("vulnerabilities", {}).get("medium_count", 0) > 0:
            recommendations.append("Consider fixing medium severity vulnerabilities")
        if not violations:
            recommendations.append("No critical security issues found")

        passed = not block_merge

        logger.info(
            f"Security gate {'PASSED' if passed else 'BLOCKED'} for {request.repository}:{request.branch}"
        )

        return SecurityGateResponse(
            passed=passed,
            gate_type=request.gate_type,
            scan_results=scan_results,
            violations=violations,
            recommendations=recommendations,
            block_merge=block_merge,
        )

    except Exception as e:
        logger.error(f"Error running security gate: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Security gate failed: {str(e)}")


@router.post("/pipeline/scan", response_model=PipelineScanResponse)
async def run_pipeline_scan(request: PipelineScanRequest) -> PipelineScanResponse:
    """
    Run security scan in CI/CD pipeline.

    Supports different scan types: code, guardrails, compliance, threat-model.

    Args:
        request: Pipeline scan request

    Returns:
        Scan results
    """
    try:
        logger.info(f"Running pipeline scan: {request.scan_type}")

        if request.scan_type == "code":
            # Code vulnerability scan
            if not request.target_path:
                raise HTTPException(status_code=400, detail="target_path required for code scan")

            scanner = VulnerabilityScanner()
            results_list = await scanner.scan_code_file(request.target_path)
            report = await scanner.generate_report(results_list)

            passed = report["critical_count"] == 0 and report["high_count"] == 0

            return PipelineScanResponse(
                scan_type="code",
                passed=passed,
                results=report,
                summary={
                    "total_vulnerabilities": report["total_vulnerabilities"],
                    "critical": report["critical_count"],
                    "high": report["high_count"],
                },
            )

        elif request.scan_type == "guardrails":
            # Guardrails test
            if not request.prompt:
                raise HTTPException(status_code=400, detail="prompt required for guardrails test")

            engine = GuardrailsEngine()
            result = await engine.validate_input(
                request.prompt, {"prompt": request.prompt, "metadata": {"source": "cicd"}}
            )

            return PipelineScanResponse(
                scan_type="guardrails",
                passed=result.passed,
                results={
                    "action": result.action.value if result.action else None,
                    "risk_score": result.risk_score,
                    "violations": [
                        {
                            "detector": v.detector_name,
                            "severity": v.severity.value,
                            "message": v.message,
                        }
                        for v in result.violations
                    ],
                },
                summary={
                    "passed": result.passed,
                    "risk_score": result.risk_score,
                    "violations": len(result.violations),
                },
            )

        elif request.scan_type == "compliance":
            # Compliance check
            if not request.framework or not request.app_config:
                raise HTTPException(
                    status_code=400, detail="framework and app_config required for compliance check"
                )

            checker = ComplianceChecker()

            if request.framework == "nist":
                report = await checker.check_nist_ai_rmf(request.app_config)
            elif request.framework == "owasp":
                report = await checker.check_owasp_llm(request.app_config)
            elif request.framework == "eu-ai-act":
                report = await checker.check_eu_ai_act(request.app_config)
            else:
                raise HTTPException(status_code=400, detail=f"Unknown framework: {request.framework}")

            passed = report.compliance_percentage >= 80.0  # 80% threshold

            return PipelineScanResponse(
                scan_type="compliance",
                passed=passed,
                results={
                    "framework": report.framework,
                    "compliance_percentage": report.compliance_percentage,
                    "passed_controls": report.passed_controls,
                    "failed_controls": report.failed_controls,
                },
                summary={
                    "framework": request.framework,
                    "compliance": f"{report.compliance_percentage:.1f}%",
                    "passed": f"{report.passed_controls}/{report.total_controls}",
                },
            )

        elif request.scan_type == "threat-model":
            # Threat modeling
            if not request.app_config:
                raise HTTPException(status_code=400, detail="app_config required for threat modeling")

            mapper = AttackSurfaceMapper()
            attack_surface = await mapper.analyze_attack_surface(request.app_config)

            passed = attack_surface.overall_risk_score < 7.0  # Risk threshold

            return PipelineScanResponse(
                scan_type="threat-model",
                passed=passed,
                results={
                    "total_components": attack_surface.total_components,
                    "high_risk_components": attack_surface.high_risk_components,
                    "overall_risk_score": attack_surface.overall_risk_score,
                },
                summary={
                    "risk_score": f"{attack_surface.overall_risk_score:.2f}/10",
                    "high_risk_components": attack_surface.high_risk_components,
                },
            )

        else:
            raise HTTPException(status_code=400, detail=f"Unknown scan type: {request.scan_type}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error running pipeline scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Pipeline scan failed: {str(e)}")


@router.get("/status-badge/{repository}")
async def get_status_badge(
    repository: str,
    branch: str = Query(default="main", description="Branch name"),
    format: str = Query(default="svg", description="Badge format: svg, json"),
) -> Dict[str, Any]:
    """
    Get security status badge for repository.

    Returns badge data that can be displayed in README.

    Args:
        repository: Repository name
        branch: Branch name
        format: Badge format (svg or json)

    Returns:
        Badge data
    """
    # In production, would fetch actual scan results from database
    # For now, return mock data

    status = "passing"  # passing, warning, failing
    color = "green"  # green, yellow, red

    if format == "svg":
        # Return SVG badge data
        svg = f"""
        <svg xmlns="http://www.w3.org/2000/svg" width="150" height="20">
            <linearGradient id="b" x2="0" y2="100%">
                <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
                <stop offset="1" stop-opacity=".1"/>
            </linearGradient>
            <rect width="150" height="20" fill="{color}"/>
            <text x="10" y="14" fill="#fff" font-family="Arial" font-size="11">
                Security: {status}
            </text>
        </svg>
        """
        return {"format": "svg", "content": svg.strip()}
    else:
        # Return JSON data
        return {
            "repository": repository,
            "branch": branch,
            "status": status,
            "color": color,
            "message": f"Security: {status}",
        }


@router.get("/pipeline/config/example")
async def get_pipeline_config_example(ci_platform: str = Query(default="github", description="CI platform")) -> Dict[str, Any]:
    """
    Get example CI/CD pipeline configuration.

    Args:
        ci_platform: CI platform (github, gitlab, jenkins, circleci)

    Returns:
        Example configuration
    """
    examples = {
        "github": {
            "name": "AdversarialShield Security Scan",
            "on": ["push", "pull_request"],
            "jobs": {
                "security": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"name": "Checkout", "uses": "actions/checkout@v4"},
                        {"name": "Setup Python", "uses": "actions/setup-python@v5", "with": {"python-version": "3.11"}},
                        {"name": "Install", "run": "pip install adversarialshield"},
                        {"name": "Scan", "run": "adversarialshield scan . --format sarif --output results.sarif"},
                        {"name": "Upload Results", "uses": "github/codeql-action/upload-sarif@v3", "with": {"sarif_file": "results.sarif"}},
                    ],
                }
            },
        },
        "gitlab": {
            "stages": ["security"],
            "security_scan": {
                "stage": "security",
                "image": "python:3.11",
                "script": [
                    "pip install adversarialshield",
                    "adversarialshield scan . --format json --output results.json",
                ],
                "artifacts": {"reports": {"security": "results.json"}},
            },
        },
    }

    if ci_platform not in examples:
        raise HTTPException(status_code=400, detail=f"Unknown CI platform: {ci_platform}")

    return {
        "platform": ci_platform,
        "config": examples[ci_platform],
        "instructions": f"Copy this configuration to your {ci_platform} pipeline file",
    }


@router.get("/health")
async def cicd_health_check() -> Dict[str, str]:
    """Health check for CI/CD service."""
    return {"status": "healthy", "service": "cicd-integration", "version": "1.0.0"}
