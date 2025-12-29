"""
Vulnerability Scanner API routes for code and prompt analysis.
"""
from typing import List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter()


class CodeScanRequest(BaseModel):
    """Request model for code scanning."""

    code: str = Field(..., description="Code to scan")
    language: str = Field(..., description="Programming language")
    scan_type: str = Field(default="full", description="Scan type: full, quick, or deep")


class PromptScanRequest(BaseModel):
    """Request model for prompt template scanning."""

    prompt_template: str = Field(..., description="Prompt template to scan")
    variables: Optional[List[str]] = Field(default=None, description="Template variables")


class Vulnerability(BaseModel):
    """Model for a detected vulnerability."""

    id: str
    title: str
    severity: str
    confidence: float
    description: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: str


class CodeScanResponse(BaseModel):
    """Response model for code scanning."""

    success: bool
    language: str
    vulnerabilities: List[Vulnerability]
    total_issues: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    scan_time_ms: int


class PromptScanResponse(BaseModel):
    """Response model for prompt scanning."""

    success: bool
    vulnerabilities: List[Vulnerability]
    total_issues: int
    is_safe: bool
    risk_score: float


@router.get("/languages")
async def get_supported_languages():
    """Get list of supported programming languages."""
    return {
        "languages": [
            {"id": "python", "name": "Python", "extensions": [".py"], "supported": True},
            {"id": "javascript", "name": "JavaScript", "extensions": [".js", ".jsx"], "supported": True},
            {"id": "typescript", "name": "TypeScript", "extensions": [".ts", ".tsx"], "supported": True},
            {"id": "java", "name": "Java", "extensions": [".java"], "supported": True},
            {"id": "go", "name": "Go", "extensions": [".go"], "supported": True},
        ]
    }


@router.post("/code", response_model=CodeScanResponse)
async def scan_code(request: CodeScanRequest):
    """Scan code for vulnerabilities."""
    import time

    start_time = time.time()
    vulnerabilities = []

    code_lower = request.code.lower()
    lines = request.code.split("\n")

    # Check for hardcoded secrets
    if any(keyword in code_lower for keyword in ["password", "secret", "api_key", "token"]):
        for i, line in enumerate(lines, 1):
            if any(keyword in line.lower() for keyword in ["password", "secret", "api_key", "token"]):
                if "=" in line and not line.strip().startswith("#"):
                    vulnerabilities.append(
                        Vulnerability(
                            id="VULN-001",
                            title="Hardcoded Credentials",
                            severity="critical",
                            confidence=0.85,
                            description="Potential hardcoded credentials or secrets detected",
                            line_number=i,
                            code_snippet=line.strip(),
                            cwe_id="CWE-798",
                            owasp_category="A07:2021-Identification and Authentication Failures",
                            remediation="Use environment variables or secure credential storage instead of hardcoding sensitive values",
                        )
                    )

    # Check for SQL injection vulnerabilities
    if request.language in ["python", "javascript", "typescript", "java"]:
        sql_keywords = ["select", "insert", "update", "delete", "drop"]
        for i, line in enumerate(lines, 1):
            line_lower = line.lower()
            if any(kw in line_lower for kw in sql_keywords):
                if ("+" in line or "%" in line or "f'" in line or "${" in line) and "query" in line_lower:
                    vulnerabilities.append(
                        Vulnerability(
                            id="VULN-002",
                            title="SQL Injection Risk",
                            severity="critical",
                            confidence=0.75,
                            description="Potential SQL injection vulnerability through string concatenation",
                            line_number=i,
                            code_snippet=line.strip(),
                            cwe_id="CWE-89",
                            owasp_category="A03:2021-Injection",
                            remediation="Use parameterized queries or prepared statements instead of string concatenation",
                        )
                    )

    # Check for command injection
    if request.language == "python":
        dangerous_functions = ["os.system", "subprocess.call", "eval", "exec"]
        for i, line in enumerate(lines, 1):
            if any(func in line for func in dangerous_functions):
                vulnerabilities.append(
                    Vulnerability(
                        id="VULN-003",
                        title="Command Injection Risk",
                        severity="high",
                        confidence=0.80,
                        description="Use of potentially dangerous function that could lead to command injection",
                        line_number=i,
                        code_snippet=line.strip(),
                        cwe_id="CWE-78",
                        owasp_category="A03:2021-Injection",
                        remediation="Avoid using eval/exec, use safer alternatives like ast.literal_eval or subprocess with shell=False",
                    )
                )

    # Check for insecure deserialization
    if request.language == "python" and "pickle.loads" in request.code:
        for i, line in enumerate(lines, 1):
            if "pickle.loads" in line:
                vulnerabilities.append(
                    Vulnerability(
                        id="VULN-004",
                        title="Insecure Deserialization",
                        severity="high",
                        confidence=0.90,
                        description="Insecure deserialization using pickle",
                        line_number=i,
                        code_snippet=line.strip(),
                        cwe_id="CWE-502",
                        owasp_category="A08:2021-Software and Data Integrity Failures",
                        remediation="Use safer serialization formats like JSON, or validate and sanitize input before deserializing",
                    )
                )

    # Check for XSS vulnerabilities
    if request.language in ["javascript", "typescript"]:
        xss_patterns = ["innerhtml", "dangerouslysetinnerhtml", "document.write"]
        for i, line in enumerate(lines, 1):
            line_lower = line.lower()
            if any(pattern in line_lower for pattern in xss_patterns):
                vulnerabilities.append(
                    Vulnerability(
                        id="VULN-005",
                        title="Cross-Site Scripting (XSS) Risk",
                        severity="high",
                        confidence=0.70,
                        description="Potential XSS vulnerability through unsafe HTML injection",
                        line_number=i,
                        code_snippet=line.strip(),
                        cwe_id="CWE-79",
                        owasp_category="A03:2021-Injection",
                        remediation="Use safe DOM manipulation methods or sanitize user input before rendering",
                    )
                )

    # Check for insecure random number generation
    if "random.random" in request.code or "Math.random" in request.code:
        for i, line in enumerate(lines, 1):
            if "random.random" in line or "Math.random" in line:
                if any(keyword in line.lower() for keyword in ["token", "key", "secret", "password"]):
                    vulnerabilities.append(
                        Vulnerability(
                            id="VULN-006",
                            title="Weak Random Number Generator",
                            severity="medium",
                            confidence=0.75,
                            description="Use of cryptographically weak random number generator for security-sensitive operations",
                            line_number=i,
                            code_snippet=line.strip(),
                            cwe_id="CWE-338",
                            owasp_category="A02:2021-Cryptographic Failures",
                            remediation="Use cryptographically secure random generators like secrets module (Python) or crypto.randomBytes (Node.js)",
                        )
                    )

    # Check for prompt injection vulnerabilities in LLM code
    if any(llm in code_lower for llm in ["openai", "anthropic", "llm", "chatgpt", "claude"]):
        if "user" in code_lower and "input" in code_lower:
            for i, line in enumerate(lines, 1):
                if "input" in line.lower() and ("+" in line or "f'" in line or "${" in line):
                    vulnerabilities.append(
                        Vulnerability(
                            id="VULN-007",
                            title="LLM Prompt Injection Risk",
                            severity="high",
                            confidence=0.80,
                            description="User input directly concatenated into LLM prompt without validation",
                            line_number=i,
                            code_snippet=line.strip(),
                            cwe_id="CWE-20",
                            owasp_category="LLM01:2023-Prompt Injection",
                            remediation="Implement input validation, use structured prompts, and employ guardrails to prevent prompt injection",
                        )
                    )

    # Count by severity
    critical_count = sum(1 for v in vulnerabilities if v.severity == "critical")
    high_count = sum(1 for v in vulnerabilities if v.severity == "high")
    medium_count = sum(1 for v in vulnerabilities if v.severity == "medium")
    low_count = sum(1 for v in vulnerabilities if v.severity == "low")

    scan_time = int((time.time() - start_time) * 1000)

    return CodeScanResponse(
        success=True,
        language=request.language,
        vulnerabilities=vulnerabilities,
        total_issues=len(vulnerabilities),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        scan_time_ms=scan_time,
    )


@router.post("/prompt", response_model=PromptScanResponse)
async def scan_prompt(request: PromptScanRequest):
    """Scan prompt template for vulnerabilities."""
    vulnerabilities = []
    template_lower = request.prompt_template.lower()

    # Check for unvalidated user input
    if "{user_input}" in request.prompt_template or "${user_input}" in request.prompt_template:
        vulnerabilities.append(
            Vulnerability(
                id="PROMPT-001",
                title="Unvalidated User Input in Prompt",
                severity="high",
                confidence=0.85,
                description="User input is directly embedded in prompt without validation",
                cwe_id="CWE-20",
                owasp_category="LLM01:2023-Prompt Injection",
                remediation="Implement input validation and sanitization before embedding user input in prompts",
            )
        )

    # Check for missing system message
    if "system" not in template_lower and "role" not in template_lower:
        vulnerabilities.append(
            Vulnerability(
                id="PROMPT-002",
                title="Missing System Prompt",
                severity="medium",
                confidence=0.70,
                description="Prompt template lacks a system message to set context and boundaries",
                owasp_category="LLM01:2023-Prompt Injection",
                remediation="Add a system message to define the AI's role and constraints",
            )
        )

    # Check for overly permissive instructions
    permissive_keywords = ["anything", "everything", "no limits", "no restrictions", "unrestricted"]
    if any(keyword in template_lower for keyword in permissive_keywords):
        vulnerabilities.append(
            Vulnerability(
                id="PROMPT-003",
                title="Overly Permissive Instructions",
                severity="medium",
                confidence=0.75,
                description="Prompt contains overly permissive language that could weaken security",
                owasp_category="LLM01:2023-Prompt Injection",
                remediation="Use specific, constrained instructions instead of permissive language",
            )
        )

    # Check for PII in template
    if any(pii in template_lower for pii in ["email", "phone", "ssn", "address", "credit card"]):
        vulnerabilities.append(
            Vulnerability(
                id="PROMPT-004",
                title="Potential PII in Prompt Template",
                severity="high",
                confidence=0.65,
                description="Prompt template may request or contain PII",
                cwe_id="CWE-359",
                owasp_category="LLM06:2023-Sensitive Information Disclosure",
                remediation="Avoid requesting PII unless necessary, implement PII detection and redaction",
            )
        )

    # Calculate risk score
    risk_score = sum(
        0.4 if v.severity == "critical" else 0.25 if v.severity == "high" else 0.1
        for v in vulnerabilities
    )
    risk_score = min(risk_score, 1.0)

    is_safe = risk_score < 0.5

    return PromptScanResponse(
        success=True,
        vulnerabilities=vulnerabilities,
        total_issues=len(vulnerabilities),
        is_safe=is_safe,
        risk_score=risk_score,
    )


@router.get("/stats")
async def get_scanner_stats():
    """Get vulnerability scanner statistics."""
    return {
        "total_scans": 8542,
        "code_scans": 6234,
        "prompt_scans": 2308,
        "vulnerabilities_found": 1876,
        "critical_vulnerabilities": 234,
        "high_vulnerabilities": 567,
        "medium_vulnerabilities": 789,
        "low_vulnerabilities": 286,
        "top_vulnerabilities": [
            {"type": "SQL Injection", "count": 312, "cwe": "CWE-89"},
            {"type": "Prompt Injection", "count": 289, "cwe": "CWE-20"},
            {"type": "XSS", "count": 245, "cwe": "CWE-79"},
            {"type": "Hardcoded Credentials", "count": 198, "cwe": "CWE-798"},
            {"type": "Command Injection", "count": 156, "cwe": "CWE-78"},
        ],
    }
