"""
Scanner Engine for vulnerability detection.
"""
import hashlib
import time
from dataclasses import dataclass, field
from typing import List, Optional

from backend.scanner.static_analysis.ast_analyzer import ASTAnalyzer
from backend.scanner.static_analysis.code_patterns import CodePatternScanner


@dataclass
class Vulnerability:
    """Detected vulnerability information."""
    id: str
    title: str
    severity: str
    confidence: float
    description: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: str = ""


@dataclass
class CodeScanResult:
    """Result of code scanning."""
    success: bool
    language: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    total_issues: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    scan_time_ms: int = 0
    source_hash: str = ""


@dataclass
class PromptScanResult:
    """Result of prompt template scanning."""
    success: bool
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    total_issues: int = 0
    is_safe: bool = True
    risk_score: float = 0.0
    scan_time_ms: int = 0


class ScannerEngine:
    """
    Main engine for vulnerability scanning.
    Orchestrates static and dynamic analysis.
    """

    def __init__(self):
        self.ast_analyzer = ASTAnalyzer()
        self.pattern_scanner = CodePatternScanner()

    async def scan_code(
        self,
        code: str,
        language: str,
        scan_type: str = "full",
    ) -> CodeScanResult:
        """
        Scan code for security vulnerabilities.
        
        Args:
            code: Source code to scan
            language: Programming language
            scan_type: 'quick', 'full', or 'deep'
            
        Returns:
            CodeScanResult with findings
        """
        start_time = time.time()
        vulnerabilities: List[Vulnerability] = []
        source_hash = hashlib.sha256(code.encode()).hexdigest()

        # Run AST analysis for supported languages
        if language in ["python", "javascript", "typescript"]:
            ast_vulns = await self.ast_analyzer.analyze(code, language)
            vulnerabilities.extend(ast_vulns)

        # Run pattern-based scanning
        pattern_vulns = await self.pattern_scanner.scan(code, language)
        vulnerabilities.extend(pattern_vulns)

        # Deduplicate vulnerabilities
        vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)

        # Count by severity
        critical_count = sum(1 for v in vulnerabilities if v.severity == "critical")
        high_count = sum(1 for v in vulnerabilities if v.severity == "high")
        medium_count = sum(1 for v in vulnerabilities if v.severity == "medium")
        low_count = sum(1 for v in vulnerabilities if v.severity == "low")

        scan_time = int((time.time() - start_time) * 1000)

        return CodeScanResult(
            success=True,
            language=language,
            vulnerabilities=vulnerabilities,
            total_issues=len(vulnerabilities),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            scan_time_ms=scan_time,
            source_hash=source_hash,
        )

    async def scan_prompt(
        self,
        prompt_template: str,
        variables: Optional[List[str]] = None,
    ) -> PromptScanResult:
        """
        Scan prompt template for security issues.
        
        Args:
            prompt_template: Prompt template to scan
            variables: Template variables (if any)
            
        Returns:
            PromptScanResult with findings
        """
        start_time = time.time()
        vulnerabilities: List[Vulnerability] = []
        template_lower = prompt_template.lower()

        # Check for unvalidated user input
        if "{user_input}" in prompt_template or "${user_input}" in prompt_template:
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
        pii_keywords = ["email", "phone", "ssn", "address", "credit card", "password"]
        if any(pii in template_lower for pii in pii_keywords):
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

        # Check for injection-vulnerable patterns
        if "{{" in prompt_template or "${" in prompt_template:
            if not any(safe in template_lower for safe in ["sanitize", "validate", "escape"]):
                vulnerabilities.append(
                    Vulnerability(
                        id="PROMPT-005",
                        title="Unescaped Template Variables",
                        severity="high",
                        confidence=0.80,
                        description="Template variables may not be properly escaped",
                        cwe_id="CWE-94",
                        owasp_category="LLM01:2023-Prompt Injection",
                        remediation="Ensure all template variables are properly validated and escaped",
                    )
                )

        # Check for output format manipulation risk
        format_keywords = ["json", "xml", "html", "markdown", "format"]
        if any(kw in template_lower for kw in format_keywords):
            if "user" in template_lower:
                vulnerabilities.append(
                    Vulnerability(
                        id="PROMPT-006",
                        title="Output Format Manipulation Risk",
                        severity="medium",
                        confidence=0.60,
                        description="User may be able to manipulate output format through input",
                        owasp_category="LLM02:2023-Insecure Output Handling",
                        remediation="Validate and sanitize output format, enforce strict output schemas",
                    )
                )

        # Calculate risk score
        risk_score = sum(
            0.4 if v.severity == "critical" else
            0.25 if v.severity == "high" else
            0.1 if v.severity == "medium" else 0.05
            for v in vulnerabilities
        )
        risk_score = min(risk_score, 1.0)

        scan_time = int((time.time() - start_time) * 1000)

        return PromptScanResult(
            success=True,
            vulnerabilities=vulnerabilities,
            total_issues=len(vulnerabilities),
            is_safe=risk_score < 0.5,
            risk_score=risk_score,
            scan_time_ms=scan_time,
        )

    def _deduplicate_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability],
    ) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities."""
        seen = {}
        for vuln in vulnerabilities:
            key = (vuln.title, vuln.line_number)
            if key not in seen or seen[key].confidence < vuln.confidence:
                seen[key] = vuln
        return list(seen.values())


# Singleton instance
scanner_engine = ScannerEngine()
