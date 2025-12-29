"""
AST-based code analyzer for Python, JavaScript, and TypeScript.
"""
import ast
import re
from dataclasses import dataclass
from typing import List, Optional


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


class ASTAnalyzer:
    """
    AST-based code analyzer for detecting security vulnerabilities.
    """

    async def analyze(self, code: str, language: str) -> List[Vulnerability]:
        """
        Analyze code using AST parsing.
        
        Args:
            code: Source code to analyze
            language: Programming language
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        if language == "python":
            vulnerabilities = self._analyze_python(code)
        elif language in ["javascript", "typescript"]:
            # For JS/TS, we'll use regex-based analysis as a fallback
            # Full AST analysis would require a JS parser
            vulnerabilities = self._analyze_javascript(code)

        return vulnerabilities

    def _analyze_python(self, code: str) -> List[Vulnerability]:
        """Analyze Python code using AST."""
        vulnerabilities = []
        lines = code.split("\n")

        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            vulnerabilities.append(
                Vulnerability(
                    id="SYNTAX-001",
                    title="Syntax Error",
                    severity="info",
                    confidence=1.0,
                    description=f"Code contains syntax error: {e}",
                    line_number=e.lineno,
                    remediation="Fix the syntax error before scanning",
                )
            )
            return vulnerabilities

        for node in ast.walk(tree):
            # Check for dangerous function calls
            if isinstance(node, ast.Call):
                vulns = self._check_python_call(node, lines)
                vulnerabilities.extend(vulns)

            # Check for dangerous imports
            if isinstance(node, ast.Import):
                vulns = self._check_python_import(node, lines)
                vulnerabilities.extend(vulns)

            if isinstance(node, ast.ImportFrom):
                vulns = self._check_python_import_from(node, lines)
                vulnerabilities.extend(vulns)

            # Check for string formatting with user input
            if isinstance(node, ast.JoinedStr):  # f-strings
                vulns = self._check_python_fstring(node, lines)
                vulnerabilities.extend(vulns)

        return vulnerabilities

    def _check_python_call(self, node: ast.Call, lines: List[str]) -> List[Vulnerability]:
        """Check Python function calls for vulnerabilities."""
        vulnerabilities = []
        
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{node.func.attr}"
            else:
                func_name = node.func.attr

        line_no = node.lineno
        snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""

        # Dangerous eval/exec
        if func_name in ["eval", "exec"]:
            vulnerabilities.append(
                Vulnerability(
                    id="PY-001",
                    title="Dangerous eval/exec Usage",
                    severity="critical",
                    confidence=0.95,
                    description=f"Use of {func_name}() can execute arbitrary code",
                    line_number=line_no,
                    code_snippet=snippet,
                    cwe_id="CWE-95",
                    owasp_category="A03:2021-Injection",
                    remediation="Avoid eval/exec. Use ast.literal_eval for safe evaluation of literals.",
                )
            )

        # os.system and subprocess with shell=True
        if func_name in ["os.system", "os.popen"]:
            vulnerabilities.append(
                Vulnerability(
                    id="PY-002",
                    title="Command Injection Risk",
                    severity="high",
                    confidence=0.90,
                    description="os.system/popen can lead to command injection",
                    line_number=line_no,
                    code_snippet=snippet,
                    cwe_id="CWE-78",
                    owasp_category="A03:2021-Injection",
                    remediation="Use subprocess.run with shell=False and pass arguments as a list",
                )
            )

        # subprocess with shell=True
        if "subprocess" in func_name:
            for keyword in node.keywords:
                if keyword.arg == "shell":
                    if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        vulnerabilities.append(
                            Vulnerability(
                                id="PY-003",
                                title="Shell Injection Risk",
                                severity="high",
                                confidence=0.85,
                                description="subprocess with shell=True can lead to shell injection",
                                line_number=line_no,
                                code_snippet=snippet,
                                cwe_id="CWE-78",
                                owasp_category="A03:2021-Injection",
                                remediation="Use shell=False and pass arguments as a list",
                            )
                        )

        # pickle.loads
        if func_name in ["pickle.loads", "pickle.load"]:
            vulnerabilities.append(
                Vulnerability(
                    id="PY-004",
                    title="Insecure Deserialization",
                    severity="critical",
                    confidence=0.95,
                    description="pickle can execute arbitrary code during deserialization",
                    line_number=line_no,
                    code_snippet=snippet,
                    cwe_id="CWE-502",
                    owasp_category="A08:2021-Software and Data Integrity Failures",
                    remediation="Use safer formats like JSON, or validate source before unpickling",
                )
            )

        # SQL query building
        if func_name == "execute" or "cursor" in func_name.lower():
            # Check if using string formatting
            if node.args:
                arg = node.args[0]
                if isinstance(arg, (ast.JoinedStr, ast.BinOp)):
                    vulnerabilities.append(
                        Vulnerability(
                            id="PY-005",
                            title="SQL Injection Risk",
                            severity="critical",
                            confidence=0.80,
                            description="SQL query built with string formatting",
                            line_number=line_no,
                            code_snippet=snippet,
                            cwe_id="CWE-89",
                            owasp_category="A03:2021-Injection",
                            remediation="Use parameterized queries with placeholders",
                        )
                    )

        return vulnerabilities

    def _check_python_import(self, node: ast.Import, lines: List[str]) -> List[Vulnerability]:
        """Check Python imports for dangerous modules."""
        vulnerabilities = []
        
        dangerous_imports = {
            "pickle": ("Insecure Serialization Module", "CWE-502"),
            "marshal": ("Insecure Serialization Module", "CWE-502"),
            "shelve": ("Insecure Serialization Module", "CWE-502"),
        }

        for alias in node.names:
            if alias.name in dangerous_imports:
                title, cwe = dangerous_imports[alias.name]
                vulnerabilities.append(
                    Vulnerability(
                        id="PY-IMP-001",
                        title=title,
                        severity="medium",
                        confidence=0.60,
                        description=f"Import of {alias.name} - use with caution",
                        line_number=node.lineno,
                        code_snippet=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                        cwe_id=cwe,
                        remediation="Consider using safer alternatives like JSON for serialization",
                    )
                )

        return vulnerabilities

    def _check_python_import_from(self, node: ast.ImportFrom, lines: List[str]) -> List[Vulnerability]:
        """Check Python from imports."""
        vulnerabilities = []
        
        if node.module == "xml.etree.ElementTree":
            vulnerabilities.append(
                Vulnerability(
                    id="PY-XML-001",
                    title="Potential XXE Vulnerability",
                    severity="medium",
                    confidence=0.50,
                    description="ElementTree may be vulnerable to XXE attacks",
                    line_number=node.lineno,
                    code_snippet=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                    cwe_id="CWE-611",
                    owasp_category="A05:2021-Security Misconfiguration",
                    remediation="Use defusedxml library for safe XML parsing",
                )
            )

        return vulnerabilities

    def _check_python_fstring(self, node: ast.JoinedStr, lines: List[str]) -> List[Vulnerability]:
        """Check f-strings for potential issues."""
        # This is a simplified check - would need more context analysis
        return []

    def _analyze_javascript(self, code: str) -> List[Vulnerability]:
        """Analyze JavaScript/TypeScript code using regex patterns."""
        vulnerabilities = []
        lines = code.split("\n")

        # Check for eval usage
        for i, line in enumerate(lines, 1):
            if re.search(r"\beval\s*\(", line):
                vulnerabilities.append(
                    Vulnerability(
                        id="JS-001",
                        title="Dangerous eval Usage",
                        severity="critical",
                        confidence=0.95,
                        description="eval() can execute arbitrary code",
                        line_number=i,
                        code_snippet=line.strip(),
                        cwe_id="CWE-95",
                        owasp_category="A03:2021-Injection",
                        remediation="Avoid eval. Use JSON.parse for JSON data, or safer alternatives.",
                    )
                )

            # innerHTML
            if "innerHTML" in line.lower():
                vulnerabilities.append(
                    Vulnerability(
                        id="JS-002",
                        title="XSS Risk via innerHTML",
                        severity="high",
                        confidence=0.80,
                        description="innerHTML can lead to XSS if used with user input",
                        line_number=i,
                        code_snippet=line.strip(),
                        cwe_id="CWE-79",
                        owasp_category="A03:2021-Injection",
                        remediation="Use textContent or sanitize input before using innerHTML",
                    )
                )

            # document.write
            if "document.write" in line:
                vulnerabilities.append(
                    Vulnerability(
                        id="JS-003",
                        title="XSS Risk via document.write",
                        severity="high",
                        confidence=0.85,
                        description="document.write can lead to XSS vulnerabilities",
                        line_number=i,
                        code_snippet=line.strip(),
                        cwe_id="CWE-79",
                        owasp_category="A03:2021-Injection",
                        remediation="Use DOM manipulation methods instead of document.write",
                    )
                )

            # dangerouslySetInnerHTML (React)
            if "dangerouslySetInnerHTML" in line:
                vulnerabilities.append(
                    Vulnerability(
                        id="JS-004",
                        title="XSS Risk in React",
                        severity="high",
                        confidence=0.80,
                        description="dangerouslySetInnerHTML can lead to XSS if misused",
                        line_number=i,
                        code_snippet=line.strip(),
                        cwe_id="CWE-79",
                        owasp_category="A03:2021-Injection",
                        remediation="Sanitize HTML content before using dangerouslySetInnerHTML",
                    )
                )

        return vulnerabilities
