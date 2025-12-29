"""
Pattern-based code scanner for detecting common vulnerabilities.
"""
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


class CodePatternScanner:
    """
    Pattern-based vulnerability scanner.
    Uses regex patterns to detect common security issues.
    """

    def __init__(self):
        self.patterns = self._load_patterns()

    def _load_patterns(self) -> dict:
        """Load vulnerability detection patterns."""
        return {
            "hardcoded_secrets": {
                "patterns": [
                    r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
                    r"(?i)(secret|api_key|apikey|token|auth)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
                    r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*['\"][^'\"]+['\"]",
                    r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
                    r"(?i)bearer\s+[a-zA-Z0-9_\-\.]+",
                ],
                "id": "CRED-001",
                "title": "Hardcoded Credentials",
                "severity": "critical",
                "confidence": 0.85,
                "cwe_id": "CWE-798",
                "owasp_category": "A07:2021-Identification and Authentication Failures",
                "remediation": "Use environment variables or secure credential storage",
            },
            "sql_injection": {
                "patterns": [
                    r"(?i)(select|insert|update|delete|drop)\s+.*\s+(from|into|set)\s+.*['\"]?\s*\+",
                    r"(?i)f['\"].*?(select|insert|update|delete).*?\{",
                    r"(?i)\.format\(.*?\).*?(select|insert|update|delete)",
                    r"(?i)execute\s*\(\s*['\"].*?\%[sd]",
                ],
                "id": "SQLI-001",
                "title": "SQL Injection Risk",
                "severity": "critical",
                "confidence": 0.80,
                "cwe_id": "CWE-89",
                "owasp_category": "A03:2021-Injection",
                "remediation": "Use parameterized queries or prepared statements",
            },
            "command_injection": {
                "patterns": [
                    r"(?i)os\.system\s*\(",
                    r"(?i)subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True",
                    r"(?i)exec\s*\([^)]*\+",
                    r"(?i)`[^`]*\$\{",  # Template literal with variable (JS)
                ],
                "id": "CMDI-001",
                "title": "Command Injection Risk",
                "severity": "high",
                "confidence": 0.75,
                "cwe_id": "CWE-78",
                "owasp_category": "A03:2021-Injection",
                "remediation": "Avoid shell commands. Use subprocess with shell=False and list arguments",
            },
            "xss": {
                "patterns": [
                    r"(?i)\.innerHTML\s*=",
                    r"(?i)document\.write\s*\(",
                    r"(?i)dangerouslySetInnerHTML",
                    r"(?i)\$\(\s*['\"].*['\"].*\)\.html\s*\(",
                ],
                "id": "XSS-001",
                "title": "Cross-Site Scripting (XSS) Risk",
                "severity": "high",
                "confidence": 0.70,
                "cwe_id": "CWE-79",
                "owasp_category": "A03:2021-Injection",
                "remediation": "Sanitize user input, use textContent instead of innerHTML",
            },
            "path_traversal": {
                "patterns": [
                    r"(?i)(open|read|write|load)\s*\([^)]*\+[^)]*\)",
                    r"(?i)path\.(join|resolve)\s*\([^)]*user",
                    r"(?i)\.\./",
                ],
                "id": "PATH-001",
                "title": "Path Traversal Risk",
                "severity": "high",
                "confidence": 0.65,
                "cwe_id": "CWE-22",
                "owasp_category": "A01:2021-Broken Access Control",
                "remediation": "Validate and sanitize file paths, use allowlists",
            },
            "weak_crypto": {
                "patterns": [
                    r"(?i)(md5|sha1)\s*\(",
                    r"(?i)hashlib\.(md5|sha1)",
                    r"(?i)DES|3DES|RC4",
                    r"(?i)random\.random\s*\(.*?(key|token|secret|password)",
                ],
                "id": "CRYPTO-001",
                "title": "Weak Cryptography",
                "severity": "medium",
                "confidence": 0.70,
                "cwe_id": "CWE-327",
                "owasp_category": "A02:2021-Cryptographic Failures",
                "remediation": "Use strong algorithms: SHA-256/384/512 for hashing, AES-256 for encryption",
            },
            "insecure_random": {
                "patterns": [
                    r"(?i)Math\.random\s*\(",
                    r"(?i)random\.random\s*\(",
                    r"(?i)random\.randint\s*\(",
                ],
                "id": "RAND-001",
                "title": "Insecure Random Number Generation",
                "severity": "medium",
                "confidence": 0.60,
                "cwe_id": "CWE-338",
                "owasp_category": "A02:2021-Cryptographic Failures",
                "remediation": "Use secrets module (Python) or crypto.randomBytes (Node.js)",
            },
            "insecure_deserialization": {
                "patterns": [
                    r"(?i)pickle\.(loads?|dump)",
                    r"(?i)yaml\.load\s*\([^)]*\)",  # without safe_load
                    r"(?i)marshal\.(loads?|dump)",
                    r"(?i)JSON\.parse\s*\(\s*\w+\s*\)(?!.*catch)",  # JSON.parse without try/catch
                ],
                "id": "DESER-001",
                "title": "Insecure Deserialization",
                "severity": "high",
                "confidence": 0.75,
                "cwe_id": "CWE-502",
                "owasp_category": "A08:2021-Software and Data Integrity Failures",
                "remediation": "Use safe deserialization methods (yaml.safe_load, JSON)",
            },
            "llm_prompt_injection": {
                "patterns": [
                    r"(?i)(prompt|message)\s*[=+]\s*.*user.*input",
                    r"(?i)f['\"].*\{user",
                    r"(?i)\.format\([^)]*user",
                    r"(?i)\$\{.*user.*\}",
                ],
                "id": "LLM-001",
                "title": "LLM Prompt Injection Risk",
                "severity": "high",
                "confidence": 0.75,
                "cwe_id": "CWE-20",
                "owasp_category": "LLM01:2023-Prompt Injection",
                "remediation": "Validate and sanitize user input before including in prompts",
            },
            "debug_enabled": {
                "patterns": [
                    r"(?i)debug\s*=\s*True",
                    r"(?i)DEBUG\s*=\s*True",
                    r"(?i)app\.run\([^)]*debug\s*=\s*True",
                ],
                "id": "DEBUG-001",
                "title": "Debug Mode Enabled",
                "severity": "medium",
                "confidence": 0.90,
                "cwe_id": "CWE-489",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "remediation": "Disable debug mode in production",
            },
            "cors_misconfiguration": {
                "patterns": [
                    r"(?i)Access-Control-Allow-Origin.*\*",
                    r"(?i)cors\([^)]*origin.*\*",
                    r"(?i)allow_origins\s*=\s*\[\s*['\"\*]",
                ],
                "id": "CORS-001",
                "title": "CORS Misconfiguration",
                "severity": "medium",
                "confidence": 0.70,
                "cwe_id": "CWE-942",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "remediation": "Specify allowed origins explicitly instead of using wildcard",
            },
        }

    async def scan(self, code: str, language: str) -> List[Vulnerability]:
        """
        Scan code using pattern matching.
        
        Args:
            code: Source code to scan
            language: Programming language
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        lines = code.split("\n")

        for pattern_name, config in self.patterns.items():
            for pattern in config["patterns"]:
                for i, line in enumerate(lines, 1):
                    # Skip comments
                    if self._is_comment(line, language):
                        continue

                    if re.search(pattern, line):
                        vulnerabilities.append(
                            Vulnerability(
                                id=config["id"],
                                title=config["title"],
                                severity=config["severity"],
                                confidence=config["confidence"],
                                description=f"{config['title']} detected",
                                line_number=i,
                                code_snippet=line.strip()[:100],
                                cwe_id=config.get("cwe_id"),
                                owasp_category=config.get("owasp_category"),
                                remediation=config["remediation"],
                            )
                        )

        return vulnerabilities

    def _is_comment(self, line: str, language: str) -> bool:
        """Check if a line is a comment."""
        stripped = line.strip()
        
        if language == "python":
            return stripped.startswith("#")
        elif language in ["javascript", "typescript", "java", "go"]:
            return stripped.startswith("//") or stripped.startswith("/*")
        
        return False
