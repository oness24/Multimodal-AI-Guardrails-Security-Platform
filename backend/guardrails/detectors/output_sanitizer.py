"""
Output Sanitizer for detecting dangerous content in LLM outputs.
Covers OWASP LLM02: Insecure Output Handling.
"""
import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple


class OutputThreatType(str, Enum):
    """Types of output threats."""
    CODE_INJECTION = "code_injection"
    SCRIPT_INJECTION = "script_injection"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    MARKDOWN_INJECTION = "markdown_injection"
    LINK_INJECTION = "link_injection"
    HTML_INJECTION = "html_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF_ATTEMPT = "ssrf_attempt"


@dataclass
class OutputThreat:
    """Detected output threat."""
    threat_type: OutputThreatType
    severity: str
    confidence: float
    description: str
    matched_content: str
    start_pos: int
    end_pos: int
    remediation: Optional[str] = None


class OutputSanitizer:
    """
    Detects and sanitizes dangerous content in LLM outputs.
    Prevents code injection, XSS, and other output-based attacks.
    """

    def __init__(self):
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile regex patterns for threat detection."""
        
        # Code injection patterns
        self.code_injection_patterns = [
            # Python dangerous functions
            (r'\bexec\s*\([^)]+\)', "Python exec() call", "high"),
            (r'\beval\s*\([^)]+\)', "Python eval() call", "high"),
            (r'\bcompile\s*\([^)]+\)', "Python compile() call", "medium"),
            (r'__import__\s*\([^)]+\)', "Python __import__() call", "high"),
            (r'\bos\.system\s*\([^)]+\)', "OS system call", "critical"),
            (r'\bsubprocess\.(run|call|Popen)\s*\([^)]+\)', "Subprocess execution", "critical"),
            (r'\bopen\s*\([^)]*[\'"]w[\'"][^)]*\)', "File write operation", "medium"),
            
            # JavaScript dangerous patterns
            (r'\bFunction\s*\([^)]+\)', "JavaScript Function constructor", "high"),
            (r'new\s+Function\s*\([^)]+\)', "JavaScript new Function()", "high"),
            (r'setTimeout\s*\(\s*[\'"][^\'"]+[\'"]', "setTimeout with string", "medium"),
            (r'setInterval\s*\(\s*[\'"][^\'"]+[\'"]', "setInterval with string", "medium"),
        ]
        
        # Script injection (XSS) patterns
        self.script_injection_patterns = [
            (r'<script[^>]*>.*?</script>', "Script tag", "critical"),
            (r'<script[^>]*>', "Unclosed script tag", "critical"),
            (r'javascript:', "JavaScript protocol", "high"),
            (r'on\w+\s*=\s*[\'"][^\'"]+[\'"]', "Event handler attribute", "high"),
            (r'<iframe[^>]*>', "Iframe tag", "high"),
            (r'<embed[^>]*>', "Embed tag", "medium"),
            (r'<object[^>]*>', "Object tag", "medium"),
            (r'<svg[^>]*onload', "SVG with onload", "high"),
            (r'<img[^>]*onerror', "Image with onerror", "high"),
            (r'data:text/html', "Data URI with HTML", "high"),
        ]
        
        # SQL injection patterns
        self.sql_injection_patterns = [
            (r"('\s*OR\s+'1'\s*=\s*'1)", "SQL OR injection", "critical"),
            (r'(;\s*DROP\s+TABLE)', "SQL DROP TABLE", "critical"),
            (r'(;\s*DELETE\s+FROM)', "SQL DELETE statement", "critical"),
            (r'(;\s*INSERT\s+INTO)', "SQL INSERT statement", "high"),
            (r'(;\s*UPDATE\s+\w+\s+SET)', "SQL UPDATE statement", "high"),
            (r'(UNION\s+SELECT)', "SQL UNION SELECT", "critical"),
            (r'(--\s*$)', "SQL comment terminator", "medium"),
            (r"(;\s*EXEC\s+)", "SQL EXEC statement", "critical"),
        ]
        
        # Command injection patterns
        self.command_injection_patterns = [
            (r';\s*(rm|del|format|shutdown|reboot)\b', "Destructive command", "critical"),
            (r'\|\s*(bash|sh|cmd|powershell)', "Pipe to shell", "critical"),
            (r'`[^`]+`', "Backtick command substitution", "high"),
            (r'\$\([^)]+\)', "Command substitution", "high"),
            (r'&&\s*(wget|curl|nc|netcat)', "Chained network command", "critical"),
            (r'\|\|\s*(wget|curl|nc|netcat)', "Conditional network command", "high"),
            (r'>\s*/etc/', "Write to /etc/", "critical"),
            (r'>\s*~/', "Write to home directory", "medium"),
        ]
        
        # Markdown injection patterns
        self.markdown_injection_patterns = [
            (r'\[([^\]]+)\]\(javascript:[^)]+\)', "Markdown JS link", "high"),
            (r'\[([^\]]+)\]\(data:[^)]+\)', "Markdown data URI", "high"),
            (r'!\[([^\]]*)\]\([^)]*\s+[\'"]onerror', "Markdown image with onerror", "high"),
            (r'\[([^\]]+)\]\(vbscript:[^)]+\)', "Markdown VBScript link", "high"),
        ]
        
        # Suspicious link patterns
        self.link_injection_patterns = [
            (r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "IP address URL", "medium"),
            (r'https?://[^/]*@', "URL with credentials", "high"),
            (r'file://', "File protocol URL", "high"),
            (r'ftp://', "FTP protocol URL", "medium"),
            (r'https?://localhost', "Localhost URL", "medium"),
            (r'https?://127\.0\.0\.1', "Loopback URL", "medium"),
            (r'https?://0\.0\.0\.0', "Any interface URL", "high"),
            (r'https?://[^/]*\.onion', "Tor onion URL", "medium"),
            (r'gopher://', "Gopher protocol", "high"),
        ]
        
        # Path traversal patterns
        self.path_traversal_patterns = [
            (r'\.\./', "Directory traversal", "high"),
            (r'\.\.\\', "Windows directory traversal", "high"),
            (r'%2e%2e%2f', "Encoded traversal", "high"),
            (r'%252e%252e%252f', "Double encoded traversal", "critical"),
            (r'/etc/passwd', "Unix passwd access", "critical"),
            (r'/etc/shadow', "Unix shadow access", "critical"),
            (r'C:\\Windows\\', "Windows system path", "high"),
            (r'\\\\[^\\]+\\', "UNC path", "medium"),
        ]
        
        # SSRF patterns
        self.ssrf_patterns = [
            (r'http://169\.254\.169\.254', "AWS metadata endpoint", "critical"),
            (r'http://metadata\.google\.internal', "GCP metadata endpoint", "critical"),
            (r'http://100\.100\.100\.200', "Alibaba metadata endpoint", "critical"),
            (r'http://\[::1\]', "IPv6 localhost", "high"),
            (r'http://\[0:0:0:0:0:0:0:1\]', "IPv6 localhost full", "high"),
            (r'http://0x7f000001', "Hex encoded localhost", "high"),
            (r'http://2130706433', "Decimal encoded localhost", "high"),
        ]

    async def detect(self, text: str) -> List[OutputThreat]:
        """
        Detect threats in output text.
        
        Args:
            text: Output text to analyze
            
        Returns:
            List of detected threats
        """
        threats: List[OutputThreat] = []
        
        # Run all detection patterns
        pattern_groups = [
            (self.code_injection_patterns, OutputThreatType.CODE_INJECTION),
            (self.script_injection_patterns, OutputThreatType.SCRIPT_INJECTION),
            (self.sql_injection_patterns, OutputThreatType.SQL_INJECTION),
            (self.command_injection_patterns, OutputThreatType.COMMAND_INJECTION),
            (self.markdown_injection_patterns, OutputThreatType.MARKDOWN_INJECTION),
            (self.link_injection_patterns, OutputThreatType.LINK_INJECTION),
            (self.path_traversal_patterns, OutputThreatType.PATH_TRAVERSAL),
            (self.ssrf_patterns, OutputThreatType.SSRF_ATTEMPT),
        ]
        
        for patterns, threat_type in pattern_groups:
            for pattern, description, severity in patterns:
                for match in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
                    threats.append(OutputThreat(
                        threat_type=threat_type,
                        severity=severity,
                        confidence=0.85,
                        description=description,
                        matched_content=match.group(0)[:100],  # Limit length
                        start_pos=match.start(),
                        end_pos=match.end(),
                        remediation=self._get_remediation(threat_type),
                    ))
        
        return threats

    def _get_remediation(self, threat_type: OutputThreatType) -> str:
        """Get remediation advice for a threat type."""
        remediations = {
            OutputThreatType.CODE_INJECTION: "Escape or sandbox code execution. Never pass LLM output directly to exec/eval.",
            OutputThreatType.SCRIPT_INJECTION: "HTML-encode output before rendering. Use Content-Security-Policy headers.",
            OutputThreatType.SQL_INJECTION: "Use parameterized queries. Never interpolate LLM output into SQL.",
            OutputThreatType.COMMAND_INJECTION: "Avoid shell execution. Use subprocess with shell=False and explicit args.",
            OutputThreatType.MARKDOWN_INJECTION: "Sanitize markdown links. Whitelist allowed URL protocols.",
            OutputThreatType.LINK_INJECTION: "Validate URLs against allowlist. Check for private IP ranges.",
            OutputThreatType.PATH_TRAVERSAL: "Use os.path.basename() or Path.resolve() with strict validation.",
            OutputThreatType.SSRF_ATTEMPT: "Validate URLs server-side. Block internal/metadata IP ranges.",
        }
        return remediations.get(threat_type, "Review and sanitize output before use.")

    async def sanitize(
        self,
        text: str,
        remove_threats: bool = True,
        escape_html: bool = True,
    ) -> Tuple[str, List[OutputThreat]]:
        """
        Sanitize output text by removing or escaping threats.
        
        Args:
            text: Text to sanitize
            remove_threats: Whether to remove detected threats
            escape_html: Whether to escape HTML entities
            
        Returns:
            Tuple of (sanitized_text, detected_threats)
        """
        threats = await self.detect(text)
        sanitized = text
        
        if remove_threats and threats:
            # Sort by position descending to maintain indices
            sorted_threats = sorted(threats, key=lambda t: t.start_pos, reverse=True)
            
            for threat in sorted_threats:
                # Replace threat with safe placeholder
                placeholder = f"[BLOCKED:{threat.threat_type.value}]"
                sanitized = sanitized[:threat.start_pos] + placeholder + sanitized[threat.end_pos:]
        
        if escape_html:
            # Escape remaining HTML entities
            html_escapes = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#x27;',
            }
            for char, escape in html_escapes.items():
                # Don't escape our placeholders
                parts = sanitized.split('[BLOCKED:')
                for i, part in enumerate(parts):
                    if i == 0:
                        parts[i] = part.replace(char, escape)
                    else:
                        # Find the end of the placeholder
                        end_bracket = part.find(']')
                        if end_bracket != -1:
                            parts[i] = part[:end_bracket+1] + part[end_bracket+1:].replace(char, escape)
                sanitized = '[BLOCKED:'.join(parts)
        
        return sanitized, threats

    def is_safe(self, text: str) -> bool:
        """Quick check if output is safe (no threats detected)."""
        for patterns, _ in [
            (self.code_injection_patterns, None),
            (self.script_injection_patterns, None),
            (self.sql_injection_patterns, None),
            (self.command_injection_patterns, None),
        ]:
            for pattern, _, severity in patterns:
                if severity in ("critical", "high"):
                    if re.search(pattern, text, re.IGNORECASE):
                        return False
        return True
