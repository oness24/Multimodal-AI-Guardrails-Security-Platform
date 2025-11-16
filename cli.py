#!/usr/bin/env python3
"""
AdversarialShield CLI - Command-line interface for local security testing.

Allows developers to run security scans, generate attacks, and test guardrails
locally without needing the full API server.
"""
import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# CLI version
__version__ = "0.9.0"


def print_banner():
    """Print CLI banner."""
    banner = r"""
    ___      __                           _       __   _____ __    _      __    __
   /   | ___/ /   _____  ______________ _(_)___ _/ /  / ___// /_  (_)__  / /___/ /
  / /| |/ __  / | / / _ \/ ___/ ___/ __ `/ / __ `/ /   \__ \/ __ \/ / _ \/ / __  /
 / ___ / /_/ /| |/ /  __/ /  /__  / /_/ / / /_/ / /   ___/ / / / / /  __/ / /_/ /
/_/  |_\__,_/ |___/\___/_/  /____/\__,_/_/\__,_/_/   /____/_/ /_/_/\___/_/\__,_/

    AI Security Testing Platform - CLI v{version}
    """.format(version=__version__)
    print(banner)


class AdversarialShieldCLI:
    """Main CLI class."""

    def __init__(self):
        """Initialize CLI."""
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from .adversarialshield.json."""
        config_path = Path.cwd() / ".adversarialshield.json"
        if config_path.exists():
            with open(config_path, "r") as f:
                return json.load(f)
        return {}

    def _save_config(self, config: Dict[str, Any]):
        """Save configuration to .adversarialshield.json."""
        config_path = Path.cwd() / ".adversarialshield.json"
        with open(config_path, "w") as f:
            json.dump(config, indent=2, fp=f)

    async def scan_code(self, path: str, output: Optional[str] = None, format: str = "json") -> int:
        """
        Scan code for vulnerabilities.

        Args:
            path: Path to code file or directory
            output: Output file path
            format: Output format (json, sarif, text)

        Returns:
            Exit code (0 = success, 1 = vulnerabilities found)
        """
        from backend.scanner.vulnerability_scanner import VulnerabilityScanner

        print(f"🔍 Scanning: {path}")
        scanner = VulnerabilityScanner()

        target_path = Path(path)
        if not target_path.exists():
            print(f"❌ Error: Path not found: {path}", file=sys.stderr)
            return 1

        # Scan based on type
        if target_path.is_file():
            if path.endswith(".py"):
                results = await scanner.scan_code_file(path)
            else:
                print(f"⚠️  Warning: Unsupported file type, skipping: {path}")
                results = []
        else:
            # Scan directory
            results = []
            for py_file in target_path.rglob("*.py"):
                file_results = await scanner.scan_code_file(str(py_file))
                results.extend(file_results)

        # Generate report
        report = await scanner.generate_report(results)

        # Format output
        if format == "json":
            output_data = json.dumps(report, indent=2)
        elif format == "sarif":
            output_data = self._convert_to_sarif(report)
        else:  # text
            output_data = self._format_text_report(report)

        # Write output
        if output:
            with open(output, "w") as f:
                f.write(output_data)
            print(f"✅ Report saved to: {output}")
        else:
            print(output_data)

        # Print summary
        print(f"\n📊 Summary:")
        print(f"   Total vulnerabilities: {report['total_vulnerabilities']}")
        print(f"   Critical: {report['critical_count']}")
        print(f"   High: {report['high_count']}")
        print(f"   Medium: {report['medium_count']}")
        print(f"   Low: {report['low_count']}")

        # Return exit code
        return 1 if report["critical_count"] > 0 or report["high_count"] > 0 else 0

    async def test_guardrails(
        self, prompt: str, system_prompt: Optional[str] = None, output: Optional[str] = None
    ) -> int:
        """
        Test guardrails with a prompt.

        Args:
            prompt: User prompt to test
            system_prompt: Optional system prompt
            output: Output file path

        Returns:
            Exit code (0 = safe, 1 = blocked)
        """
        from backend.guardrails.engine import GuardrailsEngine

        print(f"🛡️  Testing guardrails...")

        engine = GuardrailsEngine()

        # Create request
        request = {
            "prompt": prompt,
            "system_prompt": system_prompt or "You are a helpful assistant.",
            "metadata": {"source": "cli"},
        }

        # Validate
        result = await engine.validate_input(prompt, request)

        # Format output
        output_data = {
            "passed": result.passed,
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
        }

        if output:
            with open(output, "w") as f:
                json.dump(output_data, indent=2, fp=f)

        # Print result
        if result.passed:
            print("✅ PASSED - Prompt is safe")
        else:
            print("❌ BLOCKED - Prompt violated guardrails")
            print(f"\nViolations ({len(result.violations)}):")
            for v in result.violations:
                print(f"  - [{v.severity.value.upper()}] {v.detector_name}: {v.message}")

        print(f"\nRisk Score: {result.risk_score:.2f}/10")

        return 0 if result.passed else 1

    async def generate_attack(
        self, technique: str, objective: Optional[str] = None, output: Optional[str] = None
    ) -> int:
        """
        Generate adversarial attack.

        Args:
            technique: Attack technique
            objective: Attack objective
            output: Output file path

        Returns:
            Exit code
        """
        from backend.redteam.prompt_injection import PromptInjectionGenerator

        print(f"⚔️  Generating {technique} attack...")

        generator = PromptInjectionGenerator()

        # Generate attack
        payload = await generator.generate_attack(
            technique=technique,
            target_context={"objective": objective} if objective else {},
        )

        if not payload:
            print("❌ Failed to generate attack", file=sys.stderr)
            return 1

        # Output
        output_data = {"technique": technique, "payload": payload, "objective": objective}

        if output:
            with open(output, "w") as f:
                json.dump(output_data, indent=2, fp=f)
            print(f"✅ Attack saved to: {output}")
        else:
            print(f"\n📝 Generated Attack:\n{payload}")

        return 0

    async def analyze_threat_model(self, config_file: str, output: Optional[str] = None) -> int:
        """
        Analyze application threat model.

        Args:
            config_file: Path to application configuration JSON
            output: Output file path

        Returns:
            Exit code
        """
        from backend.threat_intel.attack_surface_mapper import AttackSurfaceMapper
        from backend.threat_intel.stride_modeler import STRIDEModeler
        from backend.threat_intel.owasp_threat_modeler import OWASPThreatModeler

        print(f"🔍 Analyzing threat model from: {config_file}")

        # Load config
        with open(config_file, "r") as f:
            app_config = json.load(f)

        # Attack surface analysis
        mapper = AttackSurfaceMapper()
        attack_surface = await mapper.analyze_attack_surface(app_config)

        # STRIDE analysis
        stride = STRIDEModeler()
        stride_model = await stride.analyze_attack_surface(attack_surface)

        # OWASP analysis
        owasp = OWASPThreatModeler()
        owasp_model = await owasp.analyze_attack_surface(attack_surface)

        # Generate report
        report = {
            "application_name": app_config.get("app_name", "Unknown"),
            "attack_surface": {
                "total_components": attack_surface.total_components,
                "high_risk_components": attack_surface.high_risk_components,
                "overall_risk_score": attack_surface.overall_risk_score,
            },
            "stride": {
                "total_threats": stride_model.total_threats,
                "critical": stride_model.critical_threats,
                "high": stride_model.high_threats,
            },
            "owasp": {
                "total_threats": owasp_model.total_threats,
                "critical": owasp_model.critical_threats,
                "categories_found": owasp_model.owasp_categories_found,
            },
        }

        # Output
        if output:
            with open(output, "w") as f:
                json.dump(report, indent=2, fp=f)
            print(f"✅ Threat model saved to: {output}")
        else:
            print(json.dumps(report, indent=2))

        # Print summary
        print(f"\n📊 Threat Model Summary:")
        print(f"   Overall Risk: {attack_surface.overall_risk_score:.2f}/10")
        print(f"   STRIDE Threats: {stride_model.total_threats} ({stride_model.critical_threats} critical)")
        print(f"   OWASP Threats: {owasp_model.total_threats} ({owasp_model.critical_threats} critical)")

        return 0

    async def run_compliance_check(self, framework: str, config_file: str, output: Optional[str] = None) -> int:
        """
        Run compliance check.

        Args:
            framework: Framework to check (nist, owasp, eu-ai-act)
            config_file: Path to application configuration
            output: Output file path

        Returns:
            Exit code
        """
        from backend.scanner.compliance_checker import ComplianceChecker

        print(f"📋 Running {framework.upper()} compliance check...")

        checker = ComplianceChecker()

        # Load config
        with open(config_file, "r") as f:
            app_config = json.load(f)

        # Run compliance check
        if framework == "nist":
            report = await checker.check_nist_ai_rmf(app_config)
        elif framework == "owasp":
            report = await checker.check_owasp_llm(app_config)
        elif framework == "eu-ai-act":
            report = await checker.check_eu_ai_act(app_config)
        else:
            print(f"❌ Unknown framework: {framework}", file=sys.stderr)
            return 1

        # Output
        output_data = {
            "framework": report.framework,
            "compliance_percentage": report.compliance_percentage,
            "passed_controls": report.passed_controls,
            "failed_controls": report.failed_controls,
            "violations": [
                {"control_id": v.control_id, "title": v.control_title, "severity": v.severity}
                for v in report.violations
            ],
        }

        if output:
            with open(output, "w") as f:
                json.dump(output_data, indent=2, fp=f)
            print(f"✅ Compliance report saved to: {output}")
        else:
            print(json.dumps(output_data, indent=2))

        # Print summary
        print(f"\n📊 Compliance Summary:")
        print(f"   Framework: {framework.upper()}")
        print(f"   Compliance: {report.compliance_percentage:.1f}%")
        print(f"   Passed: {report.passed_controls}/{report.total_controls}")
        print(f"   Failed: {report.failed_controls}/{report.total_controls}")

        return 1 if report.compliance_percentage < 100 else 0

    def _convert_to_sarif(self, report: Dict[str, Any]) -> str:
        """Convert report to SARIF format."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AdversarialShield",
                            "version": __version__,
                            "informationUri": "https://github.com/adversarialshield/adversarialshield",
                        }
                    },
                    "results": [
                        {
                            "ruleId": vuln["owasp_category"],
                            "level": self._severity_to_sarif_level(vuln["severity"]),
                            "message": {"text": vuln["description"]},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": vuln.get("file_path", "unknown")},
                                        "region": {"startLine": vuln.get("line_number", 1)},
                                    }
                                }
                            ],
                        }
                        for vuln in report.get("vulnerabilities", [])
                    ],
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def _severity_to_sarif_level(self, severity: str) -> str:
        """Convert severity to SARIF level."""
        mapping = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
        return mapping.get(severity, "warning")

    def _format_text_report(self, report: Dict[str, Any]) -> str:
        """Format report as text."""
        lines = [
            "=" * 80,
            "AdversarialShield Security Scan Report",
            "=" * 80,
            "",
            f"Total Vulnerabilities: {report['total_vulnerabilities']}",
            f"Critical: {report['critical_count']}",
            f"High: {report['high_count']}",
            f"Medium: {report['medium_count']}",
            f"Low: {report['low_count']}",
            "",
            "=" * 80,
            "Vulnerabilities:",
            "=" * 80,
            "",
        ]

        for vuln in report.get("vulnerabilities", []):
            lines.extend(
                [
                    f"[{vuln['severity'].upper()}] {vuln['owasp_category']}: {vuln['title']}",
                    f"File: {vuln.get('file_path', 'N/A')}",
                    f"Line: {vuln.get('line_number', 'N/A')}",
                    f"Description: {vuln['description']}",
                    f"Mitigation: {vuln['mitigation']}",
                    "",
                ]
            )

        return "\n".join(lines)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="AdversarialShield CLI - AI Security Testing Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan code for vulnerabilities")
    scan_parser.add_argument("path", help="Path to file or directory to scan")
    scan_parser.add_argument("-o", "--output", help="Output file path")
    scan_parser.add_argument(
        "-f", "--format", choices=["json", "sarif", "text"], default="json", help="Output format"
    )

    # Guardrails command
    guard_parser = subparsers.add_parser("guard", help="Test guardrails")
    guard_parser.add_argument("prompt", help="Prompt to test")
    guard_parser.add_argument("-s", "--system-prompt", help="System prompt")
    guard_parser.add_argument("-o", "--output", help="Output file path")

    # Attack command
    attack_parser = subparsers.add_parser("attack", help="Generate adversarial attack")
    attack_parser.add_argument("technique", help="Attack technique")
    attack_parser.add_argument("--objective", help="Attack objective")
    attack_parser.add_argument("-o", "--output", help="Output file path")

    # Threat model command
    threat_parser = subparsers.add_parser("threat-model", help="Analyze threat model")
    threat_parser.add_argument("config", help="Path to application config JSON")
    threat_parser.add_argument("-o", "--output", help="Output file path")

    # Compliance command
    compliance_parser = subparsers.add_parser("compliance", help="Run compliance check")
    compliance_parser.add_argument(
        "framework", choices=["nist", "owasp", "eu-ai-act"], help="Compliance framework"
    )
    compliance_parser.add_argument("config", help="Path to application config JSON")
    compliance_parser.add_argument("-o", "--output", help="Output file path")

    # Init command
    init_parser = subparsers.add_parser("init", help="Initialize configuration")

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        return 0

    # Initialize CLI
    cli = AdversarialShieldCLI()

    # Run command
    if args.command == "scan":
        return asyncio.run(cli.scan_code(args.path, args.output, args.format))
    elif args.command == "guard":
        return asyncio.run(cli.test_guardrails(args.prompt, args.system_prompt, args.output))
    elif args.command == "attack":
        return asyncio.run(cli.generate_attack(args.technique, args.objective, args.output))
    elif args.command == "threat-model":
        return asyncio.run(cli.analyze_threat_model(args.config, args.output))
    elif args.command == "compliance":
        return asyncio.run(cli.run_compliance_check(args.framework, args.config, args.output))
    elif args.command == "init":
        # Create default config
        config = {
            "project_name": "my-llm-app",
            "scan_paths": ["./"],
            "exclude_paths": ["./venv", "./node_modules", "./.git"],
            "guardrails": {"enabled": True, "block_on_critical": True},
        }
        cli._save_config(config)
        print("✅ Created .adversarialshield.json")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
