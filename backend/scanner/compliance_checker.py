"""
Compliance checker for AI/LLM security standards.
"""
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ComplianceViolation:
    """A compliance violation."""

    control_id: str
    framework: str  # NIST_AI_RMF, OWASP_LLM, EU_AI_ACT
    title: str
    description: str
    severity: str
    recommendation: str
    evidence: Optional[str] = None


@dataclass
class ComplianceReport:
    """Compliance assessment report."""

    framework: str
    total_controls: int
    compliant: int
    non_compliant: int
    not_applicable: int
    compliance_percentage: float
    violations: List[ComplianceViolation]
    passed_controls: List[str]


class ComplianceChecker:
    """
    Checks LLM applications for compliance with security standards.

    Supported Frameworks:
    - NIST AI Risk Management Framework (AI RMF)
    - OWASP Top 10 for LLM Applications
    - EU AI Act (High-Risk AI Systems)
    """

    # NIST AI RMF Controls
    NIST_AI_RMF_CONTROLS = {
        "GOVERN-1.1": {
            "title": "Legal and regulatory requirements are understood",
            "category": "Governance",
        },
        "GOVERN-1.2": {
            "title": "Organizational risk tolerances are established",
            "category": "Governance",
        },
        "MAP-1.1": {
            "title": "Context and purpose of AI system are defined",
            "category": "Mapping",
        },
        "MAP-2.3": {
            "title": "Data access and permissions are documented",
            "category": "Mapping",
        },
        "MEASURE-2.1": {
            "title": "AI system performance is measured",
            "category": "Measurement",
        },
        "MEASURE-2.3": {
            "title": "Security vulnerabilities are identified",
            "category": "Measurement",
        },
        "MEASURE-3.1": {
            "title": "Internal system components are tested",
            "category": "Measurement",
        },
        "MANAGE-1.1": {
            "title": "Risk responses are planned",
            "category": "Management",
        },
        "MANAGE-2.1": {
            "title": "Resources for AI risks are allocated",
            "category": "Management",
        },
        "MANAGE-3.1": {
            "title": "AI risks are monitored on an ongoing basis",
            "category": "Management",
        },
    }

    # OWASP LLM Top 10
    OWASP_LLM_CONTROLS = {
        "LLM01": {
            "title": "Prompt Injection Prevention",
            "description": "Protect against malicious prompt manipulation",
        },
        "LLM02": {
            "title": "Insecure Output Handling",
            "description": "Validate and sanitize LLM outputs",
        },
        "LLM03": {
            "title": "Training Data Poisoning Prevention",
            "description": "Ensure training data integrity",
        },
        "LLM04": {
            "title": "Model Denial of Service Prevention",
            "description": "Implement rate limiting and resource controls",
        },
        "LLM05": {
            "title": "Supply Chain Vulnerabilities",
            "description": "Secure dependencies and model sources",
        },
        "LLM06": {
            "title": "Sensitive Information Disclosure Prevention",
            "description": "Prevent leakage of sensitive data",
        },
        "LLM07": {
            "title": "Insecure Plugin Design",
            "description": "Secure plugin architecture",
        },
        "LLM08": {
            "title": "Excessive Agency Prevention",
            "description": "Limit model permissions and capabilities",
        },
        "LLM09": {
            "title": "Overreliance Prevention",
            "description": "Implement human oversight mechanisms",
        },
        "LLM10": {
            "title": "Model Theft Prevention",
            "description": "Protect model intellectual property",
        },
    }

    # EU AI Act (High-Risk AI Systems Requirements)
    EU_AI_ACT_CONTROLS = {
        "ART-9": {
            "title": "Risk management system",
            "description": "Establish risk management throughout lifecycle",
        },
        "ART-10": {
            "title": "Data and data governance",
            "description": "Ensure training data quality and governance",
        },
        "ART-11": {
            "title": "Technical documentation",
            "description": "Maintain comprehensive technical documentation",
        },
        "ART-12": {
            "title": "Record-keeping",
            "description": "Enable traceability through logging",
        },
        "ART-13": {
            "title": "Transparency and user information",
            "description": "Provide clear information to users",
        },
        "ART-14": {
            "title": "Human oversight",
            "description": "Enable human intervention and monitoring",
        },
        "ART-15": {
            "title": "Accuracy, robustness and cybersecurity",
            "description": "Ensure system resilience and security",
        },
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize compliance checker.

        Args:
            config: Optional configuration
        """
        self.config = config or {}

    async def check_nist_ai_rmf_compliance(
        self, scan_results: List[Any], app_config: Dict[str, Any]
    ) -> ComplianceReport:
        """
        Check compliance with NIST AI Risk Management Framework.

        Args:
            scan_results: Results from vulnerability scans
            app_config: Application configuration

        Returns:
            Compliance report
        """
        violations = []
        passed_controls = []

        # GOVERN-1.2: Risk tolerances
        if not app_config.get("risk_management", {}).get("risk_tolerance_defined"):
            violations.append(
                ComplianceViolation(
                    control_id="GOVERN-1.2",
                    framework="NIST_AI_RMF",
                    title=self.NIST_AI_RMF_CONTROLS["GOVERN-1.2"]["title"],
                    description="Risk tolerance not documented",
                    severity="medium",
                    recommendation="Document organizational risk tolerances for AI systems",
                )
            )
        else:
            passed_controls.append("GOVERN-1.2")

        # MAP-2.3: Data access permissions
        for result in scan_results:
            if hasattr(result, "vulnerabilities"):
                access_vulns = [
                    v
                    for v in result.vulnerabilities
                    if v.owasp_id == "LLM08"
                ]
                if access_vulns:
                    violations.append(
                        ComplianceViolation(
                            control_id="MAP-2.3",
                            framework="NIST_AI_RMF",
                            title=self.NIST_AI_RMF_CONTROLS["MAP-2.3"]["title"],
                            description="Excessive permissions detected",
                            severity="high",
                            recommendation="Document and restrict data access permissions",
                            evidence=f"{len(access_vulns)} excessive agency vulnerabilities found",
                        )
                    )

        # MEASURE-2.3: Security vulnerabilities identified
        total_vulns = sum(
            result.total_vulns for result in scan_results if hasattr(result, "total_vulns")
        )
        if total_vulns > 0:
            violations.append(
                ComplianceViolation(
                    control_id="MEASURE-2.3",
                    framework="NIST_AI_RMF",
                    title=self.NIST_AI_RMF_CONTROLS["MEASURE-2.3"]["title"],
                    description=f"{total_vulns} security vulnerabilities identified",
                    severity="high" if total_vulns > 5 else "medium",
                    recommendation="Remediate identified vulnerabilities",
                    evidence=f"Total vulnerabilities: {total_vulns}",
                )
            )
        else:
            passed_controls.append("MEASURE-2.3")

        # MEASURE-3.1: Internal components tested
        if app_config.get("testing", {}).get("dynamic_testing_enabled"):
            passed_controls.append("MEASURE-3.1")
        else:
            violations.append(
                ComplianceViolation(
                    control_id="MEASURE-3.1",
                    framework="NIST_AI_RMF",
                    title=self.NIST_AI_RMF_CONTROLS["MEASURE-3.1"]["title"],
                    description="No evidence of internal component testing",
                    severity="medium",
                    recommendation="Implement dynamic testing for AI components",
                )
            )

        # MANAGE-3.1: Ongoing monitoring
        if not app_config.get("monitoring", {}).get("enabled"):
            violations.append(
                ComplianceViolation(
                    control_id="MANAGE-3.1",
                    framework="NIST_AI_RMF",
                    title=self.NIST_AI_RMF_CONTROLS["MANAGE-3.1"]["title"],
                    description="No ongoing risk monitoring configured",
                    severity="high",
                    recommendation="Enable continuous monitoring and alerting",
                )
            )
        else:
            passed_controls.append("MANAGE-3.1")

        total_controls = len(self.NIST_AI_RMF_CONTROLS)
        compliant = len(passed_controls)
        non_compliant = len(violations)
        not_applicable = total_controls - compliant - non_compliant

        compliance_pct = (compliant / total_controls) * 100

        logger.info(
            f"NIST AI RMF compliance: {compliance_pct:.1f}% ({compliant}/{total_controls})"
        )

        return ComplianceReport(
            framework="NIST AI RMF",
            total_controls=total_controls,
            compliant=compliant,
            non_compliant=non_compliant,
            not_applicable=not_applicable,
            compliance_percentage=compliance_pct,
            violations=violations,
            passed_controls=passed_controls,
        )

    async def check_owasp_llm_compliance(
        self, scan_results: List[Any]
    ) -> ComplianceReport:
        """
        Check compliance with OWASP Top 10 for LLM Applications.

        Args:
            scan_results: Results from vulnerability scans

        Returns:
            Compliance report
        """
        violations = []
        passed_controls = []

        # Aggregate vulnerabilities by OWASP category
        owasp_vulns = {}
        for result in scan_results:
            if hasattr(result, "vulnerabilities"):
                for vuln in result.vulnerabilities:
                    if vuln.owasp_id:
                        if vuln.owasp_id not in owasp_vulns:
                            owasp_vulns[vuln.owasp_id] = []
                        owasp_vulns[vuln.owasp_id].append(vuln)

        # Check each OWASP LLM category
        for owasp_id, control in self.OWASP_LLM_CONTROLS.items():
            if owasp_id in owasp_vulns:
                vulns = owasp_vulns[owasp_id]
                critical_count = sum(1 for v in vulns if v.severity == "critical")
                high_count = sum(1 for v in vulns if v.severity == "high")

                severity = "critical" if critical_count > 0 else "high" if high_count > 0 else "medium"

                violations.append(
                    ComplianceViolation(
                        control_id=owasp_id,
                        framework="OWASP_LLM",
                        title=control["title"],
                        description=f"{len(vulns)} vulnerabilities found",
                        severity=severity,
                        recommendation=control["description"],
                        evidence=f"Critical: {critical_count}, High: {high_count}",
                    )
                )
            else:
                passed_controls.append(owasp_id)

        total_controls = len(self.OWASP_LLM_CONTROLS)
        compliant = len(passed_controls)
        non_compliant = len(violations)
        not_applicable = 0

        compliance_pct = (compliant / total_controls) * 100

        logger.info(
            f"OWASP LLM compliance: {compliance_pct:.1f}% ({compliant}/{total_controls})"
        )

        return ComplianceReport(
            framework="OWASP Top 10 for LLM",
            total_controls=total_controls,
            compliant=compliant,
            non_compliant=non_compliant,
            not_applicable=not_applicable,
            compliance_percentage=compliance_pct,
            violations=violations,
            passed_controls=passed_controls,
        )

    async def check_eu_ai_act_compliance(
        self, scan_results: List[Any], app_config: Dict[str, Any]
    ) -> ComplianceReport:
        """
        Check compliance with EU AI Act (High-Risk AI Systems).

        Args:
            scan_results: Results from vulnerability scans
            app_config: Application configuration

        Returns:
            Compliance report
        """
        violations = []
        passed_controls = []

        # ART-9: Risk management system
        if not app_config.get("risk_management", {}).get("system_implemented"):
            violations.append(
                ComplianceViolation(
                    control_id="ART-9",
                    framework="EU_AI_ACT",
                    title=self.EU_AI_ACT_CONTROLS["ART-9"]["title"],
                    description="No risk management system documented",
                    severity="critical",
                    recommendation="Implement and document risk management system",
                )
            )
        else:
            passed_controls.append("ART-9")

        # ART-10: Data governance
        sensitive_vulns = []
        for result in scan_results:
            if hasattr(result, "vulnerabilities"):
                sensitive_vulns.extend(
                    [v for v in result.vulnerabilities if v.owasp_id == "LLM06"]
                )

        if sensitive_vulns:
            violations.append(
                ComplianceViolation(
                    control_id="ART-10",
                    framework="EU_AI_ACT",
                    title=self.EU_AI_ACT_CONTROLS["ART-10"]["title"],
                    description="Data governance issues detected",
                    severity="high",
                    recommendation="Implement data quality and governance controls",
                    evidence=f"{len(sensitive_vulns)} data disclosure vulnerabilities",
                )
            )
        else:
            passed_controls.append("ART-10")

        # ART-12: Record-keeping (logging)
        if not app_config.get("logging", {}).get("enabled"):
            violations.append(
                ComplianceViolation(
                    control_id="ART-12",
                    framework="EU_AI_ACT",
                    title=self.EU_AI_ACT_CONTROLS["ART-12"]["title"],
                    description="Logging not enabled for traceability",
                    severity="high",
                    recommendation="Enable comprehensive logging for AI operations",
                )
            )
        else:
            passed_controls.append("ART-12")

        # ART-13: Transparency
        if not app_config.get("transparency", {}).get("user_notification_enabled"):
            violations.append(
                ComplianceViolation(
                    control_id="ART-13",
                    framework="EU_AI_ACT",
                    title=self.EU_AI_ACT_CONTROLS["ART-13"]["title"],
                    description="No user notification about AI system",
                    severity="medium",
                    recommendation="Provide transparency about AI system to users",
                )
            )
        else:
            passed_controls.append("ART-13")

        # ART-14: Human oversight
        if not app_config.get("human_oversight", {}).get("enabled"):
            violations.append(
                ComplianceViolation(
                    control_id="ART-14",
                    framework="EU_AI_ACT",
                    title=self.EU_AI_ACT_CONTROLS["ART-14"]["title"],
                    description="No human oversight mechanism",
                    severity="critical",
                    recommendation="Implement human-in-the-loop oversight",
                )
            )
        else:
            passed_controls.append("ART-14")

        # ART-15: Cybersecurity
        critical_vulns = sum(
            result.critical for result in scan_results if hasattr(result, "critical")
        )
        if critical_vulns > 0:
            violations.append(
                ComplianceViolation(
                    control_id="ART-15",
                    framework="EU_AI_ACT",
                    title=self.EU_AI_ACT_CONTROLS["ART-15"]["title"],
                    description=f"{critical_vulns} critical security vulnerabilities",
                    severity="critical",
                    recommendation="Address all critical cybersecurity vulnerabilities",
                    evidence=f"Critical vulnerabilities: {critical_vulns}",
                )
            )
        else:
            passed_controls.append("ART-15")

        total_controls = len(self.EU_AI_ACT_CONTROLS)
        compliant = len(passed_controls)
        non_compliant = len(violations)
        not_applicable = total_controls - compliant - non_compliant

        compliance_pct = (compliant / total_controls) * 100

        logger.info(
            f"EU AI Act compliance: {compliance_pct:.1f}% ({compliant}/{total_controls})"
        )

        return ComplianceReport(
            framework="EU AI Act",
            total_controls=total_controls,
            compliant=compliant,
            non_compliant=non_compliant,
            not_applicable=not_applicable,
            compliance_percentage=compliance_pct,
            violations=violations,
            passed_controls=passed_controls,
        )

    async def run_comprehensive_compliance_check(
        self, scan_results: List[Any], app_config: Dict[str, Any]
    ) -> Dict[str, ComplianceReport]:
        """
        Run compliance checks for all supported frameworks.

        Args:
            scan_results: Results from vulnerability scans
            app_config: Application configuration

        Returns:
            Dictionary of compliance reports by framework
        """
        reports = {}

        # NIST AI RMF
        nist_report = await self.check_nist_ai_rmf_compliance(scan_results, app_config)
        reports["NIST_AI_RMF"] = nist_report

        # OWASP LLM
        owasp_report = await self.check_owasp_llm_compliance(scan_results)
        reports["OWASP_LLM"] = owasp_report

        # EU AI Act
        eu_report = await self.check_eu_ai_act_compliance(scan_results, app_config)
        reports["EU_AI_ACT"] = eu_report

        # Calculate overall compliance
        total_compliance = sum(r.compliance_percentage for r in reports.values()) / len(
            reports
        )
        logger.info(f"Overall compliance across frameworks: {total_compliance:.1f}%")

        return reports
