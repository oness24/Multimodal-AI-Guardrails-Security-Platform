"""
OWASP Top 10 for LLM Applications threat modeling.

Provides threat analysis and mitigation guidance based on OWASP Top 10 for LLMs.
"""
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from backend.threat_intel.attack_surface_mapper import AttackSurface, Component, ComponentType

logger = logging.getLogger(__name__)


class OWASPCategory(str, Enum):
    """OWASP Top 10 for LLM Applications categories."""

    LLM01_PROMPT_INJECTION = "LLM01"
    LLM02_INSECURE_OUTPUT_HANDLING = "LLM02"
    LLM03_TRAINING_DATA_POISONING = "LLM03"
    LLM04_MODEL_DENIAL_OF_SERVICE = "LLM04"
    LLM05_SUPPLY_CHAIN_VULNERABILITIES = "LLM05"
    LLM06_SENSITIVE_INFORMATION_DISCLOSURE = "LLM06"
    LLM07_INSECURE_PLUGIN_DESIGN = "LLM07"
    LLM08_EXCESSIVE_AGENCY = "LLM08"
    LLM09_OVERRELIANCE = "LLM09"
    LLM10_MODEL_THEFT = "LLM10"


@dataclass
class OWASPThreat:
    """OWASP LLM threat."""

    threat_id: str = field(default_factory=lambda: str(uuid4()))
    category: OWASPCategory = OWASPCategory.LLM01_PROMPT_INJECTION
    title: str = ""
    description: str = ""
    severity: str = "medium"  # critical, high, medium, low

    # Affected components
    affected_components: List[str] = field(default_factory=list)

    # Attack scenarios
    attack_scenarios: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    impact: List[str] = field(default_factory=list)

    # Mitigations
    prevention_measures: List[str] = field(default_factory=list)
    detection_strategies: List[str] = field(default_factory=list)
    example_attack_scenarios: List[str] = field(default_factory=list)

    # References
    mitre_atlas_techniques: List[str] = field(default_factory=list)
    cwe_mapping: List[str] = field(default_factory=list)


@dataclass
class OWASPThreatModel:
    """OWASP threat model for LLM application."""

    model_id: str = field(default_factory=lambda: str(uuid4()))
    application_name: str = ""
    threats: List[OWASPThreat] = field(default_factory=list)

    # Statistics
    total_threats: int = 0
    critical_threats: int = 0
    high_threats: int = 0

    # Coverage
    owasp_categories_found: List[str] = field(default_factory=list)
    coverage_percentage: float = 0.0


class OWASPThreatModeler:
    """
    OWASP Top 10 for LLM Applications threat modeler.

    Analyzes attack surface for OWASP LLM vulnerabilities and provides
    detailed mitigation guidance.
    """

    # OWASP Top 10 for LLM Applications detailed definitions
    OWASP_DEFINITIONS = {
        OWASPCategory.LLM01_PROMPT_INJECTION: {
            "name": "Prompt Injection",
            "description": "Manipulating LLM via crafted inputs can lead to unauthorized access, "
            "data breaches, and compromised decision-making.",
            "severity": "critical",
            "common_examples": [
                "Bypassing filters or manipulation via crafted prompts",
                "Direct injection: Overwriting system prompts",
                "Indirect injection: Manipulating inputs from external sources",
            ],
            "prevention": [
                "Enforce privilege control on LLM access to backend systems",
                "Separate user content from LLM prompts",
                "Establish trust boundaries between LLM, external sources, and extensible functionality",
                "Manually approve any privileged operations",
                "Implement robust input validation and sanitization",
            ],
            "detection": [
                "Monitor for unusual prompt patterns",
                "Implement output anomaly detection",
                "Track privilege escalation attempts",
                "Log all LLM interactions for audit",
            ],
            "mitre_atlas": ["AML.T0051.000", "AML.T0054.000"],
            "cwe": ["CWE-77", "CWE-94"],
        },
        OWASPCategory.LLM02_INSECURE_OUTPUT_HANDLING: {
            "name": "Insecure Output Handling",
            "description": "Neglecting to validate LLM outputs may lead to downstream security "
            "exploits, including code execution that compromises systems and exposes data.",
            "severity": "high",
            "common_examples": [
                "LLM output directly enters privileged functions or backend systems",
                "XSS via LLM output rendered in browser",
                "SSRF via LLM-generated URLs",
                "SQL injection via LLM-generated queries",
            ],
            "prevention": [
                "Treat the model as any other user and apply proper input validation",
                "Encode model output back to users to mitigate XSS/CSRF",
                "Adhere to OWASP ASVS guidelines for input validation",
                "Use allowlisting and proper encoding for LLM outputs",
            ],
            "detection": [
                "Monitor for malicious patterns in outputs",
                "Implement output content filtering",
                "Detect injection attempts in downstream systems",
            ],
            "mitre_atlas": ["AML.T0048.000"],
            "cwe": ["CWE-79", "CWE-89", "CWE-94"],
        },
        OWASPCategory.LLM03_TRAINING_DATA_POISONING: {
            "name": "Training Data Poisoning",
            "description": "Tampered training data can impair LLM models leading to responses that "
            "compromise security, accuracy, or ethical behavior.",
            "severity": "high",
            "common_examples": [
                "Malicious actor injects falsified information",
                "Victim model trained on poisoned data",
                "Backdoor triggers embedded in data",
            ],
            "prevention": [
                "Verify supply chain of training data",
                "Verify legitimacy of data sources",
                "Use SBOM (Software Bill of Materials) for data provenance",
                "Implement sandboxing to prevent poisoned data impact",
                "Use adversarial robustness techniques",
            ],
            "detection": [
                "Monitor model behavior for anomalies",
                "Implement model integrity checks",
                "Track training data provenance",
                "Detect distribution shifts",
            ],
            "mitre_atlas": ["AML.T0018.000", "AML.T0020.000"],
            "cwe": ["CWE-345"],
        },
        OWASPCategory.LLM04_MODEL_DENIAL_OF_SERVICE: {
            "name": "Model Denial of Service",
            "description": "Overloading LLMs with resource-heavy operations can cause service "
            "disruptions and increased costs.",
            "severity": "high",
            "common_examples": [
                "Sending high-volume queries",
                "Unusually resource-consuming queries",
                "Continuous input overflow",
                "Recurring long inputs",
            ],
            "prevention": [
                "Implement rate limiting for requests",
                "Enforce API rate limits to restrict requests per user",
                "Limit resource use per request",
                "Set maximum token limits",
                "Implement request throttling and queueing",
            ],
            "detection": [
                "Monitor resource usage patterns",
                "Track request frequencies",
                "Detect unusual query lengths",
                "Alert on cost anomalies",
            ],
            "mitre_atlas": ["AML.T0029.000"],
            "cwe": ["CWE-400", "CWE-770"],
        },
        OWASPCategory.LLM05_SUPPLY_CHAIN_VULNERABILITIES: {
            "name": "Supply Chain Vulnerabilities",
            "description": "LLM application lifecycle can be compromised by vulnerable components, "
            "services, or datasets, leading to security breaches.",
            "severity": "high",
            "common_examples": [
                "Vulnerable third-party packages",
                "Outdated components",
                "Compromised pre-trained models",
                "Poisoned datasets",
            ],
            "prevention": [
                "Vet data sources and suppliers",
                "Use only reputable plugins and suppliers",
                "Use SBOM to track components",
                "Implement vulnerability scanning",
                "Maintain up-to-date dependencies",
                "Verify model and data signatures",
            ],
            "detection": [
                "Regular dependency audits",
                "Monitor for known vulnerabilities",
                "Track component provenance",
                "Implement integrity checks",
            ],
            "mitre_atlas": ["AML.T0010.000"],
            "cwe": ["CWE-1395", "CWE-829"],
        },
        OWASPCategory.LLM06_SENSITIVE_INFORMATION_DISCLOSURE: {
            "name": "Sensitive Information Disclosure",
            "description": "LLMs may inadvertently reveal confidential data in responses, leading "
            "to unauthorized data access, privacy violations, and security breaches.",
            "severity": "critical",
            "common_examples": [
                "Leaking PII, financial, health information",
                "Exposure of proprietary algorithms or data",
                "Unintentional disclosure of confidential details",
                "Training data memorization",
            ],
            "prevention": [
                "Integrate data sanitization techniques",
                "Implement techniques to detect and filter PII",
                "Use differential privacy in training",
                "Restrict LLM access to sensitive databases",
                "Implement robust output filtering",
                "Apply principle of least privilege",
            ],
            "detection": [
                "PII detection in outputs",
                "Pattern matching for sensitive data",
                "Anomaly detection in responses",
                "DLP (Data Loss Prevention) integration",
            ],
            "mitre_atlas": ["AML.T0024.000", "AML.T0028.000", "AML.T0031.001"],
            "cwe": ["CWE-200", "CWE-359"],
        },
        OWASPCategory.LLM07_INSECURE_PLUGIN_DESIGN: {
            "name": "Insecure Plugin Design",
            "description": "LLM plugins processing untrusted inputs with insufficient access control "
            "can lead to remote code execution, data exfiltration, or privilege escalation.",
            "severity": "high",
            "common_examples": [
                "Plugin accepts all parameters without validation",
                "Blind trust of LLM-generated content",
                "Inadequate access controls",
                "Overly permissive functionality",
            ],
            "prevention": [
                "Enforce strict input validation",
                "Implement least privilege access control",
                "Use manual approval for sensitive actions",
                "Avoid free-form text inputs where possible",
                "Apply OWASP API Security Top 10",
                "Implement plugin sandboxing",
            ],
            "detection": [
                "Monitor plugin executions",
                "Track privilege usage",
                "Detect anomalous plugin behavior",
                "Log all plugin actions",
            ],
            "mitre_atlas": ["AML.T0052.000"],
            "cwe": ["CWE-20", "CWE-77"],
        },
        OWASPCategory.LLM08_EXCESSIVE_AGENCY: {
            "name": "Excessive Agency",
            "description": "LLM-based system with excessive functionality, permissions, or autonomy "
            "can lead to unintended actions with significant consequences.",
            "severity": "high",
            "common_examples": [
                "Excessive permissions to perform state-changing operations",
                "Over-reliance on LLM for decision-making",
                "Lack of validation for LLM outputs",
                "Autonomous actions without human oversight",
            ],
            "prevention": [
                "Limit plugins/tools to minimum necessary functions",
                "Track user authorization and scope",
                "Implement human-in-the-loop for high-impact actions",
                "Require explicit user confirmation for sensitive operations",
                "Implement comprehensive logging",
            ],
            "detection": [
                "Monitor for unauthorized actions",
                "Track state-changing operations",
                "Detect privilege escalations",
                "Alert on high-risk actions",
            ],
            "mitre_atlas": ["AML.T0048.000"],
            "cwe": ["CWE-269"],
        },
        OWASPCategory.LLM09_OVERRELIANCE: {
            "name": "Overreliance",
            "description": "Systems or users over-relying on LLMs without oversight may face "
            "misinformation, miscommunication, legal issues, and security vulnerabilities.",
            "severity": "medium",
            "common_examples": [
                "Accepting LLM output without verification",
                "LLM hallucinations treated as fact",
                "Security decisions based solely on LLM",
                "Lack of human oversight",
            ],
            "prevention": [
                "Regularly monitor and review LLM outputs",
                "Implement cross-verification mechanisms",
                "Use LLMs as advisory tools, not sole decision-makers",
                "Communicate LLM limitations to users",
                "Implement fact-checking workflows",
            ],
            "detection": [
                "Track decision accuracy",
                "Monitor for hallucinations",
                "Implement quality checks",
                "User feedback collection",
            ],
            "mitre_atlas": [],
            "cwe": ["CWE-1039"],
        },
        OWASPCategory.LLM10_MODEL_THEFT: {
            "name": "Model Theft",
            "description": "Unauthorized access or copying of proprietary LLM models can lead to "
            "economic loss, competitive disadvantage, and security vulnerabilities.",
            "severity": "medium",
            "common_examples": [
                "Model extraction via API queries",
                "Direct access to model files",
                "Side-channel attacks",
                "Insider threats",
            ],
            "prevention": [
                "Implement strong access controls",
                "Restrict physical and logical access to models",
                "Use model watermarking",
                "Monitor access patterns",
                "Implement API rate limiting",
                "Use query complexity restrictions",
            ],
            "detection": [
                "Detect unusual query patterns",
                "Monitor model extraction attempts",
                "Track access anomalies",
                "Alert on bulk queries",
            ],
            "mitre_atlas": ["AML.T0025.000", "AML.T0002.000"],
            "cwe": ["CWE-200"],
        },
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize OWASP threat modeler.

        Args:
            config: Optional configuration
        """
        self.config = config or {}
        self.threats: List[OWASPThreat] = []

    async def analyze_attack_surface(self, attack_surface: AttackSurface) -> OWASPThreatModel:
        """
        Analyze attack surface for OWASP LLM vulnerabilities.

        Args:
            attack_surface: Attack surface analysis

        Returns:
            OWASP threat model
        """
        self.threats = []

        # Analyze each OWASP category
        await self._check_prompt_injection(attack_surface)
        await self._check_insecure_output_handling(attack_surface)
        await self._check_training_data_poisoning(attack_surface)
        await self._check_model_dos(attack_surface)
        await self._check_supply_chain(attack_surface)
        await self._check_sensitive_info_disclosure(attack_surface)
        await self._check_insecure_plugins(attack_surface)
        await self._check_excessive_agency(attack_surface)
        await self._check_overreliance(attack_surface)
        await self._check_model_theft(attack_surface)

        # Build threat model
        threat_model = self._build_threat_model(attack_surface.application_name)

        logger.info(
            f"OWASP analysis complete: {threat_model.total_threats} threats found across "
            f"{len(threat_model.owasp_categories_found)} categories"
        )

        return threat_model

    async def _check_prompt_injection(self, attack_surface: AttackSurface):
        """Check for LLM01: Prompt Injection vulnerabilities."""
        category = OWASPCategory.LLM01_PROMPT_INJECTION
        definition = self.OWASP_DEFINITIONS[category]

        for component in attack_surface.components.values():
            if component.handles_user_input and not component.input_validated:
                self.threats.append(
                    OWASPThreat(
                        category=category,
                        title=f"{definition['name']} in {component.name}",
                        description=f"Component accepts user input without validation, vulnerable to prompt injection attacks",
                        severity=definition["severity"],
                        affected_components=[component.component_id],
                        attack_scenarios=definition["common_examples"],
                        prerequisites=["User input capability", "Lack of input validation"],
                        impact=[
                            "Unauthorized data access",
                            "System prompt bypass",
                            "Data exfiltration",
                            "Privilege escalation",
                        ],
                        prevention_measures=definition["prevention"],
                        detection_strategies=definition["detection"],
                        mitre_atlas_techniques=definition["mitre_atlas"],
                        cwe_mapping=definition["cwe"],
                    )
                )

    async def _check_insecure_output_handling(self, attack_surface: AttackSurface):
        """Check for LLM02: Insecure Output Handling vulnerabilities."""
        category = OWASPCategory.LLM02_INSECURE_OUTPUT_HANDLING
        definition = self.OWASP_DEFINITIONS[category]

        for component in attack_surface.components.values():
            if component.component_type == ComponentType.LLM_MODEL and not component.output_sanitized:
                self.threats.append(
                    OWASPThreat(
                        category=category,
                        title=f"{definition['name']} in {component.name}",
                        description="LLM outputs are not sanitized before use, risking injection attacks",
                        severity=definition["severity"],
                        affected_components=[component.component_id],
                        attack_scenarios=definition["common_examples"],
                        prerequisites=["LLM output used in downstream systems"],
                        impact=["XSS attacks", "SQL injection", "SSRF", "Code execution"],
                        prevention_measures=definition["prevention"],
                        detection_strategies=definition["detection"],
                        mitre_atlas_techniques=definition["mitre_atlas"],
                        cwe_mapping=definition["cwe"],
                    )
                )

    async def _check_training_data_poisoning(self, attack_surface: AttackSurface):
        """Check for LLM03: Training Data Poisoning vulnerabilities."""
        category = OWASPCategory.LLM03_TRAINING_DATA_POISONING
        definition = self.OWASP_DEFINITIONS[category]

        for component in attack_surface.components.values():
            if component.component_type == ComponentType.LLM_MODEL:
                self.threats.append(
                    OWASPThreat(
                        category=category,
                        title=f"{definition['name']} Risk in {component.name}",
                        description="Training data source validation may be insufficient",
                        severity=definition["severity"],
                        affected_components=[component.component_id],
                        attack_scenarios=definition["common_examples"],
                        prerequisites=["Access to training pipeline", "Untrusted data sources"],
                        impact=["Model backdoors", "Biased outputs", "Compromised integrity"],
                        prevention_measures=definition["prevention"],
                        detection_strategies=definition["detection"],
                        mitre_atlas_techniques=definition["mitre_atlas"],
                        cwe_mapping=definition["cwe"],
                    )
                )

    async def _check_model_dos(self, attack_surface: AttackSurface):
        """Check for LLM04: Model Denial of Service vulnerabilities."""
        category = OWASPCategory.LLM04_MODEL_DENIAL_OF_SERVICE
        definition = self.OWASP_DEFINITIONS[category]

        for component in attack_surface.components.values():
            if component.handles_user_input and not component.rate_limited:
                self.threats.append(
                    OWASPThreat(
                        category=category,
                        title=f"{definition['name']} in {component.name}",
                        description="No rate limiting allows resource exhaustion attacks",
                        severity=definition["severity"],
                        affected_components=[component.component_id],
                        attack_scenarios=definition["common_examples"],
                        prerequisites=["API access", "No rate limiting"],
                        impact=["Service disruption", "Increased costs", "Resource exhaustion"],
                        prevention_measures=definition["prevention"],
                        detection_strategies=definition["detection"],
                        mitre_atlas_techniques=definition["mitre_atlas"],
                        cwe_mapping=definition["cwe"],
                    )
                )

    async def _check_supply_chain(self, attack_surface: AttackSurface):
        """Check for LLM05: Supply Chain Vulnerabilities."""
        category = OWASPCategory.LLM05_SUPPLY_CHAIN_VULNERABILITIES
        definition = self.OWASP_DEFINITIONS[category]

        for component in attack_surface.components.values():
            if component.component_type in [ComponentType.PLUGIN, ComponentType.INTEGRATION]:
                self.threats.append(
                    OWASPThreat(
                        category=category,
                        title=f"{definition['name']} in {component.name}",
                        description="Third-party component may have vulnerabilities",
                        severity=definition["severity"],
                        affected_components=[component.component_id],
                        attack_scenarios=definition["common_examples"],
                        prerequisites=["Third-party dependencies", "Lack of verification"],
                        impact=["Compromised components", "Backdoors", "Vulnerabilities"],
                        prevention_measures=definition["prevention"],
                        detection_strategies=definition["detection"],
                        mitre_atlas_techniques=definition["mitre_atlas"],
                        cwe_mapping=definition["cwe"],
                    )
                )

    async def _check_sensitive_info_disclosure(self, attack_surface: AttackSurface):
        """Check for LLM06: Sensitive Information Disclosure vulnerabilities."""
        category = OWASPCategory.LLM06_SENSITIVE_INFORMATION_DISCLOSURE
        definition = self.OWASP_DEFINITIONS[category]

        for component in attack_surface.components.values():
            if component.handles_sensitive_data and not component.output_sanitized:
                self.threats.append(
                    OWASPThreat(
                        category=category,
                        title=f"{definition['name']} in {component.name}",
                        description="Sensitive data may be exposed in outputs",
                        severity=definition["severity"],
                        affected_components=[component.component_id],
                        attack_scenarios=definition["common_examples"],
                        prerequisites=["Access to sensitive data", "No output filtering"],
                        impact=["PII exposure", "Data breaches", "Privacy violations"],
                        prevention_measures=definition["prevention"],
                        detection_strategies=definition["detection"],
                        mitre_atlas_techniques=definition["mitre_atlas"],
                        cwe_mapping=definition["cwe"],
                    )
                )

    async def _check_insecure_plugins(self, attack_surface: AttackSurface):
        """Check for LLM07: Insecure Plugin Design vulnerabilities."""
        category = OWASPCategory.LLM07_INSECURE_PLUGIN_DESIGN
        definition = self.OWASP_DEFINITIONS[category]

        for component in attack_surface.components.values():
            if component.component_type == ComponentType.PLUGIN:
                # Check if plugin has proper controls
                has_issues = (
                    not component.input_validated or not component.authentication_required
                )

                if has_issues:
                    self.threats.append(
                        OWASPThreat(
                            category=category,
                            title=f"{definition['name']}: {component.name}",
                            description="Plugin lacks proper security controls",
                            severity=definition["severity"],
                            affected_components=[component.component_id],
                            attack_scenarios=definition["common_examples"],
                            prerequisites=["Plugin access", "Insufficient validation"],
                            impact=["Code execution", "Data exfiltration", "Privilege escalation"],
                            prevention_measures=definition["prevention"],
                            detection_strategies=definition["detection"],
                            mitre_atlas_techniques=definition["mitre_atlas"],
                            cwe_mapping=definition["cwe"],
                        )
                    )

    async def _check_excessive_agency(self, attack_surface: AttackSurface):
        """Check for LLM08: Excessive Agency vulnerabilities."""
        category = OWASPCategory.LLM08_EXCESSIVE_AGENCY
        definition = self.OWASP_DEFINITIONS[category]

        for component in attack_surface.components.values():
            if component.component_type == ComponentType.LLM_MODEL:
                # LLMs with plugins or integrations may have excessive agency
                downstream_count = len(component.downstream_components)

                if downstream_count > 3:  # Heuristic: many downstream connections
                    self.threats.append(
                        OWASPThreat(
                            category=category,
                            title=f"{definition['name']} in {component.name}",
                            description=f"LLM has access to {downstream_count} downstream systems",
                            severity=definition["severity"],
                            affected_components=[component.component_id],
                            attack_scenarios=definition["common_examples"],
                            prerequisites=["Extensive permissions", "Autonomous actions"],
                            impact=["Unauthorized actions", "Data modification", "System changes"],
                            prevention_measures=definition["prevention"],
                            detection_strategies=definition["detection"],
                            mitre_atlas_techniques=definition["mitre_atlas"],
                            cwe_mapping=definition["cwe"],
                        )
                    )

    async def _check_overreliance(self, attack_surface: AttackSurface):
        """Check for LLM09: Overreliance vulnerabilities."""
        category = OWASPCategory.LLM09_OVERRELIANCE
        definition = self.OWASP_DEFINITIONS[category]

        # This is more of a usage pattern issue
        # Flag if LLM is used for critical decisions
        for component in attack_surface.components.values():
            if component.component_type == ComponentType.LLM_MODEL:
                if "compliance" in component.tags or "security" in component.tags:
                    self.threats.append(
                        OWASPThreat(
                            category=category,
                            title=f"{definition['name']} Risk in {component.name}",
                            description="LLM used for critical decisions without oversight",
                            severity=definition["severity"],
                            affected_components=[component.component_id],
                            attack_scenarios=definition["common_examples"],
                            prerequisites=["Critical decision-making", "Lack of verification"],
                            impact=["Misinformation", "Incorrect decisions", "Security issues"],
                            prevention_measures=definition["prevention"],
                            detection_strategies=definition["detection"],
                            mitre_atlas_techniques=definition["mitre_atlas"],
                            cwe_mapping=definition["cwe"],
                        )
                    )

    async def _check_model_theft(self, attack_surface: AttackSurface):
        """Check for LLM10: Model Theft vulnerabilities."""
        category = OWASPCategory.LLM10_MODEL_THEFT
        definition = self.OWASP_DEFINITIONS[category]

        for component in attack_surface.components.values():
            if component.component_type == ComponentType.LLM_MODEL:
                # Check if model is exposed without rate limiting
                if component.exposed_to_internet and not component.rate_limited:
                    self.threats.append(
                        OWASPThreat(
                            category=category,
                            title=f"{definition['name']} Risk in {component.name}",
                            description="Model exposed without rate limiting enables extraction",
                            severity=definition["severity"],
                            affected_components=[component.component_id],
                            attack_scenarios=definition["common_examples"],
                            prerequisites=["API access", "No rate limiting"],
                            impact=["IP theft", "Competitive loss", "Unauthorized replication"],
                            prevention_measures=definition["prevention"],
                            detection_strategies=definition["detection"],
                            mitre_atlas_techniques=definition["mitre_atlas"],
                            cwe_mapping=definition["cwe"],
                        )
                    )

    def _build_threat_model(self, application_name: str) -> OWASPThreatModel:
        """Build OWASP threat model."""
        # Count by severity
        critical = sum(1 for t in self.threats if t.severity == "critical")
        high = sum(1 for t in self.threats if t.severity == "high")

        # Get unique categories
        categories_found = list(set(t.category.value for t in self.threats))

        # Calculate coverage (out of 10 OWASP categories)
        coverage = (len(categories_found) / 10) * 100

        return OWASPThreatModel(
            application_name=application_name,
            threats=self.threats.copy(),
            total_threats=len(self.threats),
            critical_threats=critical,
            high_threats=high,
            owasp_categories_found=categories_found,
            coverage_percentage=coverage,
        )

    def get_category_details(self, category: OWASPCategory) -> Dict[str, Any]:
        """Get detailed information about OWASP category."""
        if category in self.OWASP_DEFINITIONS:
            return self.OWASP_DEFINITIONS[category]
        return {}

    async def generate_report(self, threat_model: OWASPThreatModel) -> Dict[str, Any]:
        """Generate OWASP threat report."""
        return {
            "application_name": threat_model.application_name,
            "model_id": threat_model.model_id,
            "summary": {
                "total_threats": threat_model.total_threats,
                "critical_threats": threat_model.critical_threats,
                "high_threats": threat_model.high_threats,
                "categories_found": len(threat_model.owasp_categories_found),
                "coverage_percentage": f"{threat_model.coverage_percentage:.1f}%",
            },
            "categories_found": threat_model.owasp_categories_found,
            "threats": [
                {
                    "threat_id": t.threat_id,
                    "category": t.category.value,
                    "title": t.title,
                    "description": t.description,
                    "severity": t.severity,
                    "affected_components": len(t.affected_components),
                    "attack_scenarios": t.attack_scenarios[:3],  # Top 3
                    "prevention_measures": t.prevention_measures[:5],  # Top 5
                    "mitre_atlas": t.mitre_atlas_techniques,
                    "cwe": t.cwe_mapping,
                }
                for t in self.threats
            ],
        }

    def get_all_categories_info(self) -> List[Dict[str, Any]]:
        """Get information about all OWASP Top 10 categories."""
        return [
            {
                "category_id": category.value,
                "name": definition["name"],
                "description": definition["description"],
                "severity": definition["severity"],
            }
            for category, definition in self.OWASP_DEFINITIONS.items()
        ]
