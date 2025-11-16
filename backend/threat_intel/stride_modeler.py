"""
STRIDE threat modeling for LLM applications.

Implements STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure,
Denial of Service, Elevation of Privilege) threat modeling framework adapted
for AI/LLM security.
"""
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from backend.threat_intel.attack_surface_mapper import (
    AttackSurface,
    Component,
    ComponentType,
    DataFlow,
    EntryPoint,
)

logger = logging.getLogger(__name__)


class ThreatCategory(str, Enum):
    """STRIDE threat categories."""

    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class ThreatSeverity(str, Enum):
    """Threat severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatLikelihood(str, Enum):
    """Threat likelihood levels."""

    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    VERY_LOW = "very_low"


@dataclass
class Threat:
    """Identified security threat."""

    threat_id: str = field(default_factory=lambda: str(uuid4()))
    category: ThreatCategory = ThreatCategory.SPOOFING
    title: str = ""
    description: str = ""

    # Risk assessment
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    likelihood: ThreatLikelihood = ThreatLikelihood.MEDIUM
    risk_score: float = 0.0  # 0-10 scale

    # Context
    affected_components: List[str] = field(default_factory=list)
    affected_data_flows: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)

    # Mitigation
    mitigations: List[str] = field(default_factory=list)
    mitigation_status: str = "not_implemented"  # not_implemented, partial, implemented

    # STRIDE-specific
    stride_element: str = ""  # Which STRIDE element
    prerequisites: List[str] = field(default_factory=list)
    impact: str = ""

    # Compliance mapping
    owasp_llm_mapping: List[str] = field(default_factory=list)
    mitre_atlas_mapping: List[str] = field(default_factory=list)


@dataclass
class ThreatModel:
    """Complete threat model for system."""

    model_id: str = field(default_factory=lambda: str(uuid4()))
    system_name: str = ""
    threats: List[Threat] = field(default_factory=list)

    # Statistics
    total_threats: int = 0
    critical_threats: int = 0
    high_threats: int = 0
    medium_threats: int = 0
    low_threats: int = 0

    # By category
    threats_by_category: Dict[str, int] = field(default_factory=dict)

    # Risk summary
    overall_risk_score: float = 0.0
    unmitigated_threats: int = 0


class STRIDEModeler:
    """
    STRIDE threat modeling engine for LLM applications.

    Analyzes attack surface and identifies threats across all STRIDE categories,
    adapted for AI/LLM-specific security concerns.
    """

    # Severity and likelihood to risk score mapping
    SEVERITY_SCORES = {
        ThreatSeverity.CRITICAL: 10.0,
        ThreatSeverity.HIGH: 7.5,
        ThreatSeverity.MEDIUM: 5.0,
        ThreatSeverity.LOW: 2.5,
        ThreatSeverity.INFO: 1.0,
    }

    LIKELIHOOD_MULTIPLIERS = {
        ThreatLikelihood.VERY_HIGH: 1.0,
        ThreatLikelihood.HIGH: 0.8,
        ThreatLikelihood.MEDIUM: 0.6,
        ThreatLikelihood.LOW: 0.4,
        ThreatLikelihood.VERY_LOW: 0.2,
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize STRIDE modeler.

        Args:
            config: Optional configuration
        """
        self.config = config or {}
        self.threats: List[Threat] = []

    async def analyze_attack_surface(self, attack_surface: AttackSurface) -> ThreatModel:
        """
        Perform STRIDE threat modeling on attack surface.

        Args:
            attack_surface: Attack surface analysis

        Returns:
            Complete threat model
        """
        self.threats = []

        # Analyze each STRIDE category
        await self._identify_spoofing_threats(attack_surface)
        await self._identify_tampering_threats(attack_surface)
        await self._identify_repudiation_threats(attack_surface)
        await self._identify_information_disclosure_threats(attack_surface)
        await self._identify_denial_of_service_threats(attack_surface)
        await self._identify_elevation_of_privilege_threats(attack_surface)

        # Calculate risk scores
        for threat in self.threats:
            threat.risk_score = self._calculate_risk_score(threat)

        # Build threat model
        threat_model = self._build_threat_model(attack_surface.application_name)

        logger.info(
            f"STRIDE analysis complete: {threat_model.total_threats} threats identified, "
            f"{threat_model.critical_threats} critical, {threat_model.high_threats} high"
        )

        return threat_model

    async def _identify_spoofing_threats(self, attack_surface: AttackSurface):
        """Identify spoofing threats (identity/authentication)."""

        # Check for unauthenticated components
        for component in attack_surface.components.values():
            if not component.authentication_required and component.exposed_to_internet:
                threat = Threat(
                    category=ThreatCategory.SPOOFING,
                    stride_element="Spoofing Identity",
                    title=f"Unauthenticated Access to {component.name}",
                    description=f"Component {component.name} ({component.component_type.value}) "
                    f"is exposed to the internet without authentication, allowing "
                    f"attackers to impersonate legitimate users.",
                    severity=ThreatSeverity.HIGH,
                    likelihood=ThreatLikelihood.HIGH,
                    affected_components=[component.component_id],
                    attack_vectors=[
                        "Direct API access without credentials",
                        "Automated bot attacks",
                        "Mass scanning and exploitation",
                    ],
                    mitigations=[
                        "Implement strong authentication (OAuth 2.0, JWT)",
                        "Require API keys for all requests",
                        "Add rate limiting per IP/user",
                        "Implement request signing",
                    ],
                    prerequisites=["Network access to component"],
                    impact="Unauthorized access to LLM functionality, potential data theft, abuse",
                    owasp_llm_mapping=["LLM01"],  # Prompt Injection via unauthorized access
                )
                self.threats.append(threat)

        # Check for LLM model impersonation
        for component in attack_surface.components.values():
            if component.component_type == ComponentType.LLM_MODEL:
                threat = Threat(
                    category=ThreatCategory.SPOOFING,
                    stride_element="Model Impersonation",
                    title="LLM Model Identity Spoofing",
                    description=f"Attacker could impersonate the LLM model ({component.name}) "
                    f"by injecting prompts that make the model claim a different identity, "
                    f"role, or capabilities.",
                    severity=ThreatSeverity.MEDIUM,
                    likelihood=ThreatLikelihood.MEDIUM,
                    affected_components=[component.component_id],
                    attack_vectors=[
                        "Prompt injection to change model persona",
                        "System prompt override",
                        "Role assumption attacks",
                    ],
                    mitigations=[
                        "Implement strict prompt validation",
                        "Add system prompt protection",
                        "Use output verification",
                        "Implement model signature verification",
                    ],
                    prerequisites=["Access to LLM input"],
                    impact="Users receive responses from falsified model identity, potential misinformation",
                    owasp_llm_mapping=["LLM01"],  # Prompt Injection
                    mitre_atlas_mapping=["AML.T0051.000"],  # LLM Prompt Injection
                )
                self.threats.append(threat)

        # Check for session hijacking
        for entry_point in attack_surface.entry_points:
            if entry_point.public:
                threat = Threat(
                    category=ThreatCategory.SPOOFING,
                    stride_element="Session Hijacking",
                    title=f"Session Hijacking on {entry_point.name}",
                    description="Attacker could steal or forge session tokens to impersonate "
                    "legitimate users and access their conversations/data.",
                    severity=ThreatSeverity.HIGH,
                    likelihood=ThreatLikelihood.MEDIUM,
                    affected_components=[entry_point.component_id],
                    attack_vectors=[
                        "Session token theft via XSS",
                        "Session fixation",
                        "Man-in-the-middle attacks",
                        "Token prediction",
                    ],
                    mitigations=[
                        "Use secure, HttpOnly cookies",
                        "Implement session regeneration",
                        "Add session binding to IP/User-Agent",
                        "Use short session timeouts",
                        "Implement logout functionality",
                    ],
                    prerequisites=["Access to session tokens"],
                    impact="Unauthorized access to user sessions, data theft, impersonation",
                    owasp_llm_mapping=["LLM01"],
                )
                self.threats.append(threat)

    async def _identify_tampering_threats(self, attack_surface: AttackSurface):
        """Identify tampering threats (data/code modification)."""

        # Check for prompt tampering
        for component in attack_surface.components.values():
            if component.handles_user_input and not component.input_validated:
                threat = Threat(
                    category=ThreatCategory.TAMPERING,
                    stride_element="Prompt Tampering",
                    title=f"Prompt Injection in {component.name}",
                    description=f"Attacker can modify or inject malicious content into prompts "
                    f"sent to {component.name}, potentially altering model behavior "
                    f"or extracting sensitive information.",
                    severity=ThreatSeverity.CRITICAL,
                    likelihood=ThreatLikelihood.HIGH,
                    affected_components=[component.component_id],
                    attack_vectors=[
                        "Direct prompt injection",
                        "Indirect prompt injection via documents",
                        "Context manipulation",
                        "Delimiter confusion",
                    ],
                    mitigations=[
                        "Implement input validation and sanitization",
                        "Use prompt guards and filters",
                        "Separate user input from instructions",
                        "Implement output filtering",
                        "Use structured outputs",
                    ],
                    prerequisites=["Ability to provide input to LLM"],
                    impact="Model behavior manipulation, data exfiltration, policy bypass",
                    owasp_llm_mapping=["LLM01"],  # Prompt Injection
                    mitre_atlas_mapping=["AML.T0051.000", "AML.T0054.000"],
                )
                self.threats.append(threat)

        # Check for model tampering
        for component in attack_surface.components.values():
            if component.component_type == ComponentType.LLM_MODEL:
                threat = Threat(
                    category=ThreatCategory.TAMPERING,
                    stride_element="Model Poisoning",
                    title="Model Training Data Poisoning",
                    description="Attacker could inject malicious data into training dataset "
                    "or fine-tuning process to alter model behavior.",
                    severity=ThreatSeverity.CRITICAL,
                    likelihood=ThreatLikelihood.LOW,
                    affected_components=[component.component_id],
                    attack_vectors=[
                        "Training data injection",
                        "Fine-tuning poisoning",
                        "Feedback loop manipulation",
                    ],
                    mitigations=[
                        "Validate and sanitize training data",
                        "Implement data provenance tracking",
                        "Use secure fine-tuning pipelines",
                        "Monitor model behavior changes",
                        "Implement model versioning and rollback",
                    ],
                    prerequisites=["Access to training pipeline"],
                    impact="Persistent model compromise, backdoors, bias injection",
                    owasp_llm_mapping=["LLM03"],  # Training Data Poisoning
                    mitre_atlas_mapping=["AML.T0018.000"],  # Backdoor ML Model
                )
                self.threats.append(threat)

        # Check for unencrypted data flows
        for data_flow in attack_surface.data_flows:
            if data_flow.crosses_trust_boundary and not data_flow.encrypted:
                threat = Threat(
                    category=ThreatCategory.TAMPERING,
                    stride_element="Data Flow Tampering",
                    title="Unencrypted Cross-Boundary Data Flow",
                    description="Data flowing across trust boundaries without encryption "
                    "can be intercepted and modified by attackers.",
                    severity=ThreatSeverity.HIGH,
                    likelihood=ThreatLikelihood.MEDIUM,
                    affected_data_flows=[data_flow.flow_id],
                    attack_vectors=[
                        "Man-in-the-middle attacks",
                        "Network eavesdropping",
                        "Traffic modification",
                    ],
                    mitigations=[
                        "Enable TLS/SSL for all communications",
                        "Use end-to-end encryption",
                        "Implement certificate pinning",
                        "Add integrity checks (HMAC)",
                    ],
                    prerequisites=["Network access"],
                    impact="Data modification, prompt tampering, response manipulation",
                    owasp_llm_mapping=["LLM02"],  # Insecure Output Handling
                )
                self.threats.append(threat)

        # Check for plugin tampering
        for component in attack_surface.components.values():
            if component.component_type == ComponentType.PLUGIN:
                threat = Threat(
                    category=ThreatCategory.TAMPERING,
                    stride_element="Plugin Tampering",
                    title=f"Plugin Modification: {component.name}",
                    description="Attacker could modify plugin code or configuration to "
                    "alter LLM behavior or inject malicious functionality.",
                    severity=ThreatSeverity.HIGH,
                    likelihood=ThreatLikelihood.LOW,
                    affected_components=[component.component_id],
                    attack_vectors=[
                        "Plugin code injection",
                        "Configuration tampering",
                        "Dependency confusion",
                    ],
                    mitigations=[
                        "Implement plugin signing and verification",
                        "Use read-only plugin directories",
                        "Implement integrity monitoring",
                        "Restrict plugin installation permissions",
                    ],
                    prerequisites=["Write access to plugin files"],
                    impact="Malicious code execution, data theft, backdoors",
                    owasp_llm_mapping=["LLM07"],  # Insecure Plugin Design
                    mitre_atlas_mapping=["AML.T0018.000"],
                )
                self.threats.append(threat)

    async def _identify_repudiation_threats(self, attack_surface: AttackSurface):
        """Identify repudiation threats (logging/auditing)."""

        # Check for components without logging
        for component in attack_surface.components.values():
            if not component.logging_enabled and component.handles_user_input:
                threat = Threat(
                    category=ThreatCategory.REPUDIATION,
                    stride_element="Insufficient Logging",
                    title=f"No Audit Trail for {component.name}",
                    description=f"Component {component.name} does not log user actions, "
                    f"preventing forensic analysis and accountability.",
                    severity=ThreatSeverity.MEDIUM,
                    likelihood=ThreatLikelihood.HIGH,
                    affected_components=[component.component_id],
                    attack_vectors=[
                        "Untraceable malicious actions",
                        "Evidence destruction",
                        "Action denial",
                    ],
                    mitigations=[
                        "Implement comprehensive logging",
                        "Log all user inputs and outputs",
                        "Use centralized log management (SIEM)",
                        "Implement log integrity protection",
                        "Add non-repudiation controls (signatures)",
                    ],
                    prerequisites=["Access to component"],
                    impact="No forensic evidence, inability to attribute actions, compliance issues",
                    owasp_llm_mapping=["LLM09"],  # Overreliance
                )
                self.threats.append(threat)

        # Check for LLM interaction logging
        for component in attack_surface.components.values():
            if component.component_type == ComponentType.LLM_MODEL:
                threat = Threat(
                    category=ThreatCategory.REPUDIATION,
                    stride_element="LLM Interaction Logging",
                    title="Insufficient LLM Interaction Logging",
                    description="LLM prompts and responses are not adequately logged, "
                    "preventing detection of abuse or malicious use.",
                    severity=ThreatSeverity.MEDIUM,
                    likelihood=ThreatLikelihood.MEDIUM,
                    affected_components=[component.component_id],
                    attack_vectors=[
                        "Undetected prompt injection",
                        "Hidden jailbreak attempts",
                        "Untraceable data exfiltration",
                    ],
                    mitigations=[
                        "Log all prompts and responses (sanitized)",
                        "Implement anomaly detection on logs",
                        "Add timestamps and user attribution",
                        "Enable tamper-proof logging",
                        "Set appropriate retention periods",
                    ],
                    prerequisites=["LLM access"],
                    impact="Inability to detect or investigate attacks, compliance violations",
                    owasp_llm_mapping=["LLM01", "LLM09"],
                )
                self.threats.append(threat)

    async def _identify_information_disclosure_threats(self, attack_surface: AttackSurface):
        """Identify information disclosure threats (confidentiality)."""

        # Check for sensitive data handling
        for component in attack_surface.components.values():
            if component.handles_sensitive_data and not component.output_sanitized:
                threat = Threat(
                    category=ThreatCategory.INFORMATION_DISCLOSURE,
                    stride_element="Data Leakage",
                    title=f"Sensitive Data Exposure in {component.name}",
                    description=f"Component {component.name} handles sensitive data but does not "
                    f"sanitize outputs, risking data leakage through model responses.",
                    severity=ThreatSeverity.CRITICAL,
                    likelihood=ThreatLikelihood.HIGH,
                    affected_components=[component.component_id],
                    attack_vectors=[
                        "Prompt injection to extract training data",
                        "Inference attacks",
                        "Direct data extraction prompts",
                        "Context manipulation",
                    ],
                    mitigations=[
                        "Implement output filtering and redaction",
                        "Use PII detection and removal",
                        "Add content safety filters",
                        "Implement data loss prevention (DLP)",
                        "Restrict model access to sensitive data",
                    ],
                    prerequisites=["Model access"],
                    impact="Confidential data exposure, privacy violations, compliance breaches",
                    owasp_llm_mapping=["LLM06"],  # Sensitive Information Disclosure
                    mitre_atlas_mapping=["AML.T0024.000"],  # Exfiltration via ML Model
                )
                self.threats.append(threat)

        # Check for training data leakage
        for component in attack_surface.components.values():
            if component.component_type == ComponentType.LLM_MODEL:
                threat = Threat(
                    category=ThreatCategory.INFORMATION_DISCLOSURE,
                    stride_element="Training Data Extraction",
                    title="Training Data Memorization and Extraction",
                    description="LLM may have memorized sensitive training data that can be "
                    "extracted through carefully crafted prompts.",
                    severity=ThreatSeverity.HIGH,
                    likelihood=ThreatLikelihood.MEDIUM,
                    affected_components=[component.component_id],
                    attack_vectors=[
                        "Prompt-based data extraction",
                        "Membership inference attacks",
                        "Model inversion attacks",
                    ],
                    mitigations=[
                        "Use differential privacy in training",
                        "Implement training data sanitization",
                        "Add output monitoring for sensitive patterns",
                        "Use federated learning where appropriate",
                        "Implement guardrails for PII detection",
                    ],
                    prerequisites=["Model query access"],
                    impact="Private training data exposure, PII leakage",
                    owasp_llm_mapping=["LLM06"],
                    mitre_atlas_mapping=["AML.T0024.000"],
                )
                self.threats.append(threat)

        # Check for vector store data exposure
        for component in attack_surface.components.values():
            if component.component_type == ComponentType.VECTOR_STORE:
                threat = Threat(
                    category=ThreatCategory.INFORMATION_DISCLOSURE,
                    stride_element="Vector Store Leakage",
                    title=f"Embedding/Document Exposure from {component.name}",
                    description="Vector store may expose sensitive documents or data through "
                    "similarity search or metadata leakage.",
                    severity=ThreatSeverity.HIGH,
                    likelihood=ThreatLikelihood.MEDIUM,
                    affected_components=[component.component_id],
                    attack_vectors=[
                        "Similarity search manipulation",
                        "Metadata extraction",
                        "Nearest neighbor attacks",
                    ],
                    mitigations=[
                        "Implement access controls on vector store",
                        "Add query filtering by user permissions",
                        "Sanitize document metadata",
                        "Use encryption at rest",
                        "Implement result filtering",
                    ],
                    prerequisites=["Vector store query access"],
                    impact="Unauthorized document access, sensitive data exposure",
                    owasp_llm_mapping=["LLM06", "LLM10"],  # Model Theft
                )
                self.threats.append(threat)

        # Check for API response information leakage
        for entry_point in attack_surface.entry_points:
            threat = Threat(
                category=ThreatCategory.INFORMATION_DISCLOSURE,
                stride_element="API Information Leakage",
                title=f"Verbose Error Messages from {entry_point.name}",
                description="API endpoint may expose sensitive information through error messages, "
                "stack traces, or debug information.",
                severity=ThreatSeverity.MEDIUM,
                likelihood=ThreatLikelihood.HIGH,
                affected_components=[entry_point.component_id],
                attack_vectors=[
                    "Error message enumeration",
                    "Stack trace analysis",
                    "Debug mode exploitation",
                ],
                mitigations=[
                    "Use generic error messages",
                    "Disable debug mode in production",
                    "Implement error sanitization",
                    "Log detailed errors internally only",
                ],
                prerequisites=["API access"],
                impact="System architecture disclosure, attack surface mapping",
                owasp_llm_mapping=["LLM02"],
            )
            self.threats.append(threat)

    async def _identify_denial_of_service_threats(self, attack_surface: AttackSurface):
        """Identify denial of service threats (availability)."""

        # Check for rate limiting
        for component in attack_surface.components.values():
            if component.handles_user_input and not component.rate_limited:
                threat = Threat(
                    category=ThreatCategory.DENIAL_OF_SERVICE,
                    stride_element="Resource Exhaustion",
                    title=f"No Rate Limiting on {component.name}",
                    description=f"Component {component.name} does not implement rate limiting, "
                    f"allowing attackers to exhaust resources through excessive requests.",
                    severity=ThreatSeverity.HIGH,
                    likelihood=ThreatLikelihood.HIGH,
                    affected_components=[component.component_id],
                    attack_vectors=[
                        "Request flooding",
                        "Automated bot attacks",
                        "Distributed denial of service",
                    ],
                    mitigations=[
                        "Implement rate limiting per user/IP",
                        "Add request throttling",
                        "Use WAF for DDoS protection",
                        "Implement queue management",
                        "Add circuit breakers",
                    ],
                    prerequisites=["Network access"],
                    impact="Service unavailability, increased costs, legitimate user impact",
                    owasp_llm_mapping=["LLM04"],  # Model Denial of Service
                )
                self.threats.append(threat)

        # Check for expensive LLM operations
        for component in attack_surface.components.values():
            if component.component_type == ComponentType.LLM_MODEL:
                threat = Threat(
                    category=ThreatCategory.DENIAL_OF_SERVICE,
                    stride_element="LLM Resource Exhaustion",
                    title="Model Denial of Service via Expensive Queries",
                    description="Attacker can craft computationally expensive prompts that "
                    "consume excessive tokens, memory, or processing time.",
                    severity=ThreatSeverity.HIGH,
                    likelihood=ThreatLikelihood.MEDIUM,
                    affected_components=[component.component_id],
                    attack_vectors=[
                        "Extremely long prompts",
                        "Recursive generation requests",
                        "Complex reasoning tasks",
                        "Large batch requests",
                    ],
                    mitigations=[
                        "Implement token limits",
                        "Add timeout controls",
                        "Use cost-based rate limiting",
                        "Implement request queuing with priority",
                        "Monitor resource usage",
                    ],
                    prerequisites=["LLM access"],
                    impact="Service degradation, increased costs, model unavailability",
                    owasp_llm_mapping=["LLM04"],
                    mitre_atlas_mapping=["AML.T0029.000"],  # Denial of ML Service
                )
                self.threats.append(threat)

        # Check for plugin-based DoS
        for component in attack_surface.components.values():
            if component.component_type == ComponentType.PLUGIN:
                threat = Threat(
                    category=ThreatCategory.DENIAL_OF_SERVICE,
                    stride_element="Plugin DoS",
                    title=f"Plugin Resource Exhaustion: {component.name}",
                    description="Malicious or poorly designed plugins can consume excessive "
                    "resources or cause service failures.",
                    severity=ThreatSeverity.MEDIUM,
                    likelihood=ThreatLikelihood.MEDIUM,
                    affected_components=[component.component_id],
                    attack_vectors=[
                        "Plugin infinite loops",
                        "Memory exhaustion",
                        "Plugin crashes",
                    ],
                    mitigations=[
                        "Implement plugin resource limits",
                        "Add plugin timeout controls",
                        "Use plugin sandboxing",
                        "Monitor plugin performance",
                        "Implement plugin allowlisting",
                    ],
                    prerequisites=["Plugin execution access"],
                    impact="Service disruption, resource exhaustion",
                    owasp_llm_mapping=["LLM07"],
                )
                self.threats.append(threat)

    async def _identify_elevation_of_privilege_threats(self, attack_surface: AttackSurface):
        """Identify elevation of privilege threats (authorization)."""

        # Check for missing authorization
        for entry_point in attack_surface.entry_points:
            if not entry_point.authorization_required:
                threat = Threat(
                    category=ThreatCategory.ELEVATION_OF_PRIVILEGE,
                    stride_element="Missing Authorization",
                    title=f"No Authorization on {entry_point.name}",
                    description="Entry point does not implement authorization checks, "
                    "allowing users to access functionality beyond their privileges.",
                    severity=ThreatSeverity.CRITICAL,
                    likelihood=ThreatLikelihood.HIGH,
                    affected_components=[entry_point.component_id],
                    attack_vectors=[
                        "Direct object reference",
                        "Function-level authorization bypass",
                        "Privilege escalation",
                    ],
                    mitigations=[
                        "Implement role-based access control (RBAC)",
                        "Add attribute-based access control (ABAC)",
                        "Enforce least privilege principle",
                        "Implement authorization checks on all endpoints",
                        "Add permission validation",
                    ],
                    prerequisites=["API access"],
                    impact="Unauthorized access to privileged functionality, data access",
                    owasp_llm_mapping=["LLM08"],  # Excessive Agency
                )
                self.threats.append(threat)

        # Check for LLM excessive agency
        for component in attack_surface.components.values():
            if component.component_type == ComponentType.LLM_MODEL:
                threat = Threat(
                    category=ThreatCategory.ELEVATION_OF_PRIVILEGE,
                    stride_element="Excessive Agency",
                    title="LLM Excessive Permissions and Agency",
                    description="LLM has excessive permissions to perform actions or access "
                    "resources beyond what is necessary for its function.",
                    severity=ThreatSeverity.HIGH,
                    likelihood=ThreatLikelihood.MEDIUM,
                    affected_components=[component.component_id],
                    attack_vectors=[
                        "Prompt injection to trigger unauthorized actions",
                        "Function calling abuse",
                        "Tool misuse",
                    ],
                    mitigations=[
                        "Implement least privilege for LLM",
                        "Add human-in-the-loop for sensitive actions",
                        "Restrict tool/function access",
                        "Implement action approval workflows",
                        "Add audit trails for LLM actions",
                    ],
                    prerequisites=["LLM prompt access"],
                    impact="Unauthorized actions, data modification, privilege escalation",
                    owasp_llm_mapping=["LLM08"],
                    mitre_atlas_mapping=["AML.T0051.000"],
                )
                self.threats.append(threat)

        # Check for plugin privilege escalation
        for component in attack_surface.components.values():
            if component.component_type == ComponentType.PLUGIN:
                threat = Threat(
                    category=ThreatCategory.ELEVATION_OF_PRIVILEGE,
                    stride_element="Plugin Privilege Escalation",
                    title=f"Excessive Plugin Permissions: {component.name}",
                    description="Plugin has excessive permissions that could be exploited "
                    "to escalate privileges or access unauthorized resources.",
                    severity=ThreatSeverity.HIGH,
                    likelihood=ThreatLikelihood.LOW,
                    affected_components=[component.component_id],
                    attack_vectors=[
                        "Plugin exploitation",
                        "Privilege escalation through plugin API",
                        "Plugin chain attacks",
                    ],
                    mitigations=[
                        "Implement plugin permission model",
                        "Use least privilege for plugins",
                        "Add plugin capability restrictions",
                        "Implement plugin review process",
                        "Use plugin sandboxing",
                    ],
                    prerequisites=["Plugin installation/execution"],
                    impact="System compromise, unauthorized data access",
                    owasp_llm_mapping=["LLM07", "LLM08"],
                )
                self.threats.append(threat)

        # Check for supply chain risks
        for component in attack_surface.components.values():
            if component.component_type in [ComponentType.PLUGIN, ComponentType.INTEGRATION]:
                threat = Threat(
                    category=ThreatCategory.ELEVATION_OF_PRIVILEGE,
                    stride_element="Supply Chain Attack",
                    title=f"Supply Chain Compromise: {component.name}",
                    description="Third-party component or dependency could be compromised, "
                    "allowing attackers to inject malicious code with elevated privileges.",
                    severity=ThreatSeverity.HIGH,
                    likelihood=ThreatLikelihood.LOW,
                    affected_components=[component.component_id],
                    attack_vectors=[
                        "Dependency confusion",
                        "Malicious package injection",
                        "Compromised upstream dependencies",
                    ],
                    mitigations=[
                        "Implement dependency scanning",
                        "Use Software Bill of Materials (SBOM)",
                        "Verify package signatures",
                        "Pin dependency versions",
                        "Use private package registries",
                    ],
                    prerequisites=["Dependency installation"],
                    impact="Code execution with system privileges, backdoors",
                    owasp_llm_mapping=["LLM05"],  # Supply Chain Vulnerabilities
                    mitre_atlas_mapping=["AML.T0010.000"],  # ML Supply Chain Compromise
                )
                self.threats.append(threat)

    def _calculate_risk_score(self, threat: Threat) -> float:
        """
        Calculate risk score for threat.

        Args:
            threat: Threat to score

        Returns:
            Risk score (0-10)
        """
        severity_score = self.SEVERITY_SCORES.get(threat.severity, 5.0)
        likelihood_mult = self.LIKELIHOOD_MULTIPLIERS.get(threat.likelihood, 0.6)

        risk_score = severity_score * likelihood_mult

        # Adjust based on mitigation status
        if threat.mitigation_status == "implemented":
            risk_score *= 0.2  # 80% risk reduction
        elif threat.mitigation_status == "partial":
            risk_score *= 0.5  # 50% risk reduction

        return min(risk_score, 10.0)

    def _build_threat_model(self, system_name: str) -> ThreatModel:
        """
        Build complete threat model from identified threats.

        Args:
            system_name: Name of system being modeled

        Returns:
            Complete threat model
        """
        # Count by severity
        critical = sum(1 for t in self.threats if t.severity == ThreatSeverity.CRITICAL)
        high = sum(1 for t in self.threats if t.severity == ThreatSeverity.HIGH)
        medium = sum(1 for t in self.threats if t.severity == ThreatSeverity.MEDIUM)
        low = sum(1 for t in self.threats if t.severity == ThreatSeverity.LOW)

        # Count by category
        by_category = {}
        for threat in self.threats:
            category = threat.category.value
            by_category[category] = by_category.get(category, 0) + 1

        # Calculate overall risk
        if self.threats:
            overall_risk = sum(t.risk_score for t in self.threats) / len(self.threats)
        else:
            overall_risk = 0.0

        # Count unmitigated threats
        unmitigated = sum(
            1 for t in self.threats if t.mitigation_status == "not_implemented"
        )

        return ThreatModel(
            system_name=system_name,
            threats=self.threats.copy(),
            total_threats=len(self.threats),
            critical_threats=critical,
            high_threats=high,
            medium_threats=medium,
            low_threats=low,
            threats_by_category=by_category,
            overall_risk_score=overall_risk,
            unmitigated_threats=unmitigated,
        )

    async def get_threat_report(self, threat_model: ThreatModel) -> Dict[str, Any]:
        """
        Generate threat report.

        Args:
            threat_model: Threat model to report on

        Returns:
            Report dictionary
        """
        return {
            "system_name": threat_model.system_name,
            "model_id": threat_model.model_id,
            "summary": {
                "total_threats": threat_model.total_threats,
                "critical": threat_model.critical_threats,
                "high": threat_model.high_threats,
                "medium": threat_model.medium_threats,
                "low": threat_model.low_threats,
                "overall_risk_score": f"{threat_model.overall_risk_score:.2f}/10",
                "unmitigated_threats": threat_model.unmitigated_threats,
            },
            "by_category": threat_model.threats_by_category,
            "threats": [
                {
                    "threat_id": t.threat_id,
                    "category": t.category.value,
                    "stride_element": t.stride_element,
                    "title": t.title,
                    "description": t.description,
                    "severity": t.severity.value,
                    "likelihood": t.likelihood.value,
                    "risk_score": f"{t.risk_score:.2f}",
                    "affected_components": len(t.affected_components),
                    "attack_vectors": t.attack_vectors,
                    "mitigations": t.mitigations,
                    "mitigation_status": t.mitigation_status,
                    "owasp_llm": t.owasp_llm_mapping,
                    "mitre_atlas": t.mitre_atlas_mapping,
                }
                for t in sorted(
                    threat_model.threats, key=lambda x: x.risk_score, reverse=True
                )
            ],
        }
