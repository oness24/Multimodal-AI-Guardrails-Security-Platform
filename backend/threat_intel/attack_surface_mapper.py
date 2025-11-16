"""
Attack surface mapping and discovery for LLM applications.
"""
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

logger = logging.getLogger(__name__)


class ComponentType(str, Enum):
    """Component types in LLM system."""

    LLM_MODEL = "llm_model"
    API_ENDPOINT = "api_endpoint"
    DATABASE = "database"
    VECTOR_STORE = "vector_store"
    PROMPT_TEMPLATE = "prompt_template"
    PLUGIN = "plugin"
    INTEGRATION = "integration"
    AUTH_SERVICE = "auth_service"
    GUARDRAIL = "guardrail"
    CACHE = "cache"


class DataSensitivity(str, Enum):
    """Data sensitivity levels."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class TrustBoundary(str, Enum):
    """Trust boundaries."""

    INTERNET = "internet"
    DMZ = "dmz"
    INTERNAL = "internal"
    SECURE = "secure"


@dataclass
class Component:
    """System component in attack surface."""

    component_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    component_type: ComponentType = ComponentType.API_ENDPOINT
    description: str = ""

    # Network exposure
    trust_boundary: TrustBoundary = TrustBoundary.INTERNAL
    exposed_to_internet: bool = False
    authentication_required: bool = True

    # Data handling
    handles_user_input: bool = False
    handles_sensitive_data: bool = False
    data_sensitivity: DataSensitivity = DataSensitivity.INTERNAL

    # Security controls
    rate_limited: bool = False
    input_validated: bool = False
    output_sanitized: bool = False
    logging_enabled: bool = True

    # Connections
    upstream_components: List[str] = field(default_factory=list)
    downstream_components: List[str] = field(default_factory=list)

    # Risk factors
    known_vulnerabilities: List[str] = field(default_factory=list)
    compliance_requirements: List[str] = field(default_factory=list)

    # Metadata
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataFlow:
    """Data flow between components."""

    flow_id: str = field(default_factory=lambda: str(uuid4()))
    source_component_id: str = ""
    destination_component_id: str = ""
    data_type: str = ""
    data_sensitivity: DataSensitivity = DataSensitivity.INTERNAL

    # Flow characteristics
    crosses_trust_boundary: bool = False
    encrypted: bool = False
    authenticated: bool = False

    # Data transformations
    transformations: List[str] = field(default_factory=list)

    # Risk factors
    exposure_risk: str = "low"  # low, medium, high, critical


@dataclass
class EntryPoint:
    """Entry point into the system."""

    entry_point_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    component_id: str = ""
    entry_type: str = ""  # api, webhook, cli, ui, etc.

    # Access control
    public: bool = False
    authentication_required: bool = True
    authorization_required: bool = True

    # Input characteristics
    accepts_user_input: bool = True
    input_types: List[str] = field(default_factory=list)
    input_validation: bool = False

    # Attack vectors
    potential_attack_vectors: List[str] = field(default_factory=list)

    # Risk score
    risk_score: float = 0.0


@dataclass
class AttackSurface:
    """Complete attack surface analysis."""

    analysis_id: str = field(default_factory=lambda: str(uuid4()))
    application_name: str = ""
    components: Dict[str, Component] = field(default_factory=dict)
    data_flows: List[DataFlow] = field(default_factory=list)
    entry_points: List[EntryPoint] = field(default_factory=list)

    # Analysis results
    total_components: int = 0
    internet_exposed_components: int = 0
    high_risk_components: int = 0
    total_entry_points: int = 0
    risky_data_flows: int = 0

    # Risk scores
    overall_risk_score: float = 0.0
    component_risk_scores: Dict[str, float] = field(default_factory=dict)


class AttackSurfaceMapper:
    """
    Maps and analyzes the attack surface of LLM applications.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize attack surface mapper.

        Args:
            config: Optional configuration
        """
        self.config = config or {}
        self.components: Dict[str, Component] = {}
        self.data_flows: List[DataFlow] = []
        self.entry_points: List[EntryPoint] = []

    async def discover_components(self, application_config: Dict[str, Any]) -> List[Component]:
        """
        Discover components from application configuration.

        Args:
            application_config: Application configuration

        Returns:
            List of discovered components
        """
        discovered = []

        # Discover LLM models
        if "llm_models" in application_config:
            for model_config in application_config["llm_models"]:
                component = Component(
                    name=model_config.get("name", "LLM Model"),
                    component_type=ComponentType.LLM_MODEL,
                    description=f"LLM: {model_config.get('provider', 'unknown')}",
                    handles_user_input=True,
                    handles_sensitive_data=True,
                    data_sensitivity=DataSensitivity.CONFIDENTIAL,
                    input_validated=model_config.get("input_validation", False),
                    output_sanitized=model_config.get("output_sanitization", False),
                    tags=["llm", "ai_model"],
                )
                discovered.append(component)
                self.components[component.component_id] = component

        # Discover API endpoints
        if "api_endpoints" in application_config:
            for endpoint_config in application_config["api_endpoints"]:
                component = Component(
                    name=endpoint_config.get("path", "/api"),
                    component_type=ComponentType.API_ENDPOINT,
                    exposed_to_internet=endpoint_config.get("public", False),
                    trust_boundary=TrustBoundary.INTERNET if endpoint_config.get("public") else TrustBoundary.INTERNAL,
                    authentication_required=endpoint_config.get("auth_required", True),
                    handles_user_input=True,
                    rate_limited=endpoint_config.get("rate_limited", False),
                    tags=["api", "endpoint"],
                )
                discovered.append(component)
                self.components[component.component_id] = component

        # Discover databases
        if "databases" in application_config:
            for db_config in application_config["databases"]:
                component = Component(
                    name=db_config.get("name", "Database"),
                    component_type=ComponentType.DATABASE,
                    handles_sensitive_data=True,
                    data_sensitivity=DataSensitivity.RESTRICTED,
                    trust_boundary=TrustBoundary.SECURE,
                    authentication_required=True,
                    tags=["database", "storage"],
                )
                discovered.append(component)
                self.components[component.component_id] = component

        # Discover vector stores
        if "vector_stores" in application_config:
            for vs_config in application_config["vector_stores"]:
                component = Component(
                    name=vs_config.get("name", "Vector Store"),
                    component_type=ComponentType.VECTOR_STORE,
                    handles_sensitive_data=True,
                    data_sensitivity=DataSensitivity.CONFIDENTIAL,
                    tags=["rag", "embeddings"],
                )
                discovered.append(component)
                self.components[component.component_id] = component

        # Discover plugins
        if "plugins" in application_config:
            for plugin_config in application_config["plugins"]:
                component = Component(
                    name=plugin_config.get("name", "Plugin"),
                    component_type=ComponentType.PLUGIN,
                    handles_user_input=plugin_config.get("accepts_input", True),
                    exposed_to_internet=plugin_config.get("external", False),
                    tags=["plugin", "extension"],
                )
                discovered.append(component)
                self.components[component.component_id] = component

        logger.info(f"Discovered {len(discovered)} components")
        return discovered

    async def map_data_flows(self, flow_config: Optional[List[Dict[str, Any]]] = None) -> List[DataFlow]:
        """
        Map data flows between components.

        Args:
            flow_config: Optional data flow configuration

        Returns:
            List of data flows
        """
        flows = []

        if flow_config:
            for flow_def in flow_config:
                flow = DataFlow(
                    source_component_id=flow_def.get("source"),
                    destination_component_id=flow_def.get("destination"),
                    data_type=flow_def.get("data_type", "unknown"),
                    data_sensitivity=DataSensitivity(flow_def.get("sensitivity", "internal")),
                    encrypted=flow_def.get("encrypted", False),
                    authenticated=flow_def.get("authenticated", False),
                )

                # Check if crosses trust boundary
                source_comp = self.components.get(flow.source_component_id)
                dest_comp = self.components.get(flow.destination_component_id)

                if source_comp and dest_comp:
                    flow.crosses_trust_boundary = (
                        source_comp.trust_boundary != dest_comp.trust_boundary
                    )

                flows.append(flow)
                self.data_flows.append(flow)

        logger.info(f"Mapped {len(flows)} data flows")
        return flows

    async def identify_entry_points(self) -> List[EntryPoint]:
        """
        Identify entry points into the system.

        Returns:
            List of entry points
        """
        entry_points = []

        # Entry points are typically API endpoints exposed to internet
        for component in self.components.values():
            if component.component_type == ComponentType.API_ENDPOINT:
                entry_point = EntryPoint(
                    name=component.name,
                    component_id=component.component_id,
                    entry_type="api",
                    public=component.exposed_to_internet,
                    authentication_required=component.authentication_required,
                    accepts_user_input=component.handles_user_input,
                    input_validation=component.input_validated,
                )

                # Identify potential attack vectors
                if not entry_point.authentication_required:
                    entry_point.potential_attack_vectors.append("Unauthenticated access")

                if not entry_point.input_validation:
                    entry_point.potential_attack_vectors.append("Input injection")

                if component.handles_user_input and not component.output_sanitized:
                    entry_point.potential_attack_vectors.append("Output manipulation")

                if not component.rate_limited:
                    entry_point.potential_attack_vectors.append("DoS/DDoS")

                # Calculate risk score for entry point
                entry_point.risk_score = await self._calculate_entry_point_risk(entry_point, component)

                entry_points.append(entry_point)
                self.entry_points.append(entry_point)

        logger.info(f"Identified {len(entry_points)} entry points")
        return entry_points

    async def _calculate_entry_point_risk(self, entry_point: EntryPoint, component: Component) -> float:
        """
        Calculate risk score for entry point.

        Args:
            entry_point: Entry point to score
            component: Associated component

        Returns:
            Risk score (0-10)
        """
        risk_score = 0.0

        # Base risk for public endpoints
        if entry_point.public:
            risk_score += 3.0

        # Authentication factors
        if not entry_point.authentication_required:
            risk_score += 2.5

        # Input validation
        if not entry_point.input_validation:
            risk_score += 2.0

        # User input handling
        if entry_point.accepts_user_input:
            risk_score += 1.0

        # Rate limiting
        if not component.rate_limited:
            risk_score += 1.0

        # Sensitive data handling
        if component.handles_sensitive_data:
            risk_score += 1.5

        # Known vulnerabilities
        risk_score += len(component.known_vulnerabilities) * 0.5

        return min(risk_score, 10.0)

    async def calculate_component_risk(self, component: Component) -> float:
        """
        Calculate risk score for a component.

        Args:
            component: Component to score

        Returns:
            Risk score (0-10)
        """
        risk_score = 0.0

        # Internet exposure
        if component.exposed_to_internet:
            risk_score += 2.5

        # Trust boundary
        if component.trust_boundary == TrustBoundary.INTERNET:
            risk_score += 2.0
        elif component.trust_boundary == TrustBoundary.DMZ:
            risk_score += 1.0

        # Authentication
        if not component.authentication_required:
            risk_score += 2.0

        # Data handling
        if component.handles_user_input:
            risk_score += 1.0

        if component.handles_sensitive_data:
            if component.data_sensitivity == DataSensitivity.RESTRICTED:
                risk_score += 2.0
            elif component.data_sensitivity == DataSensitivity.CONFIDENTIAL:
                risk_score += 1.5

        # Security controls (reduce risk)
        if not component.input_validated:
            risk_score += 1.5
        if not component.output_sanitized:
            risk_score += 1.0
        if not component.rate_limited and component.handles_user_input:
            risk_score += 1.0

        # Known vulnerabilities
        risk_score += len(component.known_vulnerabilities) * 1.0

        return min(risk_score, 10.0)

    async def analyze_attack_surface(self, application_config: Dict[str, Any]) -> AttackSurface:
        """
        Perform complete attack surface analysis.

        Args:
            application_config: Application configuration

        Returns:
            Attack surface analysis
        """
        # Discover components
        await self.discover_components(application_config)

        # Map data flows
        flow_config = application_config.get("data_flows", [])
        await self.map_data_flows(flow_config)

        # Identify entry points
        await self.identify_entry_points()

        # Calculate risk scores for all components
        component_risk_scores = {}
        for comp_id, component in self.components.items():
            risk_score = await self.calculate_component_risk(component)
            component_risk_scores[comp_id] = risk_score

        # Calculate metrics
        internet_exposed = sum(
            1 for c in self.components.values() if c.exposed_to_internet
        )
        high_risk = sum(1 for score in component_risk_scores.values() if score >= 7.0)

        risky_flows = sum(
            1
            for flow in self.data_flows
            if flow.crosses_trust_boundary and not flow.encrypted
        )

        # Calculate overall risk score
        if component_risk_scores:
            overall_risk = sum(component_risk_scores.values()) / len(component_risk_scores)
        else:
            overall_risk = 0.0

        attack_surface = AttackSurface(
            application_name=application_config.get("app_name", "Unknown"),
            components=self.components.copy(),
            data_flows=self.data_flows.copy(),
            entry_points=self.entry_points.copy(),
            total_components=len(self.components),
            internet_exposed_components=internet_exposed,
            high_risk_components=high_risk,
            total_entry_points=len(self.entry_points),
            risky_data_flows=risky_flows,
            overall_risk_score=overall_risk,
            component_risk_scores=component_risk_scores,
        )

        logger.info(
            f"Attack surface analysis complete: {attack_surface.total_components} components, "
            f"{attack_surface.total_entry_points} entry points, "
            f"overall risk: {attack_surface.overall_risk_score:.2f}/10"
        )

        return attack_surface

    async def get_recommendations(self, attack_surface: AttackSurface) -> List[Dict[str, Any]]:
        """
        Generate security recommendations based on attack surface analysis.

        Args:
            attack_surface: Attack surface analysis

        Returns:
            List of recommendations
        """
        recommendations = []

        # Check internet-exposed components
        if attack_surface.internet_exposed_components > 0:
            recommendations.append({
                "priority": "high",
                "category": "exposure",
                "title": "Minimize Internet Exposure",
                "description": f"{attack_surface.internet_exposed_components} components are exposed to the internet",
                "recommendation": "Review and minimize internet-facing components. Use API gateways and reverse proxies.",
            })

        # Check risky data flows
        if attack_surface.risky_data_flows > 0:
            recommendations.append({
                "priority": "high",
                "category": "encryption",
                "title": "Encrypt Cross-Boundary Data Flows",
                "description": f"{attack_surface.risky_data_flows} data flows cross trust boundaries without encryption",
                "recommendation": "Enable TLS/SSL for all cross-boundary communications. Use end-to-end encryption.",
            })

        # Check high-risk components
        for comp_id, risk_score in attack_surface.component_risk_scores.items():
            if risk_score >= 7.0:
                component = attack_surface.components[comp_id]
                recommendations.append({
                    "priority": "critical",
                    "category": "component_risk",
                    "title": f"High-Risk Component: {component.name}",
                    "description": f"Risk score: {risk_score:.1f}/10",
                    "recommendation": f"Review security controls for {component.component_type.value}. "
                                    f"Enable input validation, output sanitization, and rate limiting.",
                })

        # Check entry points
        for entry_point in attack_surface.entry_points:
            if entry_point.risk_score >= 6.0:
                recommendations.append({
                    "priority": "high",
                    "category": "entry_point",
                    "title": f"Secure Entry Point: {entry_point.name}",
                    "description": f"Risk score: {entry_point.risk_score:.1f}/10",
                    "recommendation": f"Attack vectors: {', '.join(entry_point.potential_attack_vectors)}",
                })

        return recommendations
