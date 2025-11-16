"""
MITRE ATLAS (Adversarial Threat Landscape for AI Systems) integration.

Maps LLM threats to MITRE ATLAS tactics and techniques for standardized
threat intelligence and defense strategies.
"""
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

logger = logging.getLogger(__name__)


class ATLASTactic(str, Enum):
    """MITRE ATLAS tactics."""

    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    ML_MODEL_ACCESS = "ml_model_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    COLLECTION = "collection"
    ML_ATTACK_STAGING = "ml_attack_staging"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class ATLASTechnique:
    """MITRE ATLAS technique."""

    technique_id: str  # e.g., "AML.T0051.000"
    name: str
    description: str
    tactic: ATLASTactic
    subtechniques: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    detection_methods: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    owasp_llm_mapping: List[str] = field(default_factory=list)


@dataclass
class ATLASMapping:
    """Mapping between threat and ATLAS techniques."""

    mapping_id: str = field(default_factory=lambda: str(uuid4()))
    threat_id: str = ""
    threat_title: str = ""
    atlas_techniques: List[str] = field(default_factory=list)  # Technique IDs
    confidence: float = 1.0  # 0-1 mapping confidence


class MITREATLASIntegration:
    """
    MITRE ATLAS framework integration.

    Provides mapping between LLM threats and MITRE ATLAS tactics and techniques.
    """

    # MITRE ATLAS technique definitions
    # Based on https://atlas.mitre.org/
    ATLAS_TECHNIQUES: Dict[str, ATLASTechnique] = {
        # ML Model Access Tactic
        "AML.T0040.000": ATLASTechnique(
            technique_id="AML.T0040.000",
            name="ML Model Inference API Access",
            description="Adversary obtains access to ML model inference APIs to query the model",
            tactic=ATLASTactic.ML_MODEL_ACCESS,
            detection_methods=[
                "Monitor API access patterns",
                "Track unusual query volumes",
                "Detect unauthorized API keys",
            ],
            mitigations=[
                "Implement strong authentication",
                "Add rate limiting",
                "Monitor API usage",
            ],
            owasp_llm_mapping=["LLM01", "LLM10"],
        ),
        "AML.T0051.000": ATLASTechnique(
            technique_id="AML.T0051.000",
            name="LLM Prompt Injection",
            description="Craft prompts to manipulate LLM behavior or extract sensitive information",
            tactic=ATLASTactic.ML_MODEL_ACCESS,
            detection_methods=[
                "Prompt pattern analysis",
                "Output anomaly detection",
                "Behavioral monitoring",
            ],
            mitigations=[
                "Input validation and sanitization",
                "Prompt guards",
                "Output filtering",
                "Separate instructions from user data",
            ],
            examples=[
                "Ignore previous instructions",
                "System prompt extraction",
                "Jailbreak attempts",
            ],
            owasp_llm_mapping=["LLM01"],
        ),
        "AML.T0054.000": ATLASTechnique(
            technique_id="AML.T0054.000",
            name="LLM Meta Prompt Extraction",
            description="Extract system prompts or meta instructions from LLM",
            tactic=ATLASTactic.COLLECTION,
            detection_methods=[
                "Monitor for extraction patterns",
                "Detect system prompt keywords in output",
            ],
            mitigations=[
                "System prompt protection",
                "Output sanitization",
                "Context isolation",
            ],
            owasp_llm_mapping=["LLM01", "LLM06"],
        ),
        # ML Attack Staging
        "AML.T0043.000": ATLASTechnique(
            technique_id="AML.T0043.000",
            name="Craft Adversarial Data",
            description="Create adversarial examples to fool ML models",
            tactic=ATLASTactic.ML_ATTACK_STAGING,
            detection_methods=[
                "Input distribution monitoring",
                "Adversarial example detection",
            ],
            mitigations=[
                "Adversarial training",
                "Input validation",
                "Ensemble methods",
            ],
            owasp_llm_mapping=["LLM01"],
        ),
        # Data Poisoning
        "AML.T0018.000": ATLASTechnique(
            technique_id="AML.T0018.000",
            name="Backdoor ML Model",
            description="Insert backdoors into ML models through training data poisoning",
            tactic=ATLASTactic.PERSISTENCE,
            detection_methods=[
                "Model behavior monitoring",
                "Training data validation",
                "Model integrity checks",
            ],
            mitigations=[
                "Data provenance tracking",
                "Training data validation",
                "Model versioning",
            ],
            owasp_llm_mapping=["LLM03"],
        ),
        "AML.T0020.000": ATLASTechnique(
            technique_id="AML.T0020.000",
            name="Poison Training Data",
            description="Introduce malicious data into training dataset",
            tactic=ATLASTactic.ML_ATTACK_STAGING,
            detection_methods=[
                "Data quality monitoring",
                "Anomaly detection in training data",
                "Data validation",
            ],
            mitigations=[
                "Data sanitization",
                "Source validation",
                "Automated data quality checks",
            ],
            owasp_llm_mapping=["LLM03"],
        ),
        # Exfiltration
        "AML.T0024.000": ATLASTechnique(
            technique_id="AML.T0024.000",
            name="Exfiltration via ML Model",
            description="Extract sensitive information through ML model queries",
            tactic=ATLASTactic.EXFILTRATION,
            detection_methods=[
                "Query pattern analysis",
                "Output content monitoring",
                "Data loss prevention",
            ],
            mitigations=[
                "Output filtering",
                "PII detection and redaction",
                "Query rate limiting",
            ],
            owasp_llm_mapping=["LLM06"],
        ),
        # Model Theft
        "AML.T0025.000": ATLASTechnique(
            technique_id="AML.T0025.000",
            name="Exfiltrate ML Model",
            description="Steal ML model through repeated queries or direct access",
            tactic=ATLASTactic.EXFILTRATION,
            detection_methods=[
                "Query volume monitoring",
                "Model probing detection",
                "Access pattern analysis",
            ],
            mitigations=[
                "API rate limiting",
                "Query complexity limits",
                "Watermarking",
            ],
            owasp_llm_mapping=["LLM10"],
        ),
        # Denial of Service
        "AML.T0029.000": ATLASTechnique(
            technique_id="AML.T0029.000",
            name="Denial of ML Service",
            description="Overwhelm ML service to cause denial of service",
            tactic=ATLASTactic.IMPACT,
            detection_methods=[
                "Resource usage monitoring",
                "Request rate monitoring",
                "Performance degradation alerts",
            ],
            mitigations=[
                "Rate limiting",
                "Resource quotas",
                "Request throttling",
            ],
            owasp_llm_mapping=["LLM04"],
        ),
        # Model Inversion
        "AML.T0028.000": ATLASTechnique(
            technique_id="AML.T0028.000",
            name="Model Inversion",
            description="Infer training data characteristics from model outputs",
            tactic=ATLASTactic.COLLECTION,
            detection_methods=[
                "Query pattern detection",
                "Statistical attack monitoring",
            ],
            mitigations=[
                "Differential privacy",
                "Output perturbation",
                "Query limits",
            ],
            owasp_llm_mapping=["LLM06"],
        ),
        # Membership Inference
        "AML.T0031.001": ATLASTechnique(
            technique_id="AML.T0031.001",
            name="Membership Inference Attack",
            description="Determine if specific data was in training set",
            tactic=ATLASTactic.COLLECTION,
            detection_methods=[
                "Confidence score monitoring",
                "Query pattern analysis",
            ],
            mitigations=[
                "Differential privacy",
                "Confidence masking",
                "Training data protection",
            ],
            owasp_llm_mapping=["LLM06"],
        ),
        # Evasion
        "AML.T0015.000": ATLASTechnique(
            technique_id="AML.T0015.000",
            name="Evade ML Model",
            description="Craft inputs to evade ML-based detection or classification",
            tactic=ATLASTactic.DEFENSE_EVASION,
            detection_methods=[
                "Ensemble detection",
                "Behavior-based detection",
            ],
            mitigations=[
                "Adversarial training",
                "Multiple detection layers",
                "Input preprocessing",
            ],
            owasp_llm_mapping=["LLM01"],
        ),
        # Supply Chain
        "AML.T0010.000": ATLASTechnique(
            technique_id="AML.T0010.000",
            name="ML Supply Chain Compromise",
            description="Compromise ML model or data pipeline supply chain",
            tactic=ATLASTactic.INITIAL_ACCESS,
            detection_methods=[
                "Dependency scanning",
                "Integrity verification",
                "SBOM validation",
            ],
            mitigations=[
                "Dependency pinning",
                "Signature verification",
                "Private registries",
            ],
            owasp_llm_mapping=["LLM05"],
        ),
        # Reconnaissance
        "AML.T0002.000": ATLASTechnique(
            technique_id="AML.T0002.000",
            name="Obtain ML Model Information",
            description="Gather information about ML model architecture, parameters, or training",
            tactic=ATLASTactic.RECONNAISSANCE,
            detection_methods=[
                "API endpoint monitoring",
                "Information disclosure detection",
            ],
            mitigations=[
                "Minimize information disclosure",
                "Generic error messages",
                "API obfuscation",
            ],
            owasp_llm_mapping=["LLM06", "LLM10"],
        ),
        # Function Manipulation
        "AML.T0048.000": ATLASTechnique(
            technique_id="AML.T0048.000",
            name="External Harms",
            description="Use LLM to generate harmful content or perform harmful actions",
            tactic=ATLASTactic.IMPACT,
            detection_methods=[
                "Content filtering",
                "Action monitoring",
                "Output validation",
            ],
            mitigations=[
                "Content safety filters",
                "Action approval workflows",
                "Human oversight",
            ],
            owasp_llm_mapping=["LLM02", "LLM08"],
        ),
        # Plugin Abuse
        "AML.T0052.000": ATLASTechnique(
            technique_id="AML.T0052.000",
            name="LLM Plugin Compromise",
            description="Exploit or abuse LLM plugins to achieve malicious objectives",
            tactic=ATLASTactic.EXECUTION,
            detection_methods=[
                "Plugin behavior monitoring",
                "Execution pattern analysis",
            ],
            mitigations=[
                "Plugin sandboxing",
                "Permission controls",
                "Plugin validation",
            ],
            owasp_llm_mapping=["LLM07"],
        ),
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize MITRE ATLAS integration.

        Args:
            config: Optional configuration
        """
        self.config = config or {}
        self.mappings: List[ATLASMapping] = []

    def get_technique(self, technique_id: str) -> Optional[ATLASTechnique]:
        """
        Get ATLAS technique by ID.

        Args:
            technique_id: Technique ID (e.g., "AML.T0051.000")

        Returns:
            Technique or None if not found
        """
        return self.ATLAS_TECHNIQUES.get(technique_id)

    def get_techniques_by_tactic(self, tactic: ATLASTactic) -> List[ATLASTechnique]:
        """
        Get all techniques for a tactic.

        Args:
            tactic: ATLAS tactic

        Returns:
            List of techniques
        """
        return [
            technique
            for technique in self.ATLAS_TECHNIQUES.values()
            if technique.tactic == tactic
        ]

    def get_techniques_by_owasp(self, owasp_id: str) -> List[ATLASTechnique]:
        """
        Get ATLAS techniques mapped to OWASP LLM category.

        Args:
            owasp_id: OWASP LLM category (e.g., "LLM01")

        Returns:
            List of mapped techniques
        """
        return [
            technique
            for technique in self.ATLAS_TECHNIQUES.values()
            if owasp_id in technique.owasp_llm_mapping
        ]

    async def map_threat_to_atlas(
        self, threat_description: str, owasp_categories: Optional[List[str]] = None
    ) -> List[str]:
        """
        Map a threat to ATLAS techniques.

        Args:
            threat_description: Description of the threat
            owasp_categories: Optional OWASP LLM categories

        Returns:
            List of matching ATLAS technique IDs
        """
        matched_techniques: Set[str] = set()

        # If OWASP categories provided, use them for mapping
        if owasp_categories:
            for owasp_id in owasp_categories:
                techniques = self.get_techniques_by_owasp(owasp_id)
                matched_techniques.update(t.technique_id for t in techniques)

        # Keyword-based matching for additional techniques
        description_lower = threat_description.lower()

        keyword_mappings = {
            "AML.T0051.000": ["prompt injection", "jailbreak", "instruction override"],
            "AML.T0054.000": ["system prompt", "meta prompt", "prompt extraction"],
            "AML.T0024.000": ["data exfiltration", "information disclosure", "data leakage"],
            "AML.T0018.000": ["backdoor", "model poisoning", "training compromise"],
            "AML.T0020.000": ["data poisoning", "training data", "dataset manipulation"],
            "AML.T0025.000": ["model theft", "model extraction", "model stealing"],
            "AML.T0029.000": ["denial of service", "dos", "resource exhaustion"],
            "AML.T0028.000": ["model inversion", "training data extraction"],
            "AML.T0031.001": ["membership inference", "training data membership"],
            "AML.T0015.000": ["evasion", "bypass", "circumvent detection"],
            "AML.T0010.000": ["supply chain", "dependency", "third-party"],
            "AML.T0048.000": ["harmful content", "external harm", "misuse"],
            "AML.T0052.000": ["plugin", "tool abuse", "function calling"],
            "AML.T0040.000": ["api access", "model access", "inference access"],
        }

        for technique_id, keywords in keyword_mappings.items():
            if any(keyword in description_lower for keyword in keywords):
                matched_techniques.add(technique_id)

        return list(matched_techniques)

    async def create_mapping(
        self, threat_id: str, threat_title: str, threat_description: str, owasp_categories: Optional[List[str]] = None
    ) -> ATLASMapping:
        """
        Create ATLAS mapping for a threat.

        Args:
            threat_id: Threat identifier
            threat_title: Threat title
            threat_description: Threat description
            owasp_categories: Optional OWASP categories

        Returns:
            ATLAS mapping
        """
        techniques = await self.map_threat_to_atlas(threat_description, owasp_categories)

        mapping = ATLASMapping(
            threat_id=threat_id,
            threat_title=threat_title,
            atlas_techniques=techniques,
            confidence=1.0 if owasp_categories else 0.7,  # Lower confidence for keyword-only
        )

        self.mappings.append(mapping)
        return mapping

    def get_mitigations_for_techniques(self, technique_ids: List[str]) -> List[str]:
        """
        Get combined mitigations for multiple techniques.

        Args:
            technique_ids: List of technique IDs

        Returns:
            Unique list of mitigations
        """
        mitigations: Set[str] = set()

        for tech_id in technique_ids:
            technique = self.get_technique(tech_id)
            if technique:
                mitigations.update(technique.mitigations)

        return list(mitigations)

    def get_detection_methods_for_techniques(self, technique_ids: List[str]) -> List[str]:
        """
        Get combined detection methods for multiple techniques.

        Args:
            technique_ids: List of technique IDs

        Returns:
            Unique list of detection methods
        """
        detection_methods: Set[str] = set()

        for tech_id in technique_ids:
            technique = self.get_technique(tech_id)
            if technique:
                detection_methods.update(technique.detection_methods)

        return list(detection_methods)

    async def generate_attack_navigator_layer(self, technique_ids: List[str]) -> Dict[str, Any]:
        """
        Generate ATT&CK Navigator layer JSON for visualization.

        Args:
            technique_ids: List of technique IDs to highlight

        Returns:
            Navigator layer JSON
        """
        techniques = []

        for tech_id in technique_ids:
            technique = self.get_technique(tech_id)
            if technique:
                techniques.append(
                    {
                        "techniqueID": tech_id,
                        "tactic": technique.tactic.value,
                        "color": "#ff6666",
                        "comment": technique.description,
                        "enabled": True,
                        "score": 1,
                    }
                )

        layer = {
            "name": "LLM Threat Model - ATLAS Coverage",
            "versions": {"attack": "13", "navigator": "4.8", "layer": "4.4"},
            "domain": "mitre-atlas",
            "description": "MITRE ATLAS techniques identified in threat model",
            "filters": {"platforms": ["LLM", "AI/ML"]},
            "sorting": 0,
            "layout": {"layout": "side", "aggregateFunction": "average", "showID": True, "showName": True},
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": 1,
            },
            "legendItems": [],
            "metadata": [],
            "links": [],
            "showTacticRowBackground": False,
            "tacticRowBackground": "#dddddd",
        }

        return layer

    async def get_coverage_report(self) -> Dict[str, Any]:
        """
        Generate coverage report showing ATLAS techniques addressed.

        Returns:
            Coverage report
        """
        all_techniques = set(self.ATLAS_TECHNIQUES.keys())
        covered_techniques = set()

        for mapping in self.mappings:
            covered_techniques.update(mapping.atlas_techniques)

        coverage_percentage = (
            (len(covered_techniques) / len(all_techniques) * 100) if all_techniques else 0
        )

        # Group by tactic
        by_tactic = {}
        for tech_id in covered_techniques:
            technique = self.get_technique(tech_id)
            if technique:
                tactic = technique.tactic.value
                if tactic not in by_tactic:
                    by_tactic[tactic] = []
                by_tactic[tactic].append(tech_id)

        return {
            "total_atlas_techniques": len(all_techniques),
            "covered_techniques": len(covered_techniques),
            "coverage_percentage": f"{coverage_percentage:.1f}%",
            "uncovered_techniques": len(all_techniques) - len(covered_techniques),
            "coverage_by_tactic": {
                tactic: len(techniques) for tactic, techniques in by_tactic.items()
            },
            "covered_technique_ids": list(covered_techniques),
            "uncovered_technique_ids": list(all_techniques - covered_techniques),
        }

    async def get_threat_intelligence_report(self, technique_ids: List[str]) -> Dict[str, Any]:
        """
        Generate threat intelligence report for techniques.

        Args:
            technique_ids: List of technique IDs

        Returns:
            Threat intelligence report
        """
        techniques_detail = []

        for tech_id in technique_ids:
            technique = self.get_technique(tech_id)
            if technique:
                techniques_detail.append(
                    {
                        "technique_id": technique.technique_id,
                        "name": technique.name,
                        "description": technique.description,
                        "tactic": technique.tactic.value,
                        "mitigations": technique.mitigations,
                        "detection_methods": technique.detection_methods,
                        "examples": technique.examples,
                        "owasp_mapping": technique.owasp_llm_mapping,
                    }
                )

        # Get unique tactics
        tactics = list(set(t["tactic"] for t in techniques_detail))

        return {
            "total_techniques": len(technique_ids),
            "tactics_involved": tactics,
            "techniques": techniques_detail,
            "combined_mitigations": self.get_mitigations_for_techniques(technique_ids),
            "combined_detection_methods": self.get_detection_methods_for_techniques(technique_ids),
        }

    def get_all_tactics(self) -> List[Dict[str, str]]:
        """Get all ATLAS tactics."""
        return [{"id": tactic.value, "name": tactic.value.replace("_", " ").title()} for tactic in ATLASTactic]

    def get_all_techniques_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all ATLAS techniques."""
        return [
            {
                "technique_id": tech.technique_id,
                "name": tech.name,
                "tactic": tech.tactic.value,
                "owasp_mapping": tech.owasp_llm_mapping,
            }
            for tech in self.ATLAS_TECHNIQUES.values()
        ]
