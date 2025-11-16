"""
Threat Intelligence module for attack surface mapping and threat modeling.
"""
from backend.threat_intel.attack_surface_mapper import (
    AttackSurface,
    AttackSurfaceMapper,
    Component,
    ComponentType,
    DataFlow,
    DataSensitivity,
    EntryPoint,
    TrustBoundary,
)
from backend.threat_intel.mitre_atlas import (
    ATLASMapping,
    ATLASTactic,
    ATLASTechnique,
    MITREATLASIntegration,
)
from backend.threat_intel.owasp_threat_modeler import (
    OWASPCategory,
    OWASPThreat,
    OWASPThreatModel,
    OWASPThreatModeler,
)
from backend.threat_intel.stride_modeler import (
    STRIDEModeler,
    Threat,
    ThreatCategory,
    ThreatLikelihood,
    ThreatModel,
    ThreatSeverity,
)

__all__ = [
    # Attack Surface Mapping
    "AttackSurfaceMapper",
    "AttackSurface",
    "Component",
    "ComponentType",
    "DataFlow",
    "DataSensitivity",
    "EntryPoint",
    "TrustBoundary",
    # STRIDE
    "STRIDEModeler",
    "Threat",
    "ThreatModel",
    "ThreatCategory",
    "ThreatSeverity",
    "ThreatLikelihood",
    # OWASP
    "OWASPThreatModeler",
    "OWASPThreat",
    "OWASPThreatModel",
    "OWASPCategory",
    # MITRE ATLAS
    "MITREATLASIntegration",
    "ATLASTechnique",
    "ATLASTactic",
    "ATLASMapping",
]
