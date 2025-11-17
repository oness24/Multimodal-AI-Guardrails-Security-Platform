// Type definitions for the AdversarialShield platform

// Red Team Types
export interface AttackTechnique {
  id: string;
  name: string;
  description: string;
  severity: string;
  examples: string[];
}

export interface AttackPayload {
  payload: string;
  technique: string;
  severity: string;
  description: string;
}

export interface LLMProvider {
  id: string;
  name: string;
  models: string[];
  supported: boolean;
}

// Guardrails Types
export interface ThreatDetection {
  threat_type: string;
  severity: string;
  confidence: number;
  description: string;
  matched_pattern?: string;
}

export interface PIIDetection {
  pii_type: string;
  value: string;
  start_pos: number;
  end_pos: number;
  confidence: number;
}

export interface GuardrailCheckResponse {
  is_safe: boolean;
  risk_score: number;
  threats: ThreatDetection[];
  pii_detected: PIIDetection[];
  sanitized_text?: string;
  policy_violations: string[];
}

// Scanner Types
export interface Vulnerability {
  id: string;
  title: string;
  severity: string;
  confidence: number;
  description: string;
  line_number?: number;
  code_snippet?: string;
  cwe_id?: string;
  owasp_category?: string;
  remediation: string;
}

export interface CodeScanResponse {
  success: boolean;
  language: string;
  vulnerabilities: Vulnerability[];
  total_issues: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  scan_time_ms: number;
}

export interface PromptScanResponse {
  success: boolean;
  vulnerabilities: Vulnerability[];
  total_issues: number;
  is_safe: boolean;
  risk_score: number;
}
