export interface User {
  user_id: string
  email: string
  full_name: string
  is_active: boolean
  is_admin: boolean
  scopes: string[]
  created_at: string
}

export interface Attack {
  id: string
  technique: string
  payload: string
  target_model?: string
  objective?: string
  success: boolean
  response?: string
  metadata?: Record<string, any>
  created_at: string
}

export interface Vulnerability {
  id: string
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  description: string
  location?: {
    file?: string
    line?: number
    column?: number
  }
  cwe_id?: string
  owasp_category?: string
  recommendation: string
  code_snippet?: string
  created_at: string
}

export interface GuardrailValidation {
  is_safe: boolean
  blocked: boolean
  risk_score: number
  detections: Detection[]
  sanitized_prompt?: string
  metadata: Record<string, any>
}

export interface Detection {
  detector: string
  risk_level: 'critical' | 'high' | 'medium' | 'low' | 'info'
  description: string
  confidence: number
  details?: Record<string, any>
}

export interface Alert {
  id: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  description: string
  status: 'open' | 'investigating' | 'resolved' | 'false_positive'
  source: string
  detection_type: string
  timestamp: string
  metadata?: Record<string, any>
}

export interface Policy {
  id: string
  name: string
  description: string
  enabled: boolean
  rules: PolicyRule[]
  created_at: string
  updated_at: string
}

export interface PolicyRule {
  id: string
  type: string
  condition: string
  action: 'block' | 'warn' | 'log'
  severity: string
}

export interface ThreatModel {
  attack_surface: AttackSurface
  threats: Threat[]
  risk_summary: RiskSummary
}

export interface AttackSurface {
  components: Component[]
  data_flows: DataFlow[]
  entry_points: EntryPoint[]
  risk_score: number
}

export interface Component {
  id: string
  name: string
  type: string
  risk_score: number
  exposures: string[]
  controls: string[]
}

export interface DataFlow {
  id: string
  source: string
  destination: string
  data_type: string
  trust_level: string
  encrypted: boolean
}

export interface EntryPoint {
  id: string
  name: string
  type: string
  authentication_required: boolean
  rate_limited: boolean
  attack_vectors: string[]
}

export interface Threat {
  id: string
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  likelihood: 'very_high' | 'high' | 'medium' | 'low' | 'very_low'
  description: string
  impact: string
  affected_components: string[]
  mitigations: string[]
  risk_score: number
}

export interface RiskSummary {
  total_threats: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  average_risk_score: number
}

export interface DashboardStats {
  total_scans: number
  total_attacks: number
  total_vulnerabilities: number
  total_alerts: number
  critical_alerts: number
  blocked_attempts: number
  risk_score: number
  recent_activities: Activity[]
}

export interface Activity {
  id: string
  type: 'scan' | 'attack' | 'alert' | 'detection'
  title: string
  description: string
  severity?: string
  timestamp: string
  metadata?: Record<string, any>
}

export interface ChartDataPoint {
  name: string
  value: number
  color?: string
}

export interface TimeSeriesData {
  timestamp: string
  value: number
  category?: string
}

export interface HeatmapData {
  x: string
  y: string
  value: number
  color?: string
}

export interface WebSocketMessage {
  type: 'alert' | 'detection' | 'scan_complete' | 'attack_generated' | 'status_update'
  data: any
  timestamp: string
}

export interface MultimodalData {
  id: string
  type: 'text' | 'image' | 'audio' | 'video'
  content: string | ArrayBuffer
  metadata?: Record<string, any>
  analyzed: boolean
  threats?: Detection[]
  timestamp: string
}

export interface ConversationMessage {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp: string
  metadata?: Record<string, any>
}
