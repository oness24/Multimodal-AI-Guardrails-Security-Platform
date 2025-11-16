import axios, { AxiosError, AxiosInstance, AxiosRequestConfig } from 'axios'

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

class APIClient {
  private client: AxiosInstance

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        'Content-Type': 'application/json',
      },
      timeout: 30000,
    })

    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        // Add auth token if available
        const token = typeof window !== 'undefined' ? localStorage.getItem('accessToken') : null
        if (token && config.headers) {
          config.headers.Authorization = `Bearer ${token}`
        }
        return config
      },
      (error) => Promise.reject(error)
    )

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => response,
      async (error: AxiosError) => {
        if (error.response?.status === 401) {
          // Token expired, try to refresh
          try {
            await this.refreshToken()
            // Retry original request
            if (error.config) {
              return this.client.request(error.config)
            }
          } catch (refreshError) {
            // Refresh failed, logout user
            if (typeof window !== 'undefined') {
              localStorage.removeItem('accessToken')
              localStorage.removeItem('refreshToken')
              window.location.href = '/login'
            }
          }
        }
        return Promise.reject(error)
      }
    )
  }

  async refreshToken(): Promise<void> {
    const refreshToken = typeof window !== 'undefined' ? localStorage.getItem('refreshToken') : null
    if (!refreshToken) throw new Error('No refresh token')

    const response = await this.client.post('/api/v1/refresh', {
      refresh_token: refreshToken,
    })

    if (typeof window !== 'undefined') {
      localStorage.setItem('accessToken', response.data.access_token)
    }
  }

  // Authentication
  async login(email: string, password: string) {
    const formData = new FormData()
    formData.append('username', email)
    formData.append('password', password)

    const response = await this.client.post('/api/v1/login', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })

    if (typeof window !== 'undefined') {
      localStorage.setItem('accessToken', response.data.access_token)
      localStorage.setItem('refreshToken', response.data.refresh_token)
    }

    return response.data
  }

  async register(email: string, password: string, fullName: string) {
    const response = await this.client.post('/api/v1/register', {
      email,
      password,
      full_name: fullName,
    })
    return response.data
  }

  async logout() {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('accessToken')
      localStorage.removeItem('refreshToken')
    }
  }

  async getCurrentUser() {
    const response = await this.client.get('/api/v1/users/me')
    return response.data
  }

  // Red Team
  async generateAttack(data: {
    technique: string
    target_model?: string
    objective?: string
  }) {
    const response = await this.client.post('/api/v1/redteam/attacks/generate', data)
    return response.data
  }

  async listAttacks(limit: number = 50, offset: number = 0) {
    const response = await this.client.get('/api/v1/redteam/attacks', {
      params: { limit, offset },
    })
    return response.data
  }

  async getAttack(attackId: string) {
    const response = await this.client.get(`/api/v1/redteam/attacks/${attackId}`)
    return response.data
  }

  // Guardrails
  async validatePrompt(data: {
    prompt: string
    system_prompt?: string
    model?: string
  }) {
    const response = await this.client.post('/api/v1/guardrails/validate', data)
    return response.data
  }

  async listPolicies() {
    const response = await this.client.get('/api/v1/guardrails/policies')
    return response.data
  }

  async getPolicy(policyId: string) {
    const response = await this.client.get(`/api/v1/guardrails/policies/${policyId}`)
    return response.data
  }

  // Scanner
  async scanCode(data: {
    code?: string
    file_path?: string
    language?: string
  }) {
    const response = await this.client.post('/api/v1/scanner/scan', data)
    return response.data
  }

  async getVulnerabilities(limit: number = 50, offset: number = 0) {
    const response = await this.client.get('/api/v1/scanner/vulnerabilities', {
      params: { limit, offset },
    })
    return response.data
  }

  async getVulnerability(vulnId: string) {
    const response = await this.client.get(`/api/v1/scanner/vulnerabilities/${vulnId}`)
    return response.data
  }

  // Threat Intelligence
  async analyzeAttackSurface(config: any) {
    const response = await this.client.post('/api/v1/threat-intel/attack-surface/analyze', config)
    return response.data
  }

  async strideThreatModel(config: any) {
    const response = await this.client.post('/api/v1/threat-intel/stride/analyze', config)
    return response.data
  }

  async owaspThreatModel(config: any) {
    const response = await this.client.post('/api/v1/threat-intel/owasp/analyze', config)
    return response.data
  }

  async comprehensiveThreatAnalysis(config: any) {
    const response = await this.client.post('/api/v1/threat-intel/comprehensive-analysis', config)
    return response.data
  }

  // Alerting
  async listAlerts(params?: {
    severity?: string
    status?: string
    limit?: number
    offset?: number
  }) {
    const response = await this.client.get('/api/v1/alerting/alerts', { params })
    return response.data
  }

  async getAlert(alertId: string) {
    const response = await this.client.get(`/api/v1/alerting/alerts/${alertId}`)
    return response.data
  }

  async updateAlertStatus(alertId: string, status: string) {
    const response = await this.client.patch(`/api/v1/alerting/alerts/${alertId}/status`, {
      status,
    })
    return response.data
  }

  // Dashboard Stats
  async getDashboardStats() {
    const response = await this.client.get('/api/v1/dashboard/stats')
    return response.data
  }

  // Generic request method
  async request<T = any>(config: AxiosRequestConfig): Promise<T> {
    const response = await this.client.request<T>(config)
    return response.data
  }
}

export const apiClient = new APIClient()
export default apiClient
