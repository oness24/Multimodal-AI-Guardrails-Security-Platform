'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  RiBugLine,
  RiCodeLine,
  RiFileTextLine,
  RiSearchLine,
  RiAlertLine,
  RiCheckLine,
  RiLoader4Line,
  RiArrowDownCircleLine
} from 'react-icons/ri'
import Navigation from '@/components/dashboard/Navigation'
import Header from '@/components/dashboard/Header'
import apiClient from '@/lib/api-client'

interface Vulnerability {
  vuln_id: string
  severity: string
  category: string
  title: string
  description: string
  location?: string
  line_number?: number
  recommendation?: string
  cwe_id?: string
  owasp_id?: string
}

interface ScanResult {
  total_vulns: number
  critical: number
  high: number
  medium: number
  low: number
  vulnerabilities: Vulnerability[]
  scan_type: string
  target: string
}

type ScanMode = 'prompt' | 'code'

export default function ScannerPage() {
  const [mode, setMode] = useState<ScanMode>('code')
  const [code, setCode] = useState('')
  const [promptTemplate, setPromptTemplate] = useState('')
  const [language, setLanguage] = useState('python')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleScan = async () => {
    setLoading(true)
    setError(null)

    try {
      let response
      if (mode === 'code') {
        response = await apiClient.scanCode({
          code,
          language,
        })
      } else {
        const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/v1/scanner/prompt`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${typeof window !== 'undefined' ? localStorage.getItem('accessToken') : ''}`,
          },
          body: JSON.stringify({
            template: promptTemplate,
            template_name: 'user_template',
          }),
        })
        response = await res.json()
      }

      setResult(response)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Scan failed. Please ensure the backend is running.')
      setResult(null)
    } finally {
      setLoading(false)
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-threat-critical/20 border-threat-critical text-threat-critical'
      case 'high':
        return 'bg-threat-high/20 border-threat-high text-threat-high'
      case 'medium':
        return 'bg-threat-medium/20 border-threat-medium text-threat-medium'
      case 'low':
        return 'bg-threat-low/20 border-threat-low text-threat-low'
      default:
        return 'bg-gray-600/20 border-gray-600 text-gray-400'
    }
  }

  const getSeverityBadge = (severity: string) => {
    const color = severity.toLowerCase()
    const textColors = {
      critical: 'text-threat-critical',
      high: 'text-threat-high',
      medium: 'text-threat-medium',
      low: 'text-threat-low',
    }
    return textColors[color as keyof typeof textColors] || 'text-gray-400'
  }

  return (
    <div className="min-h-screen flex">
      <Navigation />
      <div className="flex-1 overflow-auto">
        <Header stats={null} />
        <main className="p-6">
          {/* Header */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-8"
          >
            <div className="flex items-center gap-3 mb-2">
              <RiBugLine className="w-8 h-8 text-threat-medium animate-pulse-neon" />
              <h1 className="text-4xl font-bold holographic-text">Vulnerability Scanner</h1>
            </div>
            <p className="text-gray-400">
              Static analysis of AI code and prompt templates
            </p>
          </motion.div>

          {/* Mode Selection */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.1 }}
            className="mb-6 flex gap-4"
          >
            <button
              onClick={() => setMode('code')}
              className={`px-6 py-3 rounded-lg font-medium transition-all flex items-center gap-2 ${
                mode === 'code'
                  ? 'bg-threat-medium text-black'
                  : 'bg-black/30 border border-gray-700 hover:border-gray-600'
              }`}
            >
              <RiCodeLine className="w-5 h-5" />
              Code Scanning
            </button>
            <button
              onClick={() => setMode('prompt')}
              className={`px-6 py-3 rounded-lg font-medium transition-all flex items-center gap-2 ${
                mode === 'prompt'
                  ? 'bg-threat-medium text-black'
                  : 'bg-black/30 border border-gray-700 hover:border-gray-600'
              }`}
            >
              <RiFileTextLine className="w-5 h-5" />
              Prompt Scanning
            </button>
          </motion.div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Input Panel */}
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.2 }}
              className="glass-card p-6"
            >
              <h2 className="text-2xl font-bold mb-6 flex items-center gap-2">
                <RiSearchLine className="text-threat-medium" />
                {mode === 'code' ? 'Code to Scan' : 'Prompt Template'}
              </h2>

              {mode === 'code' ? (
                <>
                  <div className="mb-4">
                    <label className="block text-sm font-medium mb-3 text-gray-300">
                      Programming Language
                    </label>
                    <select
                      value={language}
                      onChange={(e) => setLanguage(e.target.value)}
                      className="w-full bg-black/50 border border-gray-700 rounded-lg px-4 py-3 focus:border-threat-medium focus:outline-none"
                    >
                      <option value="python">Python</option>
                      <option value="javascript">JavaScript</option>
                      <option value="typescript">TypeScript</option>
                      <option value="java">Java</option>
                      <option value="go">Go</option>
                    </select>
                  </div>
                  <div className="mb-6">
                    <label className="block text-sm font-medium mb-3 text-gray-300">
                      Source Code
                    </label>
                    <textarea
                      value={code}
                      onChange={(e) => setCode(e.target.value)}
                      placeholder={`# Example vulnerable code:\nimport openai\n\n# Hardcoded API key (VULNERABILITY)\napi_key = "sk-1234567890abcdef"\n\ndef get_response(user_input):\n    # SQL injection risk (VULNERABILITY)\n    query = f"SELECT * FROM users WHERE input = '{user_input}'"\n    \n    # Prompt injection risk (VULNERABILITY)\n    prompt = user_input\n    return openai.chat(prompt)`}
                      className="w-full bg-black/50 border border-gray-700 rounded-lg px-4 py-3 h-96 resize-none focus:border-threat-medium focus:outline-none font-mono text-sm"
                    />
                  </div>
                </>
              ) : (
                <div className="mb-6">
                  <label className="block text-sm font-medium mb-3 text-gray-300">
                    Prompt Template
                  </label>
                  <textarea
                    value={promptTemplate}
                    onChange={(e) => setPromptTemplate(e.target.value)}
                    placeholder={`Enter a prompt template to scan for vulnerabilities...\n\nExample:\nYou are a helpful assistant. Process this user request: {user_input}\n\nThe scanner will check for:\n- Prompt injection vulnerabilities\n- Missing input sanitization\n- Insufficient safety guidelines\n- PII handling issues`}
                    className="w-full bg-black/50 border border-gray-700 rounded-lg px-4 py-3 h-96 resize-none focus:border-threat-medium focus:outline-none font-mono text-sm"
                  />
                </div>
              )}

              <button
                onClick={handleScan}
                disabled={loading || (mode === 'code' ? !code : !promptTemplate)}
                className="w-full bg-gradient-to-r from-threat-medium to-orange-600 text-white font-bold py-4 rounded-lg hover:opacity-90 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <RiLoader4Line className="w-5 h-5 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <RiSearchLine className="w-5 h-5" />
                    Scan {mode === 'code' ? 'Code' : 'Prompt'}
                  </>
                )}
              </button>
            </motion.div>

            {/* Results Panel */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.3 }}
              className="glass-card p-6"
            >
              <h2 className="text-2xl font-bold mb-6 flex items-center gap-2">
                <RiAlertLine className="text-neon-pink" />
                Scan Results
              </h2>

              <AnimatePresence mode="wait">
                {error && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    className="bg-threat-high/20 border border-threat-high rounded-lg p-4 mb-4"
                  >
                    <p className="text-threat-high">{error}</p>
                  </motion.div>
                )}

                {!result && !error && !loading && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="flex flex-col items-center justify-center h-full text-center py-20"
                  >
                    <RiBugLine className="w-20 h-20 text-gray-600 mb-4" />
                    <p className="text-gray-500">
                      Enter {mode === 'code' ? 'code' : 'a prompt template'} and click Scan to analyze for vulnerabilities
                    </p>
                  </motion.div>
                )}

                {result && (
                  <motion.div
                    key={result.scan_type}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                  >
                    {/* Summary Stats */}
                    <div className="grid grid-cols-2 gap-3 mb-6">
                      <div className="bg-black/30 rounded-lg p-3 border border-gray-800">
                        <div className="text-xs text-gray-400 mb-1">Total Vulnerabilities</div>
                        <div className="text-2xl font-bold">{result.total_vulns}</div>
                      </div>
                      <div className="bg-black/30 rounded-lg p-3 border border-gray-800">
                        <div className="text-xs text-gray-400 mb-1">Scan Type</div>
                        <div className="font-medium text-threat-medium">{result.scan_type}</div>
                      </div>
                    </div>

                    {/* Severity Breakdown */}
                    <div className="mb-6">
                      <h3 className="text-sm font-semibold mb-3 text-gray-300">Severity Distribution</h3>
                      <div className="grid grid-cols-4 gap-2">
                        <div className="bg-threat-critical/20 border border-threat-critical/30 rounded-lg p-2 text-center">
                          <div className="text-xs text-gray-400">Critical</div>
                          <div className="text-xl font-bold text-threat-critical">{result.critical}</div>
                        </div>
                        <div className="bg-threat-high/20 border border-threat-high/30 rounded-lg p-2 text-center">
                          <div className="text-xs text-gray-400">High</div>
                          <div className="text-xl font-bold text-threat-high">{result.high}</div>
                        </div>
                        <div className="bg-threat-medium/20 border border-threat-medium/30 rounded-lg p-2 text-center">
                          <div className="text-xs text-gray-400">Medium</div>
                          <div className="text-xl font-bold text-threat-medium">{result.medium}</div>
                        </div>
                        <div className="bg-threat-low/20 border border-threat-low/30 rounded-lg p-2 text-center">
                          <div className="text-xs text-gray-400">Low</div>
                          <div className="text-xl font-bold text-threat-low">{result.low}</div>
                        </div>
                      </div>
                    </div>

                    {/* Vulnerabilities List */}
                    {result.vulnerabilities.length > 0 ? (
                      <div className="space-y-3 max-h-96 overflow-y-auto">
                        <h3 className="text-sm font-semibold mb-3 text-gray-300 sticky top-0 bg-gray-900/95 py-2">
                          Vulnerabilities ({result.vulnerabilities.length})
                        </h3>
                        {result.vulnerabilities.map((vuln, idx) => (
                          <div
                            key={vuln.vuln_id}
                            className={`border rounded-lg p-4 ${getSeverityColor(vuln.severity)}`}
                          >
                            <div className="flex items-start justify-between mb-2">
                              <div className="flex-1">
                                <div className="font-medium mb-1">{vuln.title}</div>
                                {vuln.line_number && (
                                  <div className="text-xs text-gray-400">Line {vuln.line_number}</div>
                                )}
                              </div>
                              <span className={`text-xs px-2 py-1 rounded border font-medium ${getSeverityBadge(vuln.severity)}`}>
                                {vuln.severity.toUpperCase()}
                              </span>
                            </div>
                            <p className="text-sm mb-2">{vuln.description}</p>
                            {vuln.recommendation && (
                              <div className="mt-2 pt-2 border-t border-current/20">
                                <div className="text-xs font-medium mb-1">Recommendation:</div>
                                <p className="text-xs opacity-80">{vuln.recommendation}</p>
                              </div>
                            )}
                            {(vuln.cwe_id || vuln.owasp_id) && (
                              <div className="flex gap-2 mt-2">
                                {vuln.cwe_id && (
                                  <span className="text-xs px-2 py-1 bg-black/30 rounded">{vuln.cwe_id}</span>
                                )}
                                {vuln.owasp_id && (
                                  <span className="text-xs px-2 py-1 bg-black/30 rounded">{vuln.owasp_id}</span>
                                )}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="bg-green-500/20 border border-green-500/30 rounded-lg p-4 flex items-center gap-3">
                        <RiCheckLine className="w-6 h-6 text-green-400" />
                        <div>
                          <div className="font-bold text-green-400">No Vulnerabilities Found</div>
                          <div className="text-sm text-gray-300">Code appears secure</div>
                        </div>
                      </div>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          </div>
        </main>
      </div>
    </div>
  )
}
