'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  RiShieldLine,
  RiShieldCheckLine,
  RiAlertLine,
  RiCheckLine,
  RiCloseLine,
  RiLoader4Line,
  RiErrorWarningLine
} from 'react-icons/ri'
import Navigation from '@/components/dashboard/Navigation'
import Header from '@/components/dashboard/Header'
import apiClient from '@/lib/api-client'

interface ProtectionResult {
  is_safe: boolean
  action: string
  sanitized_input?: string
  threats_detected: Array<{
    type: string
    severity: string
    confidence: number
    details: string
  }>
  pii_detected: Array<{
    type: string
    value: string
    location: number
  }>
  policy_violations: string[]
}

type ValidationMode = 'input' | 'output'

export default function GuardrailsPage() {
  const [mode, setMode] = useState<ValidationMode>('input')
  const [userInput, setUserInput] = useState('')
  const [modelOutput, setModelOutput] = useState('')
  const [originalInput, setOriginalInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<ProtectionResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleValidate = async () => {
    setLoading(true)
    setError(null)

    try {
      let response
      if (mode === 'input') {
        response = await apiClient.validatePrompt({
          prompt: userInput,
        })
      } else {
        if (!originalInput || !modelOutput) {
          setError('Please provide both original input and model output')
          setLoading(false)
          return
        }
        response = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/v1/guardrails/protect/output`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${typeof window !== 'undefined' ? localStorage.getItem('accessToken') : ''}`,
          },
          body: JSON.stringify({
            model_output: modelOutput,
            original_input: originalInput,
          }),
        }).then(r => r.json())
      }

      setResult(response)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Validation failed. Please ensure the backend is running.')
      setResult(null)
    } finally {
      setLoading(false)
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'text-threat-critical border-threat-critical bg-threat-critical/10'
      case 'high':
        return 'text-threat-high border-threat-high bg-threat-high/10'
      case 'medium':
        return 'text-threat-medium border-threat-medium bg-threat-medium/10'
      case 'low':
        return 'text-threat-low border-threat-low bg-threat-low/10'
      default:
        return 'text-gray-400 border-gray-600 bg-gray-600/10'
    }
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
              <RiShieldLine className="w-8 h-8 text-neon-cyan animate-glow" />
              <h1 className="text-4xl font-bold holographic-text">Guardrails System</h1>
            </div>
            <p className="text-gray-400">
              Real-time detection and protection against AI attacks
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
              onClick={() => setMode('input')}
              className={`px-6 py-3 rounded-lg font-medium transition-all ${
                mode === 'input'
                  ? 'bg-neon-cyan text-black'
                  : 'bg-black/30 border border-gray-700 hover:border-gray-600'
              }`}
            >
              Input Protection
            </button>
            <button
              onClick={() => setMode('output')}
              className={`px-6 py-3 rounded-lg font-medium transition-all ${
                mode === 'output'
                  ? 'bg-neon-cyan text-black'
                  : 'bg-black/30 border border-gray-700 hover:border-gray-600'
              }`}
            >
              Output Validation
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
                <RiShieldCheckLine className="text-neon-cyan" />
                {mode === 'input' ? 'User Input' : 'Model Input/Output'}
              </h2>

              {mode === 'input' ? (
                <div className="mb-6">
                  <label className="block text-sm font-medium mb-3 text-gray-300">
                    User Input to Validate
                  </label>
                  <textarea
                    value={userInput}
                    onChange={(e) => setUserInput(e.target.value)}
                    placeholder="Enter user input to check for threats..."
                    className="w-full bg-black/50 border border-gray-700 rounded-lg px-4 py-3 h-64 resize-none focus:border-neon-cyan focus:outline-none font-mono text-sm"
                  />
                </div>
              ) : (
                <>
                  <div className="mb-6">
                    <label className="block text-sm font-medium mb-3 text-gray-300">
                      Original User Input
                    </label>
                    <textarea
                      value={originalInput}
                      onChange={(e) => setOriginalInput(e.target.value)}
                      placeholder="Enter original user input..."
                      className="w-full bg-black/50 border border-gray-700 rounded-lg px-4 py-3 h-24 resize-none focus:border-neon-cyan focus:outline-none font-mono text-sm"
                    />
                  </div>
                  <div className="mb-6">
                    <label className="block text-sm font-medium mb-3 text-gray-300">
                      Model Output to Validate
                    </label>
                    <textarea
                      value={modelOutput}
                      onChange={(e) => setModelOutput(e.target.value)}
                      placeholder="Enter model output to check for leaks and vulnerabilities..."
                      className="w-full bg-black/50 border border-gray-700 rounded-lg px-4 py-3 h-32 resize-none focus:border-neon-cyan focus:outline-none font-mono text-sm"
                    />
                  </div>
                </>
              )}

              <button
                onClick={handleValidate}
                disabled={loading || (mode === 'input' ? !userInput : !originalInput || !modelOutput)}
                className="w-full bg-gradient-to-r from-neon-cyan to-blue-500 text-black font-bold py-4 rounded-lg hover:opacity-90 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <RiLoader4Line className="w-5 h-5 animate-spin" />
                    Validating...
                  </>
                ) : (
                  <>
                    <RiShieldCheckLine className="w-5 h-5" />
                    Validate {mode === 'input' ? 'Input' : 'Output'}
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
                <RiErrorWarningLine className="text-neon-pink" />
                Validation Results
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
                    <RiShieldLine className="w-20 h-20 text-gray-600 mb-4" />
                    <p className="text-gray-500">
                      Enter {mode === 'input' ? 'user input' : 'model output'} and click Validate to analyze for threats
                    </p>
                  </motion.div>
                )}

                {result && (
                  <motion.div
                    key={result.action}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                  >
                    {/* Safety Status */}
                    <div className={`rounded-lg p-4 mb-6 flex items-center gap-3 ${
                      result.is_safe
                        ? 'bg-green-500/20 border border-green-500/30'
                        : 'bg-threat-high/20 border border-threat-high/30'
                    }`}>
                      {result.is_safe ? (
                        <>
                          <RiCheckLine className="w-6 h-6 text-green-400" />
                          <div>
                            <div className="font-bold text-green-400">Safe</div>
                            <div className="text-sm text-gray-300">No threats detected</div>
                          </div>
                        </>
                      ) : (
                        <>
                          <RiCloseLine className="w-6 h-6 text-threat-high" />
                          <div>
                            <div className="font-bold text-threat-high">Unsafe</div>
                            <div className="text-sm text-gray-300">Action: {result.action}</div>
                          </div>
                        </>
                      )}
                    </div>

                    {/* Threats Detected */}
                    {result.threats_detected && result.threats_detected.length > 0 && (
                      <div className="mb-6">
                        <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
                          <RiAlertLine className="text-threat-high" />
                          Threats Detected ({result.threats_detected.length})
                        </h3>
                        <div className="space-y-3">
                          {result.threats_detected.map((threat, idx) => (
                            <div
                              key={idx}
                              className={`border rounded-lg p-3 ${getSeverityColor(threat.severity)}`}
                            >
                              <div className="flex items-start justify-between mb-2">
                                <span className="font-medium">{threat.type}</span>
                                <span className="text-xs px-2 py-1 rounded border">
                                  {(threat.confidence * 100).toFixed(0)}%
                                </span>
                              </div>
                              <p className="text-sm text-gray-300">{threat.details}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* PII Detected */}
                    {result.pii_detected && result.pii_detected.length > 0 && (
                      <div className="mb-6">
                        <h3 className="text-lg font-semibold mb-3">
                          PII Detected ({result.pii_detected.length})
                        </h3>
                        <div className="space-y-2">
                          {result.pii_detected.map((pii, idx) => (
                            <div
                              key={idx}
                              className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3"
                            >
                              <div className="flex items-center justify-between">
                                <span className="text-yellow-400 font-medium">{pii.type}</span>
                                <span className="text-xs text-gray-400">Position: {pii.location}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Sanitized Input */}
                    {result.sanitized_input && (
                      <div className="mb-6">
                        <h3 className="text-lg font-semibold mb-3">Sanitized Input</h3>
                        <div className="bg-black/50 border border-gray-700 rounded-lg p-4">
                          <pre className="text-sm text-gray-300 whitespace-pre-wrap font-mono">
                            {result.sanitized_input}
                          </pre>
                        </div>
                      </div>
                    )}

                    {/* Policy Violations */}
                    {result.policy_violations && result.policy_violations.length > 0 && (
                      <div>
                        <h3 className="text-lg font-semibold mb-3">Policy Violations</h3>
                        <ul className="space-y-2">
                          {result.policy_violations.map((violation, idx) => (
                            <li key={idx} className="flex items-start gap-2">
                              <RiCloseLine className="w-5 h-5 text-threat-high flex-shrink-0 mt-0.5" />
                              <span className="text-sm text-gray-300">{violation}</span>
                            </li>
                          ))}
                        </ul>
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
