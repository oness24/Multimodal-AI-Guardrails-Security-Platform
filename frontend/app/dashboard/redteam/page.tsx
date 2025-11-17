'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  RiVirusLine,
  RiPlayFill,
  RiDownloadLine,
  RiFileCopyLine,
  RiSparklingLine,
  RiShieldFlashLine,
  RiLoader4Line
} from 'react-icons/ri'
import Navigation from '@/components/dashboard/Navigation'
import Header from '@/components/dashboard/Header'
import apiClient from '@/lib/api-client'

interface AttackResult {
  id?: string
  technique: string
  payload: string
  llm_provider: string
  success: boolean
  error?: string
}

const ATTACK_TECHNIQUES = [
  { id: 'prompt_injection', name: 'Prompt Injection', description: 'Inject malicious instructions into prompts', icon: '💉' },
  { id: 'jailbreak', name: 'Jailbreak', description: 'Bypass safety guidelines and restrictions', icon: '🔓' },
  { id: 'context_manipulation', name: 'Context Manipulation', description: 'Manipulate context to override behavior', icon: '🎭' },
  { id: 'delimiter_confusion', name: 'Delimiter Confusion', description: 'Use delimiters to confuse parsing', icon: '🔀' },
  { id: 'instruction_override', name: 'Instruction Override', description: 'Override system instructions', icon: '⚡' },
  { id: 'role_playing', name: 'Role Playing Attack', description: 'Assume privileged roles', icon: '👤' },
]

const LLM_PROVIDERS = [
  { id: 'openai', name: 'OpenAI (GPT-4)' },
  { id: 'anthropic', name: 'Anthropic (Claude)' },
  { id: 'ollama', name: 'Ollama (Local)' },
]

export default function RedTeamPage() {
  const [selectedTechnique, setSelectedTechnique] = useState('prompt_injection')
  const [selectedProvider, setSelectedProvider] = useState('openai')
  const [targetContext, setTargetContext] = useState('')
  const [customObjective, setCustomObjective] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<AttackResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleGenerate = async () => {
    setLoading(true)
    setError(null)

    try {
      const response = await apiClient.generateAttack({
        technique: selectedTechnique,
        target_model: selectedProvider,
        objective: customObjective || undefined,
      })

      setResult(response)
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to generate attack. Please ensure the backend is running.')
      setResult(null)
    } finally {
      setLoading(false)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const downloadPayload = () => {
    if (!result) return

    const blob = new Blob([result.payload], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `attack_${result.technique}_${Date.now()}.txt`
    a.click()
    URL.revokeObjectURL(url)
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
              <RiVirusLine className="w-8 h-8 text-neon-pink animate-pulse-neon" />
              <h1 className="text-4xl font-bold holographic-text">Red Team Engine</h1>
            </div>
            <p className="text-gray-400">
              Generate adversarial attacks to test AI system resilience
            </p>
          </motion.div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Configuration Panel */}
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.1 }}
              className="glass-card p-6"
            >
              <h2 className="text-2xl font-bold mb-6 flex items-center gap-2">
                <RiShieldFlashLine className="text-neon-pink" />
                Attack Configuration
              </h2>

              {/* Attack Technique Selection */}
              <div className="mb-6">
                <label className="block text-sm font-medium mb-3 text-gray-300">
                  Attack Technique
                </label>
                <div className="grid grid-cols-1 gap-2">
                  {ATTACK_TECHNIQUES.map((tech) => (
                    <button
                      key={tech.id}
                      onClick={() => setSelectedTechnique(tech.id)}
                      className={`p-3 rounded-lg border transition-all text-left ${
                        selectedTechnique === tech.id
                          ? 'bg-neon-pink/20 border-neon-pink text-neon-pink'
                          : 'bg-black/30 border-gray-700 hover:border-gray-600'
                      }`}
                    >
                      <div className="flex items-start gap-3">
                        <span className="text-2xl">{tech.icon}</span>
                        <div className="flex-1">
                          <div className="font-medium">{tech.name}</div>
                          <div className="text-xs text-gray-400 mt-1">
                            {tech.description}
                          </div>
                        </div>
                      </div>
                    </button>
                  ))}
                </div>
              </div>

              {/* LLM Provider Selection */}
              <div className="mb-6">
                <label className="block text-sm font-medium mb-3 text-gray-300">
                  LLM Provider
                </label>
                <select
                  value={selectedProvider}
                  onChange={(e) => setSelectedProvider(e.target.value)}
                  className="w-full bg-black/50 border border-gray-700 rounded-lg px-4 py-3 focus:border-neon-pink focus:outline-none"
                >
                  {LLM_PROVIDERS.map((provider) => (
                    <option key={provider.id} value={provider.id}>
                      {provider.name}
                    </option>
                  ))}
                </select>
              </div>

              {/* Target Context */}
              <div className="mb-6">
                <label className="block text-sm font-medium mb-3 text-gray-300">
                  Target Context (Optional)
                </label>
                <textarea
                  value={targetContext}
                  onChange={(e) => setTargetContext(e.target.value)}
                  placeholder="Describe the target system context..."
                  className="w-full bg-black/50 border border-gray-700 rounded-lg px-4 py-3 h-24 resize-none focus:border-neon-pink focus:outline-none"
                />
              </div>

              {/* Custom Objective */}
              <div className="mb-6">
                <label className="block text-sm font-medium mb-3 text-gray-300">
                  Custom Objective (Optional)
                </label>
                <input
                  type="text"
                  value={customObjective}
                  onChange={(e) => setCustomObjective(e.target.value)}
                  placeholder="e.g., Extract sensitive information"
                  className="w-full bg-black/50 border border-gray-700 rounded-lg px-4 py-3 focus:border-neon-pink focus:outline-none"
                />
              </div>

              {/* Generate Button */}
              <button
                onClick={handleGenerate}
                disabled={loading}
                className="w-full bg-gradient-to-r from-neon-pink to-threat-high text-white font-bold py-4 rounded-lg hover:opacity-90 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <RiLoader4Line className="w-5 h-5 animate-spin" />
                    Generating Attack...
                  </>
                ) : (
                  <>
                    <RiPlayFill className="w-5 h-5" />
                    Generate Attack
                  </>
                )}
              </button>
            </motion.div>

            {/* Results Panel */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.2 }}
              className="glass-card p-6"
            >
              <h2 className="text-2xl font-bold mb-6 flex items-center gap-2">
                <RiSparklingLine className="text-neon-cyan" />
                Generated Attack
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
                    <RiVirusLine className="w-20 h-20 text-gray-600 mb-4" />
                    <p className="text-gray-500">
                      Configure attack parameters and click Generate to create an adversarial payload
                    </p>
                  </motion.div>
                )}

                {result && (
                  <motion.div
                    key={result.payload}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                  >
                    {/* Metadata */}
                    <div className="grid grid-cols-2 gap-4 mb-6">
                      <div className="bg-black/30 rounded-lg p-3 border border-gray-800">
                        <div className="text-xs text-gray-400 mb-1">Technique</div>
                        <div className="font-medium text-neon-pink">{result.technique}</div>
                      </div>
                      <div className="bg-black/30 rounded-lg p-3 border border-gray-800">
                        <div className="text-xs text-gray-400 mb-1">Provider</div>
                        <div className="font-medium text-neon-cyan">{result.llm_provider}</div>
                      </div>
                    </div>

                    {/* Payload */}
                    <div className="bg-black/50 border border-gray-700 rounded-lg p-4 mb-4">
                      <div className="flex items-center justify-between mb-3">
                        <span className="text-sm font-medium text-gray-300">Attack Payload</span>
                        <div className="flex gap-2">
                          <button
                            onClick={() => copyToClipboard(result.payload)}
                            className="text-neon-cyan hover:text-neon-cyan/80 transition-colors"
                            title="Copy to clipboard"
                          >
                            <RiFileCopyLine className="w-5 h-5" />
                          </button>
                          <button
                            onClick={downloadPayload}
                            className="text-neon-pink hover:text-neon-pink/80 transition-colors"
                            title="Download payload"
                          >
                            <RiDownloadLine className="w-5 h-5" />
                          </button>
                        </div>
                      </div>
                      <pre className="text-sm text-gray-300 whitespace-pre-wrap font-mono max-h-96 overflow-y-auto">
                        {result.payload}
                      </pre>
                    </div>

                    {/* Success Indicator */}
                    <div className={`rounded-lg p-3 ${
                      result.success
                        ? 'bg-green-500/20 border border-green-500/30 text-green-400'
                        : 'bg-threat-high/20 border border-threat-high/30 text-threat-high'
                    }`}>
                      {result.success ? '✓ Attack generated successfully' : '✗ Attack generation failed'}
                    </div>
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
