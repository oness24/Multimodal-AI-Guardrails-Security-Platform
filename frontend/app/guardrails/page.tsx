'use client';

import { useState, useEffect } from 'react';
import { guardrailsAPI } from '@/lib/api';
import { getSeverityBadgeColor } from '@/lib/utils';
import type { GuardrailCheckResponse } from '@/types';

export default function GuardrailsPage() {
  const [mode, setMode] = useState<'input' | 'output'>('input');
  const [text, setText] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<GuardrailCheckResponse | null>(null);
  const [error, setError] = useState<string>('');
  const [stats, setStats] = useState<any>(null);

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    try {
      const data = await guardrailsAPI.getStats();
      setStats(data);
    } catch (err) {
      console.error('Failed to load stats:', err);
    }
  };

  const handleValidate = async () => {
    if (!text.trim()) {
      setError('Please enter text to validate');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await guardrailsAPI.validateText({
        text,
        mode,
      });
      setResult(response);
    } catch (err) {
      setError('Failed to validate text');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 0.7) return 'text-red-500';
    if (score >= 0.4) return 'text-orange-500';
    if (score >= 0.2) return 'text-yellow-500';
    return 'text-green-500';
  };

  const getRiskLabel = (score: number) => {
    if (score >= 0.7) return 'CRITICAL';
    if (score >= 0.4) return 'HIGH';
    if (score >= 0.2) return 'MEDIUM';
    return 'LOW';
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-cyan-900/20 to-gray-900 p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-600 mb-2">
            🛡️ Guardrails System
          </h1>
          <p className="text-gray-400">
            Real-time threat detection and protection against AI attacks
          </p>
        </div>

        {/* Stats Dashboard */}
        {stats && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <div className="bg-gray-800/50 backdrop-blur-sm border border-cyan-500/20 rounded-lg p-4">
              <div className="text-gray-400 text-sm mb-1">Total Checks</div>
              <div className="text-2xl font-bold text-white">{stats.total_checks.toLocaleString()}</div>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-sm border border-red-500/20 rounded-lg p-4">
              <div className="text-gray-400 text-sm mb-1">Threats Blocked</div>
              <div className="text-2xl font-bold text-red-400">{stats.threats_blocked}</div>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-sm border border-yellow-500/20 rounded-lg p-4">
              <div className="text-gray-400 text-sm mb-1">PII Redacted</div>
              <div className="text-2xl font-bold text-yellow-400">{stats.pii_redacted}</div>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-sm border border-green-500/20 rounded-lg p-4">
              <div className="text-gray-400 text-sm mb-1">Success Rate</div>
              <div className="text-2xl font-bold text-green-400">
                {(stats.success_rate * 100).toFixed(1)}%
              </div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Left Panel - Input */}
          <div className="space-y-6">
            <div className="bg-gray-800/50 backdrop-blur-sm border border-cyan-500/20 rounded-lg p-6">
              <h2 className="text-xl font-semibold text-cyan-400 mb-4">Validation Mode</h2>
              <div className="flex gap-4 mb-6">
                <button
                  onClick={() => setMode('input')}
                  className={`flex-1 py-3 px-4 rounded-lg font-semibold transition-all ${
                    mode === 'input'
                      ? 'bg-cyan-500 text-white'
                      : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  Input Protection
                </button>
                <button
                  onClick={() => setMode('output')}
                  className={`flex-1 py-3 px-4 rounded-lg font-semibold transition-all ${
                    mode === 'output'
                      ? 'bg-cyan-500 text-white'
                      : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  Output Validation
                </button>
              </div>

              <div className="mb-4">
                <div className="flex justify-between items-center mb-2">
                  <label className="block text-sm font-medium text-gray-300">
                    {mode === 'input' ? 'User Input to Validate' : 'Model Output to Validate'}
                  </label>
                  <span className="text-xs text-gray-400">{text.length} characters</span>
                </div>
                <textarea
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  placeholder={
                    mode === 'input'
                      ? 'Enter user input to check for threats, injection attempts, and PII...'
                      : 'Enter model output to validate for data leakage, PII, and policy violations...'
                  }
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyan-500 min-h-[300px] font-mono text-sm"
                />
              </div>

              <button
                onClick={handleValidate}
                disabled={loading}
                className="w-full bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-700 hover:to-blue-700 disabled:from-gray-600 disabled:to-gray-600 text-white font-semibold py-3 px-6 rounded-lg transition-all disabled:cursor-not-allowed"
              >
                {loading ? 'Validating...' : 'Run Guardrails Check'}
              </button>

              {error && (
                <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                  {error}
                </div>
              )}
            </div>
          </div>

          {/* Right Panel - Results */}
          <div className="space-y-6">
            {result && (
              <>
                {/* Risk Score */}
                <div className="bg-gray-800/50 backdrop-blur-sm border border-cyan-500/20 rounded-lg p-6">
                  <h2 className="text-xl font-semibold text-cyan-400 mb-4">Risk Assessment</h2>
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <div className="text-sm text-gray-400 mb-1">Overall Risk Score</div>
                      <div className={`text-4xl font-bold ${getRiskColor(result.risk_score)}`}>
                        {(result.risk_score * 100).toFixed(0)}%
                      </div>
                    </div>
                    <div
                      className={`px-4 py-2 rounded-lg font-semibold ${
                        result.is_safe
                          ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                          : 'bg-red-500/20 text-red-400 border border-red-500/30'
                      }`}
                    >
                      {result.is_safe ? '✓ SAFE' : '✗ UNSAFE'}
                    </div>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-3">
                    <div
                      className={`h-3 rounded-full transition-all ${
                        result.risk_score >= 0.7
                          ? 'bg-red-500'
                          : result.risk_score >= 0.4
                          ? 'bg-orange-500'
                          : result.risk_score >= 0.2
                          ? 'bg-yellow-500'
                          : 'bg-green-500'
                      }`}
                      style={{ width: `${result.risk_score * 100}%` }}
                    ></div>
                  </div>
                </div>

                {/* Threats Detected */}
                {result.threats.length > 0 && (
                  <div className="bg-gray-800/50 backdrop-blur-sm border border-cyan-500/20 rounded-lg p-6">
                    <h2 className="text-xl font-semibold text-cyan-400 mb-4">
                      Threats Detected ({result.threats.length})
                    </h2>
                    <div className="space-y-3">
                      {result.threats.map((threat, index) => (
                        <div
                          key={index}
                          className="bg-gray-900/50 border border-gray-700 rounded-lg p-4"
                        >
                          <div className="flex justify-between items-start mb-2">
                            <div className="font-semibold text-white">
                              {threat.threat_type.replace(/_/g, ' ').toUpperCase()}
                            </div>
                            <span
                              className={`text-xs px-2 py-1 rounded border ${getSeverityBadgeColor(
                                threat.severity
                              )}`}
                            >
                              {threat.severity.toUpperCase()}
                            </span>
                          </div>
                          <p className="text-sm text-gray-400 mb-2">{threat.description}</p>
                          {threat.matched_pattern && (
                            <div className="text-xs text-gray-500 font-mono">
                              Pattern: "{threat.matched_pattern}"
                            </div>
                          )}
                          <div className="mt-2 text-xs text-gray-400">
                            Confidence: {(threat.confidence * 100).toFixed(0)}%
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* PII Detected */}
                {result.pii_detected.length > 0 && (
                  <div className="bg-gray-800/50 backdrop-blur-sm border border-cyan-500/20 rounded-lg p-6">
                    <h2 className="text-xl font-semibold text-cyan-400 mb-4">
                      PII Detected ({result.pii_detected.length})
                    </h2>
                    <div className="space-y-2">
                      {result.pii_detected.map((pii, index) => (
                        <div
                          key={index}
                          className="bg-gray-900/50 border border-gray-700 rounded-lg p-3"
                        >
                          <div className="flex justify-between items-center">
                            <div>
                              <span className="text-sm font-semibold text-yellow-400">
                                {pii.pii_type.toUpperCase()}
                              </span>
                              <span className="text-xs text-gray-400 ml-2">
                                Position: {pii.start_pos}-{pii.end_pos}
                              </span>
                            </div>
                            <span className="text-xs text-gray-500">
                              {(pii.confidence * 100).toFixed(0)}% confidence
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                    {result.sanitized_text && (
                      <div className="mt-4">
                        <div className="text-sm font-medium text-gray-300 mb-2">
                          Sanitized Text:
                        </div>
                        <div className="bg-gray-900/50 border border-gray-700 rounded-lg p-3 text-sm text-gray-300 font-mono whitespace-pre-wrap">
                          {result.sanitized_text}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Policy Violations */}
                {result.policy_violations.length > 0 && (
                  <div className="bg-gray-800/50 backdrop-blur-sm border border-cyan-500/20 rounded-lg p-6">
                    <h2 className="text-xl font-semibold text-cyan-400 mb-4">
                      Policy Violations ({result.policy_violations.length})
                    </h2>
                    <div className="space-y-2">
                      {result.policy_violations.map((violation, index) => (
                        <div
                          key={index}
                          className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-red-400 text-sm"
                        >
                          {violation}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* All Clear */}
                {result.threats.length === 0 &&
                  result.pii_detected.length === 0 &&
                  result.policy_violations.length === 0 && (
                    <div className="bg-gray-800/50 backdrop-blur-sm border border-green-500/20 rounded-lg p-6">
                      <div className="text-center">
                        <div className="text-6xl mb-4">✓</div>
                        <h2 className="text-2xl font-semibold text-green-400 mb-2">All Clear!</h2>
                        <p className="text-gray-400">No threats, PII, or policy violations detected.</p>
                      </div>
                    </div>
                  )}
              </>
            )}

            {!result && (
              <div className="bg-gray-800/50 backdrop-blur-sm border border-cyan-500/20 rounded-lg p-6">
                <div className="text-center py-12">
                  <div className="text-6xl mb-4">🛡️</div>
                  <p className="text-gray-400">Enter text and run a guardrails check to see results</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
