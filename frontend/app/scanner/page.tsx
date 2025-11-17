'use client';

import { useState, useEffect } from 'react';
import { scannerAPI } from '@/lib/api';
import { getSeverityBadgeColor } from '@/lib/utils';
import type { CodeScanResponse, PromptScanResponse, Vulnerability } from '@/types';

export default function ScannerPage() {
  const [scanType, setScanType] = useState<'code' | 'prompt'>('code');
  const [languages, setLanguages] = useState<any[]>([]);
  const [selectedLanguage, setSelectedLanguage] = useState<string>('python');
  const [code, setCode] = useState<string>('');
  const [promptTemplate, setPromptTemplate] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [codeResult, setCodeResult] = useState<CodeScanResponse | null>(null);
  const [promptResult, setPromptResult] = useState<PromptScanResponse | null>(null);
  const [error, setError] = useState<string>('');
  const [stats, setStats] = useState<any>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [languagesData, statsData] = await Promise.all([
        scannerAPI.getLanguages(),
        scannerAPI.getStats(),
      ]);
      setLanguages(languagesData.languages);
      setStats(statsData);
    } catch (err) {
      console.error('Failed to load data:', err);
    }
  };

  const handleScanCode = async () => {
    if (!code.trim()) {
      setError('Please enter code to scan');
      return;
    }

    setLoading(true);
    setError('');
    setCodeResult(null);

    try {
      const response = await scannerAPI.scanCode({
        code,
        language: selectedLanguage,
        scan_type: 'full',
      });
      setCodeResult(response);
    } catch (err) {
      setError('Failed to scan code');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleScanPrompt = async () => {
    if (!promptTemplate.trim()) {
      setError('Please enter a prompt template to scan');
      return;
    }

    setLoading(true);
    setError('');
    setPromptResult(null);

    try {
      const response = await scannerAPI.scanPrompt({
        prompt_template: promptTemplate,
      });
      setPromptResult(response);
    } catch (err) {
      setError('Failed to scan prompt');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const renderVulnerability = (vuln: Vulnerability, index: number) => (
    <div key={index} className="bg-gray-900/50 border border-gray-700 rounded-lg p-4 hover:border-purple-500/30 transition-all">
      <div className="flex justify-between items-start mb-3">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-2">
            <h3 className="font-semibold text-white">{vuln.title}</h3>
            <span className={`text-xs px-2 py-1 rounded border ${getSeverityBadgeColor(vuln.severity)}`}>
              {vuln.severity.toUpperCase()}
            </span>
          </div>
          {vuln.line_number && (
            <div className="text-xs text-gray-400 mb-1">Line {vuln.line_number}</div>
          )}
        </div>
        <div className="text-xs text-gray-400">{(vuln.confidence * 100).toFixed(0)}% confidence</div>
      </div>

      <p className="text-sm text-gray-300 mb-3">{vuln.description}</p>

      {vuln.code_snippet && (
        <div className="mb-3">
          <div className="text-xs text-gray-400 mb-1">Code Snippet:</div>
          <pre className="bg-gray-800 border border-gray-700 rounded p-2 text-xs text-gray-300 overflow-x-auto">
            {vuln.code_snippet}
          </pre>
        </div>
      )}

      <div className="space-y-2 text-xs">
        {vuln.cwe_id && (
          <div className="flex items-center gap-2">
            <span className="text-gray-400">CWE:</span>
            <span className="bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded">{vuln.cwe_id}</span>
          </div>
        )}
        {vuln.owasp_category && (
          <div className="flex items-center gap-2">
            <span className="text-gray-400">OWASP:</span>
            <span className="bg-purple-500/20 text-purple-400 px-2 py-0.5 rounded">
              {vuln.owasp_category}
            </span>
          </div>
        )}
      </div>

      <div className="mt-3 pt-3 border-t border-gray-700">
        <div className="text-xs text-gray-400 mb-1">Remediation:</div>
        <p className="text-xs text-green-400">{vuln.remediation}</p>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900/20 to-gray-900 p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-600 mb-2">
            🔍 Vulnerability Scanner
          </h1>
          <p className="text-gray-400">
            Static analysis for code and prompt template security
          </p>
        </div>

        {/* Stats Dashboard */}
        {stats && (
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-8">
            <div className="bg-gray-800/50 backdrop-blur-sm border border-purple-500/20 rounded-lg p-4">
              <div className="text-gray-400 text-sm mb-1">Total Scans</div>
              <div className="text-2xl font-bold text-white">{stats.total_scans.toLocaleString()}</div>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-sm border border-red-500/20 rounded-lg p-4">
              <div className="text-gray-400 text-sm mb-1">Critical</div>
              <div className="text-2xl font-bold text-red-400">{stats.critical_vulnerabilities}</div>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-sm border border-orange-500/20 rounded-lg p-4">
              <div className="text-gray-400 text-sm mb-1">High</div>
              <div className="text-2xl font-bold text-orange-400">{stats.high_vulnerabilities}</div>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-sm border border-yellow-500/20 rounded-lg p-4">
              <div className="text-gray-400 text-sm mb-1">Medium</div>
              <div className="text-2xl font-bold text-yellow-400">{stats.medium_vulnerabilities}</div>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-sm border border-blue-500/20 rounded-lg p-4">
              <div className="text-gray-400 text-sm mb-1">Low</div>
              <div className="text-2xl font-bold text-blue-400">{stats.low_vulnerabilities}</div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Left Panel - Input */}
          <div className="space-y-6">
            <div className="bg-gray-800/50 backdrop-blur-sm border border-purple-500/20 rounded-lg p-6">
              <h2 className="text-xl font-semibold text-purple-400 mb-4">Scan Type</h2>
              <div className="flex gap-4 mb-6">
                <button
                  onClick={() => setScanType('code')}
                  className={`flex-1 py-3 px-4 rounded-lg font-semibold transition-all ${
                    scanType === 'code'
                      ? 'bg-purple-500 text-white'
                      : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  Code Scan
                </button>
                <button
                  onClick={() => setScanType('prompt')}
                  className={`flex-1 py-3 px-4 rounded-lg font-semibold transition-all ${
                    scanType === 'prompt'
                      ? 'bg-purple-500 text-white'
                      : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  Prompt Scan
                </button>
              </div>

              {scanType === 'code' ? (
                <>
                  <div className="mb-4">
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Programming Language
                    </label>
                    <select
                      value={selectedLanguage}
                      onChange={(e) => setSelectedLanguage(e.target.value)}
                      className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-purple-500"
                    >
                      {languages.map((lang) => (
                        <option key={lang.id} value={lang.id}>
                          {lang.name}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="mb-4">
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Code to Scan
                    </label>
                    <textarea
                      value={code}
                      onChange={(e) => setCode(e.target.value)}
                      placeholder="Paste your code here to scan for vulnerabilities..."
                      className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-purple-500 min-h-[400px] font-mono text-sm"
                    />
                  </div>

                  <button
                    onClick={handleScanCode}
                    disabled={loading}
                    className="w-full bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 disabled:from-gray-600 disabled:to-gray-600 text-white font-semibold py-3 px-6 rounded-lg transition-all disabled:cursor-not-allowed"
                  >
                    {loading ? 'Scanning...' : 'Scan Code'}
                  </button>
                </>
              ) : (
                <>
                  <div className="mb-4">
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Prompt Template
                    </label>
                    <textarea
                      value={promptTemplate}
                      onChange={(e) => setPromptTemplate(e.target.value)}
                      placeholder="Enter your prompt template to scan for security issues..."
                      className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-purple-500 min-h-[400px] font-mono text-sm"
                    />
                  </div>

                  <button
                    onClick={handleScanPrompt}
                    disabled={loading}
                    className="w-full bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 disabled:from-gray-600 disabled:to-gray-600 text-white font-semibold py-3 px-6 rounded-lg transition-all disabled:cursor-not-allowed"
                  >
                    {loading ? 'Scanning...' : 'Scan Prompt'}
                  </button>
                </>
              )}

              {error && (
                <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                  {error}
                </div>
              )}
            </div>
          </div>

          {/* Right Panel - Results */}
          <div className="space-y-6">
            {scanType === 'code' && codeResult && (
              <>
                {/* Summary */}
                <div className="bg-gray-800/50 backdrop-blur-sm border border-purple-500/20 rounded-lg p-6">
                  <h2 className="text-xl font-semibold text-purple-400 mb-4">Scan Summary</h2>
                  <div className="grid grid-cols-2 gap-4 mb-4">
                    <div>
                      <div className="text-sm text-gray-400">Language</div>
                      <div className="text-lg font-semibold text-white">{codeResult.language}</div>
                    </div>
                    <div>
                      <div className="text-sm text-gray-400">Scan Time</div>
                      <div className="text-lg font-semibold text-white">{codeResult.scan_time_ms}ms</div>
                    </div>
                  </div>
                  <div className="grid grid-cols-4 gap-2">
                    <div className="bg-red-500/10 border border-red-500/30 rounded p-2 text-center">
                      <div className="text-xl font-bold text-red-400">{codeResult.critical_count}</div>
                      <div className="text-xs text-gray-400">Critical</div>
                    </div>
                    <div className="bg-orange-500/10 border border-orange-500/30 rounded p-2 text-center">
                      <div className="text-xl font-bold text-orange-400">{codeResult.high_count}</div>
                      <div className="text-xs text-gray-400">High</div>
                    </div>
                    <div className="bg-yellow-500/10 border border-yellow-500/30 rounded p-2 text-center">
                      <div className="text-xl font-bold text-yellow-400">{codeResult.medium_count}</div>
                      <div className="text-xs text-gray-400">Medium</div>
                    </div>
                    <div className="bg-blue-500/10 border border-blue-500/30 rounded p-2 text-center">
                      <div className="text-xl font-bold text-blue-400">{codeResult.low_count}</div>
                      <div className="text-xs text-gray-400">Low</div>
                    </div>
                  </div>
                </div>

                {/* Vulnerabilities */}
                {codeResult.vulnerabilities.length > 0 ? (
                  <div className="bg-gray-800/50 backdrop-blur-sm border border-purple-500/20 rounded-lg p-6">
                    <h2 className="text-xl font-semibold text-purple-400 mb-4">
                      Vulnerabilities Found ({codeResult.total_issues})
                    </h2>
                    <div className="space-y-4 max-h-[600px] overflow-y-auto">
                      {codeResult.vulnerabilities.map((vuln, index) => renderVulnerability(vuln, index))}
                    </div>
                  </div>
                ) : (
                  <div className="bg-gray-800/50 backdrop-blur-sm border border-green-500/20 rounded-lg p-6">
                    <div className="text-center py-8">
                      <div className="text-6xl mb-4">✓</div>
                      <h2 className="text-2xl font-semibold text-green-400 mb-2">No Issues Found!</h2>
                      <p className="text-gray-400">Your code passed all security checks.</p>
                    </div>
                  </div>
                )}
              </>
            )}

            {scanType === 'prompt' && promptResult && (
              <>
                {/* Summary */}
                <div className="bg-gray-800/50 backdrop-blur-sm border border-purple-500/20 rounded-lg p-6">
                  <h2 className="text-xl font-semibold text-purple-400 mb-4">Prompt Scan Results</h2>
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <div className="text-sm text-gray-400 mb-1">Risk Score</div>
                      <div className="text-3xl font-bold text-white">
                        {(promptResult.risk_score * 100).toFixed(0)}%
                      </div>
                    </div>
                    <div
                      className={`px-4 py-2 rounded-lg font-semibold ${
                        promptResult.is_safe
                          ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                          : 'bg-red-500/20 text-red-400 border border-red-500/30'
                      }`}
                    >
                      {promptResult.is_safe ? '✓ SAFE' : '✗ UNSAFE'}
                    </div>
                  </div>
                </div>

                {/* Vulnerabilities */}
                {promptResult.vulnerabilities.length > 0 ? (
                  <div className="bg-gray-800/50 backdrop-blur-sm border border-purple-500/20 rounded-lg p-6">
                    <h2 className="text-xl font-semibold text-purple-400 mb-4">
                      Issues Found ({promptResult.total_issues})
                    </h2>
                    <div className="space-y-4 max-h-[600px] overflow-y-auto">
                      {promptResult.vulnerabilities.map((vuln, index) => renderVulnerability(vuln, index))}
                    </div>
                  </div>
                ) : (
                  <div className="bg-gray-800/50 backdrop-blur-sm border border-green-500/20 rounded-lg p-6">
                    <div className="text-center py-8">
                      <div className="text-6xl mb-4">✓</div>
                      <h2 className="text-2xl font-semibold text-green-400 mb-2">Prompt is Secure!</h2>
                      <p className="text-gray-400">No security issues detected in your prompt template.</p>
                    </div>
                  </div>
                )}
              </>
            )}

            {!codeResult && !promptResult && (
              <div className="bg-gray-800/50 backdrop-blur-sm border border-purple-500/20 rounded-lg p-6">
                <div className="text-center py-12">
                  <div className="text-6xl mb-4">🔍</div>
                  <p className="text-gray-400">
                    Enter {scanType === 'code' ? 'code' : 'a prompt template'} and run a scan to see results
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
