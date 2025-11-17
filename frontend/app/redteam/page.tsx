'use client';

import { useState, useEffect } from 'react';
import { redteamAPI } from '@/lib/api';
import { copyToClipboard, downloadFile, getSeverityBadgeColor } from '@/lib/utils';
import type { AttackTechnique, AttackPayload, LLMProvider } from '@/types';

export default function RedTeamPage() {
  const [techniques, setTechniques] = useState<AttackTechnique[]>([]);
  const [providers, setProviders] = useState<LLMProvider[]>([]);
  const [selectedTechnique, setSelectedTechnique] = useState<string>('');
  const [selectedProvider, setSelectedProvider] = useState<string>('openai');
  const [targetPrompt, setTargetPrompt] = useState<string>('');
  const [numVariations, setNumVariations] = useState<number>(5);
  const [loading, setLoading] = useState<boolean>(false);
  const [payloads, setPayloads] = useState<AttackPayload[]>([]);
  const [error, setError] = useState<string>('');
  const [copiedIndex, setCopiedIndex] = useState<number>(-1);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [techniquesData, providersData] = await Promise.all([
        redteamAPI.getTechniques(),
        redteamAPI.getProviders(),
      ]);
      setTechniques(techniquesData.techniques);
      setProviders(providersData.providers);
      if (techniquesData.techniques.length > 0) {
        setSelectedTechnique(techniquesData.techniques[0].id);
      }
    } catch (err) {
      setError('Failed to load data');
      console.error(err);
    }
  };

  const handleGenerate = async () => {
    if (!selectedTechnique || !targetPrompt) {
      setError('Please select a technique and enter a target prompt');
      return;
    }

    setLoading(true);
    setError('');
    setPayloads([]);

    try {
      const response = await redteamAPI.generateAttacks({
        technique: selectedTechnique,
        target_prompt: targetPrompt,
        provider: selectedProvider,
        num_variations: numVariations,
      });
      setPayloads(response.payloads);
    } catch (err) {
      setError('Failed to generate attacks');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = async (payload: string, index: number) => {
    try {
      await copyToClipboard(payload);
      setCopiedIndex(index);
      setTimeout(() => setCopiedIndex(-1), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const handleDownload = () => {
    const content = payloads.map((p, i) => `# Attack ${i + 1}\n${p.payload}`).join('\n\n---\n\n');
    downloadFile(content, `adversarial_attacks_${selectedTechnique}.txt`);
  };

  const selectedTechniqueData = techniques.find((t) => t.id === selectedTechnique);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900/20 to-gray-900 p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-600 mb-2">
            🎯 Red Team Engine
          </h1>
          <p className="text-gray-400">
            Generate adversarial attacks to test AI system robustness
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Panel - Configuration */}
          <div className="lg:col-span-1 space-y-6">
            {/* Attack Technique Selection */}
            <div className="bg-gray-800/50 backdrop-blur-sm border border-purple-500/20 rounded-lg p-6">
              <h2 className="text-xl font-semibold text-purple-400 mb-4">Attack Technique</h2>
              <div className="space-y-3">
                {techniques.map((technique) => (
                  <div
                    key={technique.id}
                    onClick={() => setSelectedTechnique(technique.id)}
                    className={`p-3 rounded-lg cursor-pointer transition-all border ${
                      selectedTechnique === technique.id
                        ? 'bg-purple-500/20 border-purple-500/50'
                        : 'bg-gray-700/30 border-gray-600/30 hover:bg-gray-700/50'
                    }`}
                  >
                    <div className="flex justify-between items-start mb-1">
                      <h3 className="font-semibold text-white text-sm">{technique.name}</h3>
                      <span
                        className={`text-xs px-2 py-0.5 rounded border ${getSeverityBadgeColor(
                          technique.severity
                        )}`}
                      >
                        {technique.severity.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-xs text-gray-400">{technique.description}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Provider Selection */}
            <div className="bg-gray-800/50 backdrop-blur-sm border border-purple-500/20 rounded-lg p-6">
              <h2 className="text-xl font-semibold text-purple-400 mb-4">LLM Provider</h2>
              <select
                value={selectedProvider}
                onChange={(e) => setSelectedProvider(e.target.value)}
                className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-purple-500"
              >
                {providers.map((provider) => (
                  <option key={provider.id} value={provider.id} disabled={!provider.supported}>
                    {provider.name} {!provider.supported && '(Not Available)'}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Right Panel - Generation */}
          <div className="lg:col-span-2 space-y-6">
            {/* Input Section */}
            <div className="bg-gray-800/50 backdrop-blur-sm border border-purple-500/20 rounded-lg p-6">
              <h2 className="text-xl font-semibold text-purple-400 mb-4">Generate Attacks</h2>

              {selectedTechniqueData && (
                <div className="mb-4 p-4 bg-purple-500/10 border border-purple-500/30 rounded-lg">
                  <p className="text-sm text-gray-300 mb-2">
                    <span className="font-semibold">Technique:</span>{' '}
                    {selectedTechniqueData.description}
                  </p>
                  <p className="text-xs text-gray-400">
                    <span className="font-semibold">Examples:</span>{' '}
                    {selectedTechniqueData.examples.join(', ')}
                  </p>
                </div>
              )}

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Target Prompt (Optional)
                  </label>
                  <textarea
                    value={targetPrompt}
                    onChange={(e) => setTargetPrompt(e.target.value)}
                    placeholder="Enter your target prompt or leave empty for generic attacks..."
                    className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-purple-500 min-h-[100px]"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Number of Variations: {numVariations}
                  </label>
                  <input
                    type="range"
                    min="1"
                    max="10"
                    value={numVariations}
                    onChange={(e) => setNumVariations(parseInt(e.target.value))}
                    className="w-full"
                  />
                </div>

                <button
                  onClick={handleGenerate}
                  disabled={loading}
                  className="w-full bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 disabled:from-gray-600 disabled:to-gray-600 text-white font-semibold py-3 px-6 rounded-lg transition-all disabled:cursor-not-allowed"
                >
                  {loading ? 'Generating...' : 'Generate Attacks'}
                </button>

                {error && (
                  <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                    {error}
                  </div>
                )}
              </div>
            </div>

            {/* Results Section */}
            {payloads.length > 0 && (
              <div className="bg-gray-800/50 backdrop-blur-sm border border-purple-500/20 rounded-lg p-6">
                <div className="flex justify-between items-center mb-4">
                  <h2 className="text-xl font-semibold text-purple-400">
                    Generated Payloads ({payloads.length})
                  </h2>
                  <button
                    onClick={handleDownload}
                    className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg text-sm transition-all"
                  >
                    Download All
                  </button>
                </div>

                <div className="space-y-3">
                  {payloads.map((payload, index) => (
                    <div
                      key={index}
                      className="bg-gray-900/50 border border-gray-700 rounded-lg p-4 hover:border-purple-500/30 transition-all"
                    >
                      <div className="flex justify-between items-start mb-2">
                        <span className="text-xs text-gray-400">Attack #{index + 1}</span>
                        <div className="flex gap-2">
                          <button
                            onClick={() => handleCopy(payload.payload, index)}
                            className="text-xs bg-gray-700 hover:bg-gray-600 text-white px-3 py-1 rounded transition-all"
                          >
                            {copiedIndex === index ? 'Copied!' : 'Copy'}
                          </button>
                        </div>
                      </div>
                      <pre className="text-sm text-gray-300 whitespace-pre-wrap font-mono">
                        {payload.payload}
                      </pre>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
