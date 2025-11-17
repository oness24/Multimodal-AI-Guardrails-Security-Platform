import Link from 'next/link';

export default function Home() {
  const features = [
    {
      icon: '🎯',
      title: 'Red Team Engine',
      description: 'Generate adversarial attacks across 6 attack techniques to test AI system robustness',
      href: '/redteam',
      gradient: 'from-purple-600 to-pink-600',
      borderColor: 'border-purple-500/20 hover:border-purple-500/50',
      stats: ['6 Attack Techniques', 'Multi-Provider Support', 'Export Payloads'],
    },
    {
      icon: '🛡️',
      title: 'Guardrails System',
      description: 'Real-time threat detection, PII scanning, and policy enforcement for AI inputs and outputs',
      href: '/guardrails',
      gradient: 'from-cyan-600 to-blue-600',
      borderColor: 'border-cyan-500/20 hover:border-cyan-500/50',
      stats: ['Threat Detection', 'PII Redaction', 'Policy Compliance'],
    },
    {
      icon: '🔍',
      title: 'Vulnerability Scanner',
      description: 'Static analysis for code and prompt templates with CWE and OWASP mapping',
      href: '/scanner',
      gradient: 'from-pink-600 to-purple-600',
      borderColor: 'border-pink-500/20 hover:border-pink-500/50',
      stats: ['5 Languages', 'Prompt Analysis', 'Security Reports'],
    },
  ];

  return (
    <main className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900/20 to-gray-900">
      {/* Hero Section */}
      <div className="relative overflow-hidden">
        <div className="absolute inset-0 bg-grid-pattern opacity-10"></div>
        <div className="max-w-7xl mx-auto px-8 py-24 relative">
          <div className="text-center mb-16">
            <div className="text-6xl mb-6">🛡️</div>
            <h1 className="text-6xl font-bold mb-4 text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-pink-500 to-cyan-500">
              AdversarialShield
            </h1>
            <p className="text-2xl text-gray-300 mb-8">
              Multimodal AI Security Testing & Guardrails Platform
            </p>
            <p className="text-lg text-gray-400 max-w-3xl mx-auto">
              Comprehensive security testing platform for AI systems. Generate adversarial attacks,
              implement guardrails, and scan for vulnerabilities in your AI applications.
            </p>
          </div>

          {/* Feature Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-16">
            {features.map((feature, index) => (
              <Link
                key={index}
                href={feature.href}
                className={`group bg-gray-800/50 backdrop-blur-sm border ${feature.borderColor} rounded-lg p-8 transition-all hover:scale-105 hover:shadow-2xl`}
              >
                <div className="text-5xl mb-4">{feature.icon}</div>
                <h2 className={`text-2xl font-bold mb-3 text-transparent bg-clip-text bg-gradient-to-r ${feature.gradient}`}>
                  {feature.title}
                </h2>
                <p className="text-gray-400 mb-6">{feature.description}</p>
                <div className="space-y-2">
                  {feature.stats.map((stat, i) => (
                    <div key={i} className="flex items-center text-sm text-gray-500">
                      <span className="text-green-500 mr-2">✓</span>
                      {stat}
                    </div>
                  ))}
                </div>
                <div className={`mt-6 inline-block px-4 py-2 rounded-lg font-semibold bg-gradient-to-r ${feature.gradient} text-white group-hover:shadow-lg transition-shadow`}>
                  Launch →
                </div>
              </Link>
            ))}
          </div>

          {/* Stats Section */}
          <div className="bg-gray-800/30 backdrop-blur-sm border border-gray-700/50 rounded-lg p-8">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-8 text-center">
              <div>
                <div className="text-4xl font-bold text-purple-400 mb-2">6</div>
                <div className="text-gray-400">Attack Techniques</div>
              </div>
              <div>
                <div className="text-4xl font-bold text-cyan-400 mb-2">8+</div>
                <div className="text-gray-400">Threat Detectors</div>
              </div>
              <div>
                <div className="text-4xl font-bold text-pink-400 mb-2">5</div>
                <div className="text-gray-400">Languages Supported</div>
              </div>
              <div>
                <div className="text-4xl font-bold text-green-400 mb-2">100%</div>
                <div className="text-gray-400">Open Source</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
