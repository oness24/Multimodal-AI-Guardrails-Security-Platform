export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-24">
      <div className="z-10 max-w-5xl w-full items-center justify-between font-mono text-sm">
        <h1 className="text-4xl font-bold mb-4">AdversarialShield</h1>
        <p className="text-xl mb-8">
          Multimodal AI Security Testing & Guardrails Platform
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="p-6 border rounded-lg">
            <h2 className="text-2xl font-semibold mb-2">🎯 Red Team Engine</h2>
            <p>Automated adversarial attack generation and testing</p>
          </div>
          <div className="p-6 border rounded-lg">
            <h2 className="text-2xl font-semibold mb-2">🛡️ Guardrails System</h2>
            <p>Real-time detection and protection against AI attacks</p>
          </div>
          <div className="p-6 border rounded-lg">
            <h2 className="text-2xl font-semibold mb-2">🔍 Vulnerability Scanner</h2>
            <p>Static and dynamic analysis of AI applications</p>
          </div>
          <div className="p-6 border rounded-lg">
            <h2 className="text-2xl font-semibold mb-2">🧠 Threat Intelligence</h2>
            <p>Attack surface mapping and threat modeling</p>
          </div>
        </div>
      </div>
    </main>
  )
}
