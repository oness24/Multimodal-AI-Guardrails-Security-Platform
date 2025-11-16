'use client'

import { useRouter } from 'next/navigation'
import { useEffect } from 'react'

export default function HomePage() {
  const router = useRouter()

  useEffect(() => {
    // Redirect to dashboard after brief loading
    const timer = setTimeout(() => {
      router.push('/dashboard')
    }, 1500)

    return () => clearTimeout(timer)
  }, [router])

  return (
    <div className="min-h-screen flex items-center justify-center relative overflow-hidden">
      {/* Animated background */}
      <div className="absolute inset-0">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-neon-cyan/10 rounded-full blur-3xl animate-float" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-neon-purple/10 rounded-full blur-3xl animate-float" style={{ animationDelay: '1s' }} />
        <div className="absolute top-1/2 left-1/2 w-96 h-96 bg-neon-pink/10 rounded-full blur-3xl animate-float" style={{ animationDelay: '2s' }} />
      </div>

      {/* Content */}
      <div className="text-center z-10">
        <h1 className="text-7xl font-bold holographic-text mb-6 animate-slide-down">
          AdversarialShield
        </h1>
        <p className="text-2xl text-neon-cyan animate-pulse-neon mb-8">
          Initializing Security Platform...
        </p>

        {/* Loading bar */}
        <div className="w-64 h-1 bg-cyber-border rounded-full overflow-hidden mx-auto">
          <div className="h-full bg-gradient-to-r from-neon-cyan via-neon-purple to-neon-pink animate-scan" />
        </div>
      </div>
    </div>
  )
}
