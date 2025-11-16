'use client'

import { motion } from 'framer-motion'
import { RiShieldLine } from 'react-icons/ri'
import Navigation from '@/components/dashboard/Navigation'
import Header from '@/components/dashboard/Header'

export default function GuardrailsPage() {
  return (
    <div className="min-h-screen flex">
      <Navigation />
      <div className="flex-1 overflow-auto">
        <Header stats={null} />
        <main className="p-6">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="glass-card p-12 text-center"
          >
            <RiShieldLine className="w-20 h-20 mx-auto mb-6 text-neon-cyan animate-glow" />
            <h1 className="text-4xl font-bold holographic-text mb-4">Guardrails System</h1>
            <p className="text-xl text-gray-300 mb-8">
              Real-time detection and protection against AI attacks
            </p>
            <div className="inline-block px-6 py-3 bg-neon-cyan/20 border border-neon-cyan/30 rounded-lg text-neon-cyan">
              Coming Soon
            </div>
          </motion.div>
        </main>
      </div>
    </div>
  )
}
