'use client'

import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import SecurityPosture from '@/components/widgets/SecurityPosture'
import ThreatMap from '@/components/widgets/ThreatMap'
import LiveAlerts from '@/components/widgets/LiveAlerts'
import MultimodalStreams from '@/components/widgets/MultimodalStreams'
import PredictiveAnalytics from '@/components/widgets/PredictiveAnalytics'
import AIAssistant from '@/components/widgets/AIAssistant'
import Navigation from '@/components/dashboard/Navigation'
import Header from '@/components/dashboard/Header'
import apiClient from '@/lib/api-client'
import type { DashboardStats, Alert } from '@/types'

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadDashboardData()

    // Set up polling for real-time updates
    const interval = setInterval(loadDashboardData, 10000) // Update every 10 seconds

    return () => clearInterval(interval)
  }, [])

  const loadDashboardData = async () => {
    try {
      // Load dashboard stats
      const dashboardStats = await apiClient.getDashboardStats().catch(() => ({
        total_scans: 1247,
        total_attacks: 523,
        total_vulnerabilities: 89,
        total_alerts: 34,
        critical_alerts: 7,
        blocked_attempts: 156,
        risk_score: 7.2,
        recent_activities: []
      }))
      setStats(dashboardStats)

      // Load recent alerts
      const alertsData = await apiClient.listAlerts({
        limit: 10,
        status: 'open'
      }).catch(() => ({ items: [] }))
      setAlerts(alertsData.items || [])

      setLoading(false)
    } catch (error) {
      console.error('Error loading dashboard data:', error)
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="inline-block w-16 h-16 border-4 border-neon-cyan border-t-transparent rounded-full animate-spin mb-4" />
          <p className="text-neon-cyan text-xl animate-pulse-neon">Loading Dashboard...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex">
      {/* Navigation Sidebar */}
      <Navigation />

      {/* Main Content */}
      <div className="flex-1 overflow-auto">
        {/* Header */}
        <Header stats={stats} />

        {/* Dashboard Grid */}
        <main className="p-6 space-y-6">
          {/* Top Row - Security Posture & Threat Map */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="grid grid-cols-1 lg:grid-cols-3 gap-6"
          >
            {/* Security Posture - 2 columns */}
            <div className="lg:col-span-2">
              <SecurityPosture stats={stats} />
            </div>

            {/* Threat Map - 1 column */}
            <div>
              <ThreatMap />
            </div>
          </motion.div>

          {/* Middle Row - Live Alerts & Multimodal Streams */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="grid grid-cols-1 lg:grid-cols-2 gap-6"
          >
            <LiveAlerts alerts={alerts} />
            <MultimodalStreams />
          </motion.div>

          {/* Bottom Row - Predictive Analytics & AI Assistant */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.4 }}
            className="grid grid-cols-1 lg:grid-cols-3 gap-6"
          >
            <div className="lg:col-span-2">
              <PredictiveAnalytics />
            </div>
            <div>
              <AIAssistant />
            </div>
          </motion.div>
        </main>
      </div>
    </div>
  )
}
