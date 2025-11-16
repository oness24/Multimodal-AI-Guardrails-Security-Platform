'use client'

import { motion } from 'framer-motion'
import { RiShieldCheckLine, RiAlertLine, RiVirusLine, RiBugLine } from 'react-icons/ri'
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import type { DashboardStats } from '@/types'
import { formatNumber } from '@/lib/utils'

interface SecurityPostureProps {
  stats: DashboardStats | null
}

// Mock time series data for risk score
const riskTrendData = [
  { time: '00:00', score: 6.2 },
  { time: '04:00', score: 5.8 },
  { time: '08:00', score: 7.1 },
  { time: '12:00', score: 8.3 },
  { time: '16:00', score: 7.5 },
  { time: '20:00', score: 7.2 },
  { time: '24:00', score: 7.2 },
]

// Mock detection data
const detectionData = [
  { time: '00:00', blocked: 12, allowed: 145 },
  { time: '04:00', blocked: 8, allowed: 98 },
  { time: '08:00', blocked: 23, allowed: 234 },
  { time: '12:00', blocked: 34, allowed: 312 },
  { time: '16:00', blocked: 28, allowed: 267 },
  { time: '20:00', blocked: 19, allowed: 189 },
  { time: '24:00', blocked: 15, allowed: 156 },
]

export default function SecurityPosture({ stats }: SecurityPostureProps) {
  const getRiskLevel = (score: number) => {
    if (score >= 8) return { level: 'CRITICAL', color: 'text-threat-critical', glow: 'shadow-neon-pink' }
    if (score >= 6) return { level: 'HIGH', color: 'text-threat-high', glow: 'shadow-neon-orange' }
    if (score >= 4) return { level: 'MEDIUM', color: 'text-threat-medium', glow: 'shadow-neon-yellow' }
    return { level: 'LOW', color: 'text-neon-green', glow: 'shadow-neon-green' }
  }

  const riskLevel = getRiskLevel(stats?.risk_score || 7.2)

  return (
    <div className="glass-card p-6 h-full">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-white mb-1">Security Posture</h2>
          <p className="text-sm text-gray-400">Real-time threat monitoring and risk assessment</p>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 bg-neon-green rounded-full animate-pulse-neon" />
          <span className="text-sm text-neon-green">Live</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        {/* Risk Score - Large Display */}
        <div className="md:col-span-1">
          <div className={`relative p-6 rounded-xl border-2 ${riskLevel.color} border-opacity-30 bg-gradient-to-br from-cyber-bgTertiary to-cyber-bg ${riskLevel.glow} animate-glow`}>
            <div className="text-center">
              <RiShieldCheckLine className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <div className="text-xs uppercase tracking-wider text-gray-400 mb-1">
                Risk Score
              </div>
              <div className={`text-5xl font-bold font-mono ${riskLevel.color}`}>
                {stats?.risk_score.toFixed(1) || '7.2'}
              </div>
              <div className={`text-xs mt-2 font-semibold ${riskLevel.color}`}>
                {riskLevel.level}
              </div>
            </div>

            {/* Pulse Effect */}
            <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-transparent to-white/5 animate-pulse-neon" />
          </div>
        </div>

        {/* Stats Grid */}
        <div className="md:col-span-3 grid grid-cols-3 gap-4">
          <StatCard
            icon={<RiAlertLine className="w-6 h-6" />}
            label="Critical Alerts"
            value={stats?.critical_alerts || 7}
            color="pink"
            trend="+2"
          />
          <StatCard
            icon={<RiVirusLine className="w-6 h-6" />}
            label="Attacks Blocked"
            value={stats?.blocked_attempts || 156}
            color="cyan"
            trend="+12"
          />
          <StatCard
            icon={<RiBugLine className="w-6 h-6" />}
            label="Vulnerabilities"
            value={stats?.total_vulnerabilities || 89}
            color="yellow"
            trend="-5"
            positive
          />
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Risk Trend */}
        <div>
          <h3 className="text-sm font-semibold text-gray-300 mb-3">Risk Score Trend (24h)</h3>
          <div className="h-48 -mx-2">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={riskTrendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a2332" />
                <XAxis dataKey="time" stroke="#6b7280" style={{ fontSize: '10px' }} />
                <YAxis stroke="#6b7280" domain={[0, 10]} style={{ fontSize: '10px' }} />
                <Tooltip
                  contentStyle={{
                    background: '#0f1420',
                    border: '1px solid #1a2332',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="score"
                  stroke="#ff006e"
                  strokeWidth={2}
                  dot={{ fill: '#ff006e', r: 4 }}
                  activeDot={{ r: 6, fill: '#ff006e' }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Detection Rate */}
        <div>
          <h3 className="text-sm font-semibold text-gray-300 mb-3">Detection Activity (24h)</h3>
          <div className="h-48 -mx-2">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={detectionData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a2332" />
                <XAxis dataKey="time" stroke="#6b7280" style={{ fontSize: '10px' }} />
                <YAxis stroke="#6b7280" style={{ fontSize: '10px' }} />
                <Tooltip
                  contentStyle={{
                    background: '#0f1420',
                    border: '1px solid #1a2332',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="blocked"
                  stackId="1"
                  stroke="#ff006e"
                  fill="#ff006e"
                  fillOpacity={0.6}
                />
                <Area
                  type="monotone"
                  dataKey="allowed"
                  stackId="1"
                  stroke="#00ff41"
                  fill="#00ff41"
                  fillOpacity={0.6}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  )
}

interface StatCardProps {
  icon: React.ReactNode
  label: string
  value: number
  color: 'cyan' | 'pink' | 'yellow' | 'green'
  trend?: string
  positive?: boolean
}

function StatCard({ icon, label, value, color, trend, positive }: StatCardProps) {
  const colorClasses = {
    cyan: 'text-neon-cyan border-neon-cyan/30 bg-neon-cyan/5',
    pink: 'text-threat-critical border-threat-critical/30 bg-threat-critical/5',
    yellow: 'text-threat-medium border-threat-medium/30 bg-threat-medium/5',
    green: 'text-neon-green border-neon-green/30 bg-neon-green/5',
  }

  return (
    <motion.div
      whileHover={{ scale: 1.02 }}
      className={`p-4 rounded-lg border ${colorClasses[color]} relative overflow-hidden hover-glow cursor-pointer`}
    >
      <div className="flex items-start justify-between mb-2">
        <div className={colorClasses[color]}>{icon}</div>
        {trend && (
          <span
            className={`text-xs font-semibold ${
              positive ? 'text-neon-green' : trend.startsWith('+') ? 'text-threat-critical' : 'text-neon-green'
            }`}
          >
            {trend}
          </span>
        )}
      </div>
      <div className="text-2xl font-bold font-mono mb-1">{formatNumber(value)}</div>
      <div className="text-xs text-gray-400">{label}</div>

      {/* Animated scan line */}
      <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-current to-transparent opacity-20 animate-scan" />
    </motion.div>
  )
}
