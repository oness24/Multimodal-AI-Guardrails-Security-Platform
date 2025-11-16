'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import {
  RiSearchLine,
  RiNotification3Line,
  RiUserLine,
  RiMoonLine,
  RiSunLine,
} from 'react-icons/ri'
import type { DashboardStats } from '@/types'
import { formatNumber } from '@/lib/utils'

interface HeaderProps {
  stats: DashboardStats | null
}

export default function Header({ stats }: HeaderProps) {
  const [searchFocused, setSearchFocused] = useState(false)

  return (
    <header className="bg-cyber-bgSecondary border-b border-cyber-border sticky top-0 z-40 backdrop-blur-sm bg-cyber-bgSecondary/95">
      <div className="px-6 py-4">
        <div className="flex items-center justify-between">
          {/* Left Side - Search */}
          <div className="flex-1 max-w-xl">
            <div
              className={`relative transition-all duration-300 ${
                searchFocused ? 'shadow-neon-cyan' : ''
              }`}
            >
              <RiSearchLine className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search threats, vulnerabilities, attacks..."
                className="w-full pl-12 pr-4 py-3 bg-cyber-bg border border-cyber-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-neon-cyan transition-all duration-200"
                onFocus={() => setSearchFocused(true)}
                onBlur={() => setSearchFocused(false)}
              />
            </div>
          </div>

          {/* Right Side - Stats & Actions */}
          <div className="flex items-center space-x-6 ml-6">
            {/* Quick Stats */}
            {stats && (
              <div className="flex items-center space-x-4">
                <QuickStat
                  label="Risk Score"
                  value={stats.risk_score.toFixed(1)}
                  color="pink"
                  pulse
                />
                <QuickStat
                  label="Critical"
                  value={stats.critical_alerts.toString()}
                  color="cyan"
                />
                <QuickStat
                  label="Blocked"
                  value={formatNumber(stats.blocked_attempts)}
                  color="green"
                />
              </div>
            )}

            {/* Divider */}
            <div className="h-8 w-px bg-cyber-border" />

            {/* Notifications */}
            <button className="relative p-2 rounded-lg hover:bg-cyber-bgTertiary transition-colors group">
              <RiNotification3Line className="w-6 h-6 text-gray-300 group-hover:text-neon-cyan transition-colors" />
              <span className="absolute top-1 right-1 w-2 h-2 bg-threat-critical rounded-full animate-pulse-neon" />
            </button>

            {/* User Menu */}
            <button className="flex items-center space-x-2 px-3 py-2 rounded-lg hover:bg-cyber-bgTertiary transition-colors group">
              <div className="w-8 h-8 bg-gradient-neon rounded-full flex items-center justify-center shadow-neon-cyan">
                <RiUserLine className="w-5 h-5 text-cyber-bg" />
              </div>
              <span className="text-sm font-medium text-gray-300 group-hover:text-white">
                Security Admin
              </span>
            </button>
          </div>
        </div>
      </div>

      {/* Status Bar */}
      <div className="px-6 py-2 bg-cyber-bg/50 border-t border-cyber-border">
        <div className="flex items-center justify-between text-xs">
          <div className="flex items-center space-x-6">
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-neon-green rounded-full animate-pulse-neon" />
              <span className="text-gray-400">
                System Status: <span className="text-neon-green">Operational</span>
              </span>
            </div>
            <div className="text-gray-400">
              Last Scan: <span className="text-neon-cyan">2m ago</span>
            </div>
            <div className="text-gray-400">
              Active Sessions: <span className="text-white">3</span>
            </div>
          </div>
          <div className="text-gray-500">
            {new Date().toLocaleString('en-US', {
              weekday: 'short',
              year: 'numeric',
              month: 'short',
              day: 'numeric',
              hour: '2-digit',
              minute: '2-digit',
            })}
          </div>
        </div>
      </div>
    </header>
  )
}

interface QuickStatProps {
  label: string
  value: string
  color: 'cyan' | 'pink' | 'green' | 'yellow'
  pulse?: boolean
}

function QuickStat({ label, value, color, pulse }: QuickStatProps) {
  const colorClasses = {
    cyan: 'text-neon-cyan border-neon-cyan/30 bg-neon-cyan/5',
    pink: 'text-threat-critical border-threat-critical/30 bg-threat-critical/5',
    green: 'text-neon-green border-neon-green/30 bg-neon-green/5',
    yellow: 'text-threat-medium border-threat-medium/30 bg-threat-medium/5',
  }

  return (
    <div
      className={`px-3 py-2 rounded-lg border ${colorClasses[color]} ${
        pulse ? 'animate-pulse-neon' : ''
      }`}
    >
      <div className="text-[10px] uppercase tracking-wider text-gray-400">
        {label}
      </div>
      <div className="text-lg font-bold font-mono">{value}</div>
    </div>
  )
}
