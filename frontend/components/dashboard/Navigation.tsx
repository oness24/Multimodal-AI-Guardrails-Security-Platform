'use client'

import { useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { motion } from 'framer-motion'
import {
  RiDashboardLine,
  RiShieldLine,
  RiVirusLine,
  RiRadarLine,
  RiBugLine,
  RiAlarmLine,
  RiSettings3Line,
  RiMenuFoldLine,
  RiMenuUnfoldLine,
} from 'react-icons/ri'
import { cn } from '@/lib/utils'

interface NavItem {
  name: string
  href: string
  icon: React.ComponentType<{ className?: string }>
  badge?: number
}

const navItems: NavItem[] = [
  { name: 'Dashboard', href: '/dashboard', icon: RiDashboardLine },
  { name: 'Red Team', href: '/dashboard/redteam', icon: RiVirusLine },
  { name: 'Guardrails', href: '/dashboard/guardrails', icon: RiShieldLine },
  { name: 'Scanner', href: '/dashboard/scanner', icon: RiBugLine },
  { name: 'Threat Intel', href: '/dashboard/threat-intel', icon: RiRadarLine },
  { name: 'Alerts', href: '/dashboard/alerts', icon: RiAlarmLine, badge: 7 },
  { name: 'Settings', href: '/dashboard/settings', icon: RiSettings3Line },
]

export default function Navigation() {
  const [collapsed, setCollapsed] = useState(false)
  const pathname = usePathname()

  return (
    <motion.nav
      initial={{ x: -280 }}
      animate={{ x: 0, width: collapsed ? 80 : 280 }}
      transition={{ duration: 0.3 }}
      className="bg-cyber-bgSecondary border-r border-cyber-border flex flex-col relative"
    >
      {/* Logo */}
      <div className="p-6 border-b border-cyber-border">
        <Link href="/dashboard" className="block">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 bg-gradient-neon rounded-lg flex items-center justify-center shadow-neon-cyan animate-glow">
              <RiShieldLine className="w-6 h-6 text-cyber-bg" />
            </div>
            {!collapsed && (
              <div className="overflow-hidden">
                <h1 className="text-xl font-bold holographic-text whitespace-nowrap">
                  AdversarialShield
                </h1>
                <p className="text-xs text-gray-400">AI Security Platform</p>
              </div>
            )}
          </div>
        </Link>
      </div>

      {/* Navigation Items */}
      <div className="flex-1 py-6 overflow-y-auto">
        <ul className="space-y-2 px-3">
          {navItems.map((item) => {
            const Icon = item.icon
            const isActive = pathname === item.href

            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  className={cn(
                    'flex items-center space-x-3 px-4 py-3 rounded-lg transition-all duration-200 relative group',
                    isActive
                      ? 'bg-neon-cyan/10 border border-neon-cyan/30 text-neon-cyan shadow-neon-cyan'
                      : 'hover:bg-cyber-bgTertiary text-gray-300 hover:text-neon-cyan'
                  )}
                >
                  {/* Active indicator */}
                  {isActive && (
                    <motion.div
                      layoutId="activeNav"
                      className="absolute left-0 top-0 bottom-0 w-1 bg-neon-cyan shadow-neon-cyan rounded-r"
                      transition={{ type: 'spring', stiffness: 300, damping: 30 }}
                    />
                  )}

                  <Icon
                    className={cn(
                      'w-5 h-5 flex-shrink-0',
                      isActive && 'animate-pulse-neon'
                    )}
                  />

                  {!collapsed && (
                    <>
                      <span className="flex-1 font-medium">{item.name}</span>
                      {item.badge && (
                        <span className="px-2 py-1 text-xs bg-threat-critical/20 text-threat-critical border border-threat-critical/30 rounded-full animate-pulse-neon">
                          {item.badge}
                        </span>
                      )}
                    </>
                  )}

                  {/* Tooltip for collapsed state */}
                  {collapsed && (
                    <div className="absolute left-full ml-6 px-3 py-2 bg-cyber-bgTertiary border border-cyber-border rounded-lg shadow-holographic opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-50">
                      {item.name}
                      {item.badge && (
                        <span className="ml-2 px-2 py-1 text-xs bg-threat-critical/20 text-threat-critical rounded-full">
                          {item.badge}
                        </span>
                      )}
                    </div>
                  )}
                </Link>
              </li>
            )
          })}
        </ul>
      </div>

      {/* Collapse Toggle */}
      <div className="p-3 border-t border-cyber-border">
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="w-full flex items-center justify-center px-4 py-3 rounded-lg bg-cyber-bgTertiary hover:bg-neon-cyan/10 border border-cyber-border hover:border-neon-cyan/30 text-gray-300 hover:text-neon-cyan transition-all duration-200 group"
        >
          {collapsed ? (
            <RiMenuUnfoldLine className="w-5 h-5" />
          ) : (
            <>
              <RiMenuFoldLine className="w-5 h-5" />
              <span className="ml-2 font-medium">Collapse</span>
            </>
          )}
        </button>
      </div>

      {/* Version Info */}
      {!collapsed && (
        <div className="p-4 border-t border-cyber-border bg-cyber-bg/50">
          <div className="text-xs text-gray-500 space-y-1">
            <div className="flex justify-between">
              <span>Version</span>
              <span className="text-neon-cyan">v0.1.0</span>
            </div>
            <div className="flex justify-between">
              <span>Status</span>
              <span className="flex items-center">
                <span className="w-2 h-2 bg-neon-green rounded-full mr-1 animate-pulse-neon" />
                <span className="text-neon-green">Online</span>
              </span>
            </div>
          </div>
        </div>
      )}
    </motion.nav>
  )
}
