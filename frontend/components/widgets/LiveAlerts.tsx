'use client'

import { motion, AnimatePresence } from 'framer-motion'
import { RiAlertLine, RiCheckLine, RiCloseLine, RiTimeLine } from 'react-icons/ri'
import type { Alert } from '@/types'
import { formatRelativeTime, getThreatColor } from '@/lib/utils'

interface LiveAlertsProps {
  alerts: Alert[]
}

const mockAlerts: Alert[] = [
  {
    id: '1',
    severity: 'critical',
    title: 'Prompt Injection Attempt Detected',
    description: 'Multiple injection patterns detected in user input targeting GPT-4',
    status: 'open',
    source: 'Guardrails',
    detection_type: 'prompt_injection',
    timestamp: new Date(Date.now() - 120000).toISOString(),
  },
  {
    id: '2',
    severity: 'high',
    title: 'Excessive Model Requests',
    description: 'IP 192.168.1.45 exceeded rate limit: 150 requests in 60 seconds',
    status: 'investigating',
    source: 'Rate Limiter',
    detection_type: 'dos_attempt',
    timestamp: new Date(Date.now() - 300000).toISOString(),
  },
  {
    id: '3',
    severity: 'medium',
    title: 'Sensitive Data in Prompt',
    description: 'Potential PII detected in prompt (email, phone number)',
    status: 'open',
    source: 'Data Scanner',
    detection_type: 'data_leak',
    timestamp: new Date(Date.now() - 600000).toISOString(),
  },
  {
    id: '4',
    severity: 'low',
    title: 'Unusual Model Behavior',
    description: 'Model response deviated from expected pattern',
    status: 'open',
    source: 'Anomaly Detector',
    detection_type: 'anomaly',
    timestamp: new Date(Date.now() - 900000).toISOString(),
  },
]

export default function LiveAlerts({ alerts }: LiveAlertsProps) {
  const displayAlerts = alerts.length > 0 ? alerts : mockAlerts

  return (
    <div className="glass-card p-6 h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-2">
          <RiAlertLine className="w-5 h-5 text-threat-critical animate-pulse-neon" />
          <h2 className="text-lg font-bold text-white">Live Alerts</h2>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-2 h-2 bg-threat-critical rounded-full animate-pulse-neon" />
          <span className="text-xs text-gray-400">Real-time</span>
        </div>
      </div>

      {/* Alerts List */}
      <div className="flex-1 overflow-auto space-y-3">
        <AnimatePresence mode="popLayout">
          {displayAlerts.map((alert, index) => (
            <AlertCard key={alert.id} alert={alert} index={index} />
          ))}
        </AnimatePresence>
      </div>

      {/* Footer */}
      <div className="mt-4 pt-4 border-t border-cyber-border flex items-center justify-between text-xs">
        <span className="text-gray-400">
          Showing {displayAlerts.length} of {displayAlerts.length} alerts
        </span>
        <button className="text-neon-cyan hover:text-neon-cyan/80 transition-colors font-medium">
          View All →
        </button>
      </div>
    </div>
  )
}

interface AlertCardProps {
  alert: Alert
  index: number
}

function AlertCard({ alert, index }: AlertCardProps) {
  const getSeverityIcon = (severity: string) => {
    const baseClass = 'w-5 h-5'
    switch (severity) {
      case 'critical':
      case 'high':
        return <RiAlertLine className={`${baseClass} ${getThreatColor(severity)}`} />
      default:
        return <RiTimeLine className={`${baseClass} ${getThreatColor(severity)}`} />
    }
  }

  const getSeverityBorder = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'border-threat-critical/30 bg-threat-critical/5'
      case 'high':
        return 'border-threat-high/30 bg-threat-high/5'
      case 'medium':
        return 'border-threat-medium/30 bg-threat-medium/5'
      case 'low':
        return 'border-neon-green/30 bg-neon-green/5'
      default:
        return 'border-neon-cyan/30 bg-neon-cyan/5'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'resolved':
        return <RiCheckLine className="w-4 h-4 text-neon-green" />
      case 'false_positive':
        return <RiCloseLine className="w-4 h-4 text-gray-500" />
      case 'investigating':
        return <RiTimeLine className="w-4 h-4 text-neon-cyan animate-pulse" />
      default:
        return <RiAlertLine className="w-4 h-4 text-threat-critical animate-pulse-neon" />
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      transition={{ delay: index * 0.05 }}
      whileHover={{ scale: 1.01 }}
      className={`p-4 rounded-lg border ${getSeverityBorder(alert.severity)} cursor-pointer hover-glow relative overflow-hidden`}
    >
      {/* Animated scan line */}
      {alert.status === 'open' && (
        <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-current to-transparent opacity-30 animate-scan" />
      )}

      <div className="flex items-start space-x-3">
        {/* Icon */}
        <div className="flex-shrink-0 mt-0.5">
          {getSeverityIcon(alert.severity)}
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between mb-1">
            <h3 className="text-sm font-semibold text-white truncate pr-2">
              {alert.title}
            </h3>
            <div className="flex-shrink-0">{getStatusIcon(alert.status)}</div>
          </div>

          <p className="text-xs text-gray-400 line-clamp-2 mb-2">
            {alert.description}
          </p>

          <div className="flex items-center justify-between text-[10px]">
            <div className="flex items-center space-x-2">
              <span className={`px-2 py-0.5 rounded ${getSeverityBorder(alert.severity)} ${getThreatColor(alert.severity)} uppercase font-semibold`}>
                {alert.severity}
              </span>
              <span className="text-gray-500">{alert.source}</span>
            </div>
            <span className="text-gray-500">
              {formatRelativeTime(alert.timestamp)}
            </span>
          </div>
        </div>
      </div>
    </motion.div>
  )
}
