'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { RiGlobalLine, RiMapPinLine } from 'react-icons/ri'

interface ThreatLocation {
  id: string
  lat: number
  lng: number
  severity: 'critical' | 'high' | 'medium' | 'low'
  count: number
  country: string
}

const mockThreats: ThreatLocation[] = [
  { id: '1', lat: 37.7749, lng: -122.4194, severity: 'critical', count: 23, country: 'USA' },
  { id: '2', lat: 51.5074, lng: -0.1278, severity: 'high', count: 15, country: 'UK' },
  { id: '3', lat: 35.6762, lng: 139.6503, severity: 'medium', count: 8, country: 'Japan' },
  { id: '4', lat: -33.8688, lng: 151.2093, severity: 'low', count: 4, country: 'Australia' },
  { id: '5', lat: 28.6139, lng: 77.2090, severity: 'high', count: 18, country: 'India' },
  { id: '6', lat: 52.5200, lng: 13.4050, severity: 'critical', count: 31, country: 'Germany' },
]

export default function ThreatMap() {
  const [activeThreats, setActiveThreats] = useState(mockThreats)
  const [pulseKey, setPulseKey] = useState(0)

  useEffect(() => {
    const interval = setInterval(() => {
      setPulseKey(prev => prev + 1)
    }, 3000)

    return () => clearInterval(interval)
  }, [])

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return '#ff006e'
      case 'high':
        return '#ff6b35'
      case 'medium':
        return '#ffed4e'
      case 'low':
        return '#00ff41'
      default:
        return '#00fff9'
    }
  }

  return (
    <div className="glass-card p-6 h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-2">
          <RiGlobalLine className="w-5 h-5 text-neon-cyan" />
          <h2 className="text-lg font-bold text-white">Threat Map</h2>
        </div>
        <div className="text-xs text-gray-400">Live</div>
      </div>

      {/* World Map Visualization */}
      <div className="flex-1 relative bg-cyber-bg rounded-lg border border-cyber-border overflow-hidden">
        {/* Simplified world map background */}
        <div className="absolute inset-0">
          <svg className="w-full h-full opacity-20" viewBox="0 0 1000 500">
            {/* Simplified continents outlines */}
            <path
              d="M 150 150 Q 200 100, 300 120 T 450 150 L 500 200 Q 480 250, 450 280 L 350 300 Q 250 280, 200 250 Z"
              fill="none"
              stroke="#00fff9"
              strokeWidth="1"
            />
            <path
              d="M 550 100 Q 650 80, 750 120 L 800 200 Q 780 280, 700 320 L 600 300 Q 550 250, 550 200 Z"
              fill="none"
              stroke="#00fff9"
              strokeWidth="1"
            />
            <path
              d="M 100 300 Q 150 280, 250 320 L 280 400 Q 200 450, 120 420 Z"
              fill="none"
              stroke="#00fff9"
              strokeWidth="1"
            />
          </svg>

          {/* Grid overlay */}
          <div
            className="absolute inset-0 opacity-10"
            style={{
              backgroundImage: `
                linear-gradient(to right, #1a2332 1px, transparent 1px),
                linear-gradient(to bottom, #1a2332 1px, transparent 1px)
              `,
              backgroundSize: '40px 40px',
            }}
          />
        </div>

        {/* Threat Markers */}
        {activeThreats.map((threat, index) => {
          const x = ((threat.lng + 180) / 360) * 100
          const y = ((90 - threat.lat) / 180) * 100

          return (
            <motion.div
              key={`${threat.id}-${pulseKey}`}
              initial={{ scale: 0, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ delay: index * 0.1 }}
              className="absolute transform -translate-x-1/2 -translate-y-1/2 cursor-pointer group"
              style={{ left: `${x}%`, top: `${y}%` }}
            >
              {/* Pulse effect */}
              <motion.div
                className="absolute inset-0 rounded-full"
                style={{
                  backgroundColor: getSeverityColor(threat.severity),
                  boxShadow: `0 0 20px ${getSeverityColor(threat.severity)}`,
                }}
                animate={{
                  scale: [1, 2, 2.5],
                  opacity: [0.6, 0.3, 0],
                }}
                transition={{
                  duration: 2,
                  repeat: Infinity,
                  ease: 'easeOut',
                }}
              />

              {/* Marker */}
              <div
                className="w-4 h-4 rounded-full relative z-10"
                style={{
                  backgroundColor: getSeverityColor(threat.severity),
                  boxShadow: `0 0 10px ${getSeverityColor(threat.severity)}`,
                }}
              />

              {/* Tooltip */}
              <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-20">
                <div className="glass-card px-3 py-2 text-xs">
                  <div className="font-semibold">{threat.country}</div>
                  <div className="text-gray-400">
                    {threat.count} threats
                  </div>
                  <div
                    className="text-xs font-semibold uppercase"
                    style={{ color: getSeverityColor(threat.severity) }}
                  >
                    {threat.severity}
                  </div>
                </div>
              </div>
            </motion.div>
          )
        })}

        {/* Scanning line */}
        <motion.div
          className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-neon-cyan to-transparent"
          animate={{ y: [0, 500] }}
          transition={{ duration: 4, repeat: Infinity, ease: 'linear' }}
        />
      </div>

      {/* Legend */}
      <div className="mt-4 flex items-center justify-between text-xs">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-1">
            <div className="w-2 h-2 bg-threat-critical rounded-full shadow-neon-pink" />
            <span className="text-gray-400">Critical</span>
          </div>
          <div className="flex items-center space-x-1">
            <div className="w-2 h-2 bg-threat-high rounded-full shadow-neon-orange" />
            <span className="text-gray-400">High</span>
          </div>
          <div className="flex items-center space-x-1">
            <div className="w-2 h-2 bg-threat-medium rounded-full shadow-neon-yellow" />
            <span className="text-gray-400">Medium</span>
          </div>
          <div className="flex items-center space-x-1">
            <div className="w-2 h-2 bg-neon-green rounded-full shadow-neon-green" />
            <span className="text-gray-400">Low</span>
          </div>
        </div>
        <div className="text-gray-500">
          {activeThreats.reduce((sum, t) => sum + t.count, 0)} total threats
        </div>
      </div>
    </div>
  )
}
