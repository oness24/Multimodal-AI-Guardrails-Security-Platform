'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { RiFileTextLine, RiImageLine, RiVoiceprintLine, RiVideoLine, RiCheckDoubleLine, RiAlertLine } from 'react-icons/ri'
import { formatRelativeTime } from '@/lib/utils'

interface DataStream {
  id: string
  type: 'text' | 'image' | 'audio' | 'video'
  name: string
  status: 'analyzing' | 'safe' | 'threat'
  threats?: string[]
  timestamp: Date
  size: string
}

const mockStreams: DataStream[] = [
  {
    id: '1',
    type: 'text',
    name: 'User Prompt #1247',
    status: 'threat',
    threats: ['Prompt Injection', 'Social Engineering'],
    timestamp: new Date(Date.now() - 30000),
    size: '2.4 KB',
  },
  {
    id: '2',
    type: 'image',
    name: 'uploaded_image.png',
    status: 'safe',
    timestamp: new Date(Date.now() - 120000),
    size: '1.2 MB',
  },
  {
    id: '3',
    type: 'audio',
    name: 'voice_command.mp3',
    status: 'analyzing',
    timestamp: new Date(Date.now() - 15000),
    size: '456 KB',
  },
  {
    id: '4',
    type: 'text',
    name: 'API Request #523',
    status: 'safe',
    timestamp: new Date(Date.now() - 60000),
    size: '1.8 KB',
  },
]

export default function MultimodalStreams() {
  const [streams] = useState<DataStream[]>(mockStreams)
  const [filter, setFilter] = useState<'all' | 'text' | 'image' | 'audio' | 'video'>('all')

  const getIcon = (type: string) => {
    const baseClass = 'w-5 h-5'
    switch (type) {
      case 'text':
        return <RiFileTextLine className={`${baseClass} text-neon-cyan`} />
      case 'image':
        return <RiImageLine className={`${baseClass} text-neon-purple`} />
      case 'audio':
        return <RiVoiceprintLine className={`${baseClass} text-neon-green`} />
      case 'video':
        return <RiVideoLine className={`${baseClass} text-neon-pink`} />
      default:
        return <RiFileTextLine className={`${baseClass} text-gray-400`} />
    }
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'threat':
        return (
          <span className="flex items-center space-x-1 px-2 py-0.5 bg-threat-critical/20 text-threat-critical border border-threat-critical/30 rounded text-[10px] font-semibold animate-pulse-neon">
            <RiAlertLine className="w-3 h-3" />
            <span>THREAT</span>
          </span>
        )
      case 'safe':
        return (
          <span className="flex items-center space-x-1 px-2 py-0.5 bg-neon-green/20 text-neon-green border border-neon-green/30 rounded text-[10px] font-semibold">
            <RiCheckDoubleLine className="w-3 h-3" />
            <span>SAFE</span>
          </span>
        )
      case 'analyzing':
        return (
          <span className="flex items-center space-x-1 px-2 py-0.5 bg-neon-cyan/20 text-neon-cyan border border-neon-cyan/30 rounded text-[10px] font-semibold">
            <div className="w-3 h-3 border-2 border-neon-cyan border-t-transparent rounded-full animate-spin" />
            <span>ANALYZING</span>
          </span>
        )
      default:
        return null
    }
  }

  const filteredStreams = filter === 'all' ? streams : streams.filter(s => s.type === filter)

  return (
    <div className="glass-card p-6 h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-lg font-bold text-white">Multimodal Data Streams</h2>
          <p className="text-xs text-gray-400">Real-time analysis of all input types</p>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center space-x-2 mb-4">
        {(['all', 'text', 'image', 'audio', 'video'] as const).map((type) => (
          <button
            key={type}
            onClick={() => setFilter(type)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              filter === type
                ? 'bg-neon-cyan/20 text-neon-cyan border border-neon-cyan/30'
                : 'bg-cyber-bgTertiary text-gray-400 border border-cyber-border hover:text-neon-cyan'
            }`}
          >
            {type.charAt(0).toUpperCase() + type.slice(1)}
          </button>
        ))}
      </div>

      {/* Streams List */}
      <div className="flex-1 overflow-auto space-y-2">
        <AnimatePresence mode="popLayout">
          {filteredStreams.map((stream, index) => (
            <motion.div
              key={stream.id}
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 10 }}
              transition={{ delay: index * 0.05 }}
              className="p-3 rounded-lg bg-cyber-bgTertiary border border-cyber-border hover:border-cyber-borderGlow transition-all cursor-pointer group"
            >
              <div className="flex items-start space-x-3">
                {/* Icon */}
                <div className="flex-shrink-0 mt-0.5">
                  {getIcon(stream.type)}
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-start justify-between mb-1">
                    <h3 className="text-sm font-medium text-white truncate pr-2 group-hover:text-neon-cyan transition-colors">
                      {stream.name}
                    </h3>
                    {getStatusBadge(stream.status)}
                  </div>

                  {/* Threats */}
                  {stream.threats && stream.threats.length > 0 && (
                    <div className="flex flex-wrap gap-1 mb-2">
                      {stream.threats.map((threat, i) => (
                        <span
                          key={i}
                          className="px-2 py-0.5 bg-threat-critical/10 text-threat-critical text-[10px] rounded border border-threat-critical/20"
                        >
                          {threat}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Meta */}
                  <div className="flex items-center justify-between text-[10px] text-gray-500">
                    <span>{stream.size}</span>
                    <span>{formatRelativeTime(stream.timestamp)}</span>
                  </div>
                </div>
              </div>

              {/* Progress bar for analyzing */}
              {stream.status === 'analyzing' && (
                <div className="mt-2 h-0.5 bg-cyber-border rounded-full overflow-hidden">
                  <motion.div
                    className="h-full bg-neon-cyan"
                    initial={{ width: '0%' }}
                    animate={{ width: '70%' }}
                    transition={{ duration: 2, repeat: Infinity }}
                  />
                </div>
              )}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      {/* Stats */}
      <div className="mt-4 pt-4 border-t border-cyber-border grid grid-cols-3 gap-4 text-center text-xs">
        <div>
          <div className="text-2xl font-bold text-neon-cyan">
            {streams.filter(s => s.status === 'safe').length}
          </div>
          <div className="text-gray-400">Safe</div>
        </div>
        <div>
          <div className="text-2xl font-bold text-threat-critical">
            {streams.filter(s => s.status === 'threat').length}
          </div>
          <div className="text-gray-400">Threats</div>
        </div>
        <div>
          <div className="text-2xl font-bold text-neon-purple">
            {streams.filter(s => s.status === 'analyzing').length}
          </div>
          <div className="text-gray-400">Analyzing</div>
        </div>
      </div>
    </div>
  )
}
