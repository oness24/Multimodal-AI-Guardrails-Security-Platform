'use client'

import { useState, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { RiRobotLine, RiSendPlaneLine, RiUserLine, RiSparklingLine } from 'react-icons/ri'
import { formatRelativeTime } from '@/lib/utils'

interface Message {
  id: string
  role: 'user' | 'assistant'
  content: string
  timestamp: Date
}

const initialMessages: Message[] = [
  {
    id: '1',
    role: 'assistant',
    content: 'Hello! I\'m your AI Security Assistant. I can help you analyze threats, investigate alerts, and provide security recommendations. How can I assist you today?',
    timestamp: new Date(Date.now() - 60000),
  },
]

const suggestedQuestions = [
  'What are the top threats today?',
  'Explain the latest critical alert',
  'Show me recent attack patterns',
  'Recommend security improvements',
]

export default function AIAssistant() {
  const [messages, setMessages] = useState<Message[]>(initialMessages)
  const [input, setInput] = useState('')
  const [isTyping, setIsTyping] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const handleSend = async (text?: string) => {
    const messageText = text || input
    if (!messageText.trim()) return

    // Add user message
    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      content: messageText,
      timestamp: new Date(),
    }

    setMessages(prev => [...prev, userMessage])
    setInput('')
    setIsTyping(true)

    // Simulate AI response
    setTimeout(() => {
      const responses: Record<string, string> = {
        'What are the top threats today?': 'Based on today\'s data, we detected:\n\n1. **23 Prompt Injection attempts** (Critical) - Targeting GPT-4 models\n2. **15 Rate limit violations** (High) - Potential DoS attacks\n3. **8 PII exposure incidents** (Medium) - Sensitive data in prompts\n\nRecommendation: Enable enhanced prompt sanitization and implement stricter rate limits.',
        'Explain the latest critical alert': 'The latest critical alert (2 minutes ago) detected a sophisticated prompt injection attempt with multiple evasion techniques:\n\n- Context manipulation via delimiter confusion\n- Instruction override using system prompt exploitation\n- Social engineering patterns\n\nThe guardrails blocked this attack successfully. Would you like to see the full analysis?',
        'Show me recent attack patterns': 'Recent attack patterns show an increase in:\n\n1. **Multi-stage injection attacks** (+34%)\n2. **Model behavior manipulation** (+18%)\n3. **Automated scanning attempts** (+45%)\n\nThese patterns suggest organized adversarial probing. I recommend increasing detection sensitivity.',
        'Recommend security improvements': 'Based on current threat landscape:\n\n1. **Implement context-aware filtering** for multi-turn conversations\n2. **Add behavioral anomaly detection** with ML models\n3. **Enable real-time SIEM integration** for faster incident response\n4. **Deploy honeypot prompts** to detect reconnaissance\n\nWould you like me to generate a detailed implementation plan?',
      }

      const aiMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: responses[messageText] || `I understand you're asking about "${messageText}". Let me analyze our current security data and provide relevant insights.\n\nBased on real-time monitoring, the system is operating normally with elevated threat detection. Would you like me to provide more specific information about any particular security aspect?`,
        timestamp: new Date(),
      }

      setMessages(prev => [...prev, aiMessage])
      setIsTyping(false)
    }, 1500)
  }

  return (
    <div className="glass-card p-6 h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-2">
          <div className="w-8 h-8 bg-gradient-neon rounded-full flex items-center justify-center shadow-neon-purple animate-glow">
            <RiRobotLine className="w-5 h-5 text-cyber-bg" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">AI Assistant</h2>
            <div className="flex items-center space-x-1 text-xs text-gray-400">
              <div className="w-2 h-2 bg-neon-green rounded-full animate-pulse-neon" />
              <span>Online</span>
            </div>
          </div>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-auto space-y-4 mb-4 pr-2">
        <AnimatePresence mode="popLayout">
          {messages.map((message) => (
            <motion.div
              key={message.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-[85%] ${
                  message.role === 'user'
                    ? 'bg-neon-cyan/20 border border-neon-cyan/30'
                    : 'bg-cyber-bgTertiary border border-cyber-border'
                } rounded-lg p-3`}
              >
                {/* Avatar & Name */}
                <div className="flex items-center space-x-2 mb-2">
                  {message.role === 'assistant' ? (
                    <RiRobotLine className="w-4 h-4 text-neon-purple" />
                  ) : (
                    <RiUserLine className="w-4 h-4 text-neon-cyan" />
                  )}
                  <span className="text-xs font-medium text-gray-300">
                    {message.role === 'assistant' ? 'AI Assistant' : 'You'}
                  </span>
                  <span className="text-[10px] text-gray-500">
                    {formatRelativeTime(message.timestamp)}
                  </span>
                </div>

                {/* Message Content */}
                <div className="text-sm text-gray-200 whitespace-pre-line">
                  {message.content}
                </div>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>

        {/* Typing Indicator */}
        {isTyping && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex justify-start"
          >
            <div className="bg-cyber-bgTertiary border border-cyber-border rounded-lg p-3">
              <div className="flex items-center space-x-2">
                <RiRobotLine className="w-4 h-4 text-neon-purple" />
                <div className="flex space-x-1">
                  <div className="w-2 h-2 bg-neon-purple rounded-full animate-bounce" />
                  <div className="w-2 h-2 bg-neon-purple rounded-full animate-bounce" style={{ animationDelay: '0.1s' }} />
                  <div className="w-2 h-2 bg-neon-purple rounded-full animate-bounce" style={{ animationDelay: '0.2s' }} />
                </div>
              </div>
            </div>
          </motion.div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Suggested Questions */}
      {messages.length === 1 && (
        <div className="mb-3">
          <div className="flex items-center space-x-1 mb-2">
            <RiSparklingLine className="w-3 h-3 text-neon-purple" />
            <span className="text-xs text-gray-400">Suggested questions:</span>
          </div>
          <div className="grid grid-cols-1 gap-1.5">
            {suggestedQuestions.map((question) => (
              <button
                key={question}
                onClick={() => handleSend(question)}
                className="text-left px-3 py-2 text-xs bg-cyber-bgTertiary border border-cyber-border rounded-lg text-gray-300 hover:text-neon-purple hover:border-neon-purple/30 transition-all"
              >
                {question}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Input */}
      <div className="flex items-center space-x-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && handleSend()}
          placeholder="Ask about security insights..."
          className="flex-1 px-4 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:border-neon-purple transition-all"
        />
        <button
          onClick={() => handleSend()}
          disabled={!input.trim() || isTyping}
          className="p-2 bg-neon-purple/20 border border-neon-purple/30 rounded-lg text-neon-purple hover:bg-neon-purple/30 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <RiSendPlaneLine className="w-5 h-5" />
        </button>
      </div>
    </div>
  )
}
