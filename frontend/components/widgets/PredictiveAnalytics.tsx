'use client'

import { motion } from 'framer-motion'
import { RiBarChartBoxLine, RiArrowUpLine, RiArrowDownLine } from 'react-icons/ri'
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'

// Mock prediction data
const threatPredictionData = [
  { day: 'Mon', predicted: 45, actual: 42 },
  { day: 'Tue', predicted: 52, actual: 48 },
  { day: 'Wed', predicted: 48, actual: 51 },
  { day: 'Thu', predicted: 61, actual: 58 },
  { day: 'Fri', predicted: 55, actual: 52 },
  { day: 'Sat', predicted: 35, actual: 33 },
  { day: 'Sun', predicted: 38, actual: null },
]

const attackTypeDistribution = [
  { name: 'Prompt Injection', value: 45, color: '#ff006e' },
  { name: 'Jailbreak', value: 28, color: '#ff6b35' },
  { name: 'Data Leakage', value: 18, color: '#ffed4e' },
  { name: 'DoS', value: 9, color: '#00ff41' },
]

const anomalyScoreData = [
  { hour: '00:00', score: 23 },
  { hour: '04:00', score: 18 },
  { hour: '08:00', score: 45 },
  { hour: '12:00', score: 67 },
  { hour: '16:00', score: 52 },
  { hour: '20:00', score: 38 },
  { hour: '24:00', score: 29 },
]

export default function PredictiveAnalytics() {
  return (
    <div className="glass-card p-6 h-full">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl font-bold text-white mb-1">Predictive Analytics</h2>
          <p className="text-sm text-gray-400">AI-powered threat forecasting and anomaly detection</p>
        </div>
        <RiBarChartBoxLine className="w-6 h-6 text-neon-purple" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Prediction Chart */}
        <div className="lg:col-span-2">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-gray-300">7-Day Threat Forecast</h3>
            <div className="flex items-center space-x-4 text-xs">
              <div className="flex items-center space-x-1">
                <div className="w-3 h-0.5 bg-neon-purple" />
                <span className="text-gray-400">Predicted</span>
              </div>
              <div className="flex items-center space-x-1">
                <div className="w-3 h-0.5 bg-neon-cyan" />
                <span className="text-gray-400">Actual</span>
              </div>
            </div>
          </div>

          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={threatPredictionData}>
                <defs>
                  <linearGradient id="colorPredicted" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#bf00ff" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#bf00ff" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorActual" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00fff9" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#00fff9" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a2332" />
                <XAxis dataKey="day" stroke="#6b7280" style={{ fontSize: '11px' }} />
                <YAxis stroke="#6b7280" style={{ fontSize: '11px' }} />
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
                  dataKey="predicted"
                  stroke="#bf00ff"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorPredicted)"
                />
                <Area
                  type="monotone"
                  dataKey="actual"
                  stroke="#00fff9"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorActual)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Accuracy Indicator */}
          <div className="mt-4 flex items-center justify-between p-3 bg-neon-purple/5 border border-neon-purple/20 rounded-lg">
            <div>
              <span className="text-xs text-gray-400">Model Accuracy</span>
              <div className="text-lg font-bold text-neon-purple">94.2%</div>
            </div>
            <div className="flex items-center space-x-1 text-xs text-neon-green">
              <RiArrowUpLine className="w-4 h-4" />
              <span>+2.3%</span>
            </div>
          </div>
        </div>

        {/* Attack Type Distribution */}
        <div>
          <h3 className="text-sm font-semibold text-gray-300 mb-3">Attack Type Distribution</h3>
          <div className="h-48 flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={attackTypeDistribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={70}
                  paddingAngle={2}
                  dataKey="value"
                >
                  {attackTypeDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: '#0f1420',
                    border: '1px solid #1a2332',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Legend */}
          <div className="space-y-2 mt-4">
            {attackTypeDistribution.map((item) => (
              <div key={item.name} className="flex items-center justify-between text-xs">
                <div className="flex items-center space-x-2">
                  <div
                    className="w-3 h-3 rounded-sm"
                    style={{
                      backgroundColor: item.color,
                      boxShadow: `0 0 8px ${item.color}`,
                    }}
                  />
                  <span className="text-gray-300">{item.name}</span>
                </div>
                <span className="font-semibold text-white">{item.value}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Anomaly Score Timeline */}
      <div className="mt-6 pt-6 border-t border-cyber-border">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-gray-300">Anomaly Detection Score (24h)</h3>
          <div className="text-xs text-gray-400">Higher score = more anomalous behavior</div>
        </div>

        <div className="h-32">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={anomalyScoreData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1a2332" />
              <XAxis dataKey="hour" stroke="#6b7280" style={{ fontSize: '10px' }} />
              <YAxis stroke="#6b7280" style={{ fontSize: '10px' }} />
              <Tooltip
                contentStyle={{
                  background: '#0f1420',
                  border: '1px solid #1a2332',
                  borderRadius: '8px',
                  fontSize: '12px',
                }}
              />
              <Bar dataKey="score" radius={[4, 4, 0, 0]}>
                {anomalyScoreData.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={
                      entry.score > 60
                        ? '#ff006e'
                        : entry.score > 40
                        ? '#ffed4e'
                        : '#00ff41'
                    }
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  )
}
