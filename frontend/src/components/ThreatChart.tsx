import {
  LineChart,
  Line,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
  TooltipProps
} from 'recharts'
import { format } from 'date-fns'
import { AlertTriangle, Shield, Activity } from 'lucide-react'

interface ThreatDataPoint {
  timestamp: string
  threatLevel: number
  iocCount?: number
  confidence?: number
  label?: string
}

interface ThreatChartProps {
  data: ThreatDataPoint[]
  height?: number
  variant?: 'line' | 'area'
}

// Custom tooltip component
function CustomTooltip({ active, payload, label }: TooltipProps<number, string>) {
  if (!active || !payload || !payload.length) return null

  const timestamp = label as string
  const formattedDate = format(new Date(timestamp), 'MMM dd, yyyy HH:mm')
  
  const threatLevel = payload.find(p => p.dataKey === 'threatLevel')?.value || 0
  const iocCount = payload.find(p => p.dataKey === 'iocCount')?.value
  const confidence = payload.find(p => p.dataKey === 'confidence')?.value

  const getThreatColor = (level: number) => {
    if (level >= 75) return 'text-red-400'
    if (level >= 50) return 'text-orange-400'
    if (level >= 25) return 'text-yellow-400'
    return 'text-green-400'
  }

  const getThreatLabel = (level: number) => {
    if (level >= 75) return 'Critical'
    if (level >= 50) return 'High'
    if (level >= 25) return 'Medium'
    return 'Low'
  }

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-3 shadow-xl">
      <p className="text-xs text-slate-400 mb-2">{formattedDate}</p>
      
      <div className="space-y-1">
        <div className="flex items-center justify-between">
          <span className="text-sm text-slate-300">Threat Level:</span>
          <span className={`text-sm font-medium ${getThreatColor(threatLevel as number)}`}>
            {getThreatLabel(threatLevel as number)} ({threatLevel}%)
          </span>
        </div>
        
        {iocCount !== undefined && (
          <div className="flex items-center justify-between">
            <span className="text-sm text-slate-300">IOCs:</span>
            <span className="text-sm font-medium text-white">{iocCount}</span>
          </div>
        )}
        
        {confidence !== undefined && (
          <div className="flex items-center justify-between">
            <span className="text-sm text-slate-300">Confidence:</span>
            <span className="text-sm font-medium text-blue-400">{confidence}%</span>
          </div>
        )}
      </div>
    </div>
  )
}

export default function ThreatChart({ 
  data, 
  height = 300,
  variant = 'area' 
}: ThreatChartProps) {
  // Format data for chart
  const chartData = data.map(point => ({
    ...point,
    // Format timestamp for display if needed
    displayTime: format(new Date(point.timestamp), 'HH:mm')
  }))

  // Determine if we have additional data series
  const hasIocData = data.some(d => d.iocCount !== undefined)
  const hasConfidenceData = data.some(d => d.confidence !== undefined)

  const ChartComponent = variant === 'area' ? AreaChart : LineChart
  const DataComponent = variant === 'area' ? Area : Line

  return (
    <div className="w-full">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-white flex items-center">
          <Activity className="w-5 h-5 mr-2 text-blue-400" />
          Threat Timeline Analysis
        </h3>
        <div className="flex items-center space-x-4 text-xs text-slate-400">
          <div className="flex items-center">
            <div className="w-3 h-3 bg-red-500 rounded-full mr-1"></div>
            <span>Threat Level</span>
          </div>
          {hasIocData && (
            <div className="flex items-center">
              <div className="w-3 h-3 bg-orange-500 rounded-full mr-1"></div>
              <span>IOC Count</span>
            </div>
          )}
          {hasConfidenceData && (
            <div className="flex items-center">
              <div className="w-3 h-3 bg-blue-500 rounded-full mr-1"></div>
              <span>Confidence</span>
            </div>
          )}
        </div>
      </div>

      <ResponsiveContainer width="100%" height={height}>
        <ChartComponent
          data={chartData}
          margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
        >
          <CartesianGrid 
            strokeDasharray="3 3" 
            stroke="#334155" 
            vertical={false}
          />
          
          <XAxis 
            dataKey="displayTime"
            stroke="#94a3b8"
            fontSize={12}
            tickLine={false}
            axisLine={{ stroke: '#475569' }}
          />
          
          <YAxis 
            stroke="#94a3b8"
            fontSize={12}
            tickLine={false}
            axisLine={{ stroke: '#475569' }}
            domain={[0, 100]}
            ticks={[0, 25, 50, 75, 100]}
          />
          
          <Tooltip 
            content={<CustomTooltip />}
            cursor={{ stroke: '#475569', strokeWidth: 1 }}
          />
          
          <DataComponent
            type="monotone"
            dataKey="threatLevel"
            stroke="#ef4444"
            fill="#ef4444"
            fillOpacity={variant === 'area' ? 0.3 : 0}
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 6, fill: '#ef4444' }}
          />
          
          {hasIocData && (
            <DataComponent
              type="monotone"
              dataKey="iocCount"
              stroke="#f97316"
              fill="#f97316"
              fillOpacity={variant === 'area' ? 0.2 : 0}
              strokeWidth={2}
              dot={false}
              yAxisId={hasConfidenceData ? undefined : 'right'}
              activeDot={{ r: 6, fill: '#f97316' }}
            />
          )}
          
          {hasConfidenceData && (
            <DataComponent
              type="monotone"
              dataKey="confidence"
              stroke="#3b82f6"
              fill="#3b82f6"
              fillOpacity={variant === 'area' ? 0.2 : 0}
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 6, fill: '#3b82f6' }}
            />
          )}
          
          {hasIocData && !hasConfidenceData && (
            <YAxis 
              yAxisId="right"
              orientation="right"
              stroke="#94a3b8"
              fontSize={12}
              tickLine={false}
              axisLine={{ stroke: '#475569' }}
            />
          )}
        </ChartComponent>
      </ResponsiveContainer>

      {/* Threat Level Indicators */}
      <div className="mt-4 grid grid-cols-4 gap-2">
        <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-2 text-center">
          <Shield className="w-4 h-4 text-green-400 mx-auto mb-1" />
          <span className="text-xs text-green-400">Low (0-25)</span>
        </div>
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-2 text-center">
          <AlertTriangle className="w-4 h-4 text-yellow-400 mx-auto mb-1" />
          <span className="text-xs text-yellow-400">Medium (26-50)</span>
        </div>
        <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-2 text-center">
          <AlertTriangle className="w-4 h-4 text-orange-400 mx-auto mb-1" />
          <span className="text-xs text-orange-400">High (51-75)</span>
        </div>
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-2 text-center">
          <AlertTriangle className="w-4 h-4 text-red-400 mx-auto mb-1" />
          <span className="text-xs text-red-400">Critical (76-100)</span>
        </div>
      </div>
    </div>
  )
}