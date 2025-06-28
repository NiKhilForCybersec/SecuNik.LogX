import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import {
  Shield,
  AlertTriangle,
  Activity,
  FileText,
  TrendingUp,
  Clock,
  Eye,
  Code2,
  Upload,
  Search,
  Database,
  Cpu,
  HardDrive
} from 'lucide-react'
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts'
import { historyService } from '../services/historyService'
import { rulesService } from '../services/rulesService'
import { parserService } from '../services/parserService'
import { uploadService } from '../services/uploadService'

const Dashboard: React.FC = () => {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(true)
  const [stats, setStats] = useState<any>({
    totalAnalyses: 0,
    threatsFound: 0,
    activeParsers: 0,
    detectionRules: 0
  })
  const [analysisData, setAnalysisData] = useState<any[]>([])
  const [fileTypeData, setFileTypeData] = useState<any[]>([])
  const [recentAnalyses, setRecentAnalyses] = useState<any[]>([])
  const [systemHealth, setSystemHealth] = useState<any>({
    parserEngine: { status: 'operational', load: 0 },
    ruleEngine: { status: 'operational', load: 0 },
    localStorage: { status: 'operational', load: 0 }
  })

  useEffect(() => {
    loadDashboardData()
  }, [])

  const loadDashboardData = async () => {
    setLoading(true)
    try {
      // Load all data in parallel
      const [historyStats, ruleStats, parserStats, storageInfo, recentHistory] = await Promise.all([
        historyService.getHistoryStats(),
        rulesService.getRuleStats().catch(() => ({ total_rules: 0, enabled_rules: 0 })),
        parserService.getParserStatistics().catch(() => ({ parser_stats: { enabled_parsers: 0 } })),
        uploadService.listUploads({ limit: 10 }).catch(() => ({ storage_info: { used_space: 0, total_space: 0 } })),
        historyService.getHistory({ limit: 4 }).catch(() => ({ analyses: [] }))
      ])

      // Set stats
      setStats({
        totalAnalyses: historyStats?.total_analyses || 0,
        threatsFound: historyStats?.total_threats_found || 0,
        activeParsers: parserStats?.parser_stats?.enabled_parsers || 0,
        detectionRules: ruleStats?.enabled_rules || 0
      })

      // Set analysis data
      const weeklyData = historyStats?.analyses_by_day || []
      setAnalysisData(weeklyData.map((day: any) => ({
        name: new Date(day.date).toLocaleDateString('en-US', { weekday: 'short' }),
        analyses: day.count,
        threats: day.threats
      })))

      // Set file type data
      const fileTypes = historyStats?.analyses_by_file_type || []
      setFileTypeData(fileTypes.map((type: any, index: number) => {
        const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6']
        return {
          name: type.file_type,
          value: type.count,
          color: colors[index % colors.length]
        }
      }))

      // Set recent analyses
      setRecentAnalyses(recentHistory?.analyses || [])

      // Set system health
      setSystemHealth({
        parserEngine: { 
          status: parserStats?.loader_stats?.status || 'operational', 
          load: parserStats?.loader_stats?.memory_usage_percentage || 15 
        },
        ruleEngine: { 
          status: ruleStats?.engine_status || 'operational', 
          load: ruleStats?.engine_load_percentage || 8 
        },
        localStorage: { 
          status: storageInfo?.storage_info?.status || 'operational', 
          load: storageInfo?.storage_info?.usage_percentage || 24 
        }
      })
    } catch (error) {
      console.error('Error loading dashboard data:', error)
    } finally {
      setLoading(false)
    }
  }

  const quickActions = [
    {
      title: 'Upload & Analyze',
      description: 'Drag-drop files for instant analysis',
      icon: Upload,
      color: 'bg-blue-600 hover:bg-blue-700',
      action: () => navigate('/upload')
    },
    {
      title: 'Create Parser',
      description: 'Build custom log parser',
      icon: Code2,
      color: 'bg-green-600 hover:bg-green-700',
      action: () => navigate('/parsers')
    },
    {
      title: 'View Results',
      description: 'Browse analysis findings',
      icon: Search,
      color: 'bg-purple-600 hover:bg-purple-700',
      action: () => navigate('/analysis')
    }
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Forensics Dashboard</h1>
          <p className="text-slate-400 mt-2">
            Local-first digital forensics and log analysis platform
          </p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-sm text-slate-400">
            <Clock className="w-4 h-4" />
            <span>Last updated: {new Date().toLocaleTimeString()}</span>
          </div>
          <button 
            onClick={loadDashboardData}
            className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
          >
            <TrendingUp className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {quickActions.map((action, index) => {
          const Icon = action.icon
          return (
            <motion.button
              key={action.title}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              onClick={action.action}
              className={`${action.color} text-white p-6 rounded-lg transition-all duration-200 hover:scale-105 hover:shadow-lg`}
            >
              <div className="flex items-center space-x-4">
                <Icon className="w-8 h-8" />
                <div className="text-left">
                  <h3 className="font-semibold">{action.title}</h3>
                  <p className="text-sm opacity-90">{action.description}</p>
                </div>
              </div>
            </motion.button>
          )
        })}
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {[
          {
            title: 'Total Analyses',
            value: stats.totalAnalyses.toString(),
            change: '+12%',
            trend: 'up',
            icon: FileText,
            color: 'text-blue-400',
            bgColor: 'bg-blue-900/20'
          },
          {
            title: 'Threats Found',
            value: stats.threatsFound.toString(),
            change: '+5%',
            trend: 'up',
            icon: AlertTriangle,
            color: 'text-red-400',
            bgColor: 'bg-red-900/20'
          },
          {
            title: 'Active Parsers',
            value: stats.activeParsers.toString(),
            change: '+2',
            trend: 'up',
            icon: Code2,
            color: 'text-green-400',
            bgColor: 'bg-green-900/20'
          },
          {
            title: 'Detection Rules',
            value: stats.detectionRules.toString(),
            change: '+8',
            trend: 'up',
            icon: Shield,
            color: 'text-purple-400',
            bgColor: 'bg-purple-900/20'
          }
        ].map((stat, index) => {
          const Icon = stat.icon
          return (
            <motion.div
              key={stat.title}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className={`${stat.bgColor} rounded-lg p-6 border border-slate-800`}
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-slate-400">{stat.title}</p>
                  <p className="text-2xl font-bold text-white mt-1">{stat.value}</p>
                  <div className="flex items-center mt-2">
                    <TrendingUp className={`w-4 h-4 mr-1 ${
                      stat.trend === 'up' ? 'text-green-400' : 'text-red-400'
                    }`} />
                    <span className={`text-sm ${
                      stat.trend === 'up' ? 'text-green-400' : 'text-red-400'
                    }`}>
                      {stat.change}
                    </span>
                  </div>
                </div>
                <Icon className={`w-8 h-8 ${stat.color}`} />
              </div>
            </motion.div>
          )
        })}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Analysis Activity */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-slate-900/50 rounded-lg p-6 border border-slate-800"
        >
          <h3 className="text-lg font-semibold text-white mb-6">Weekly Analysis Activity</h3>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={analysisData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="name" stroke="#64748b" />
              <YAxis stroke="#64748b" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  color: '#fff'
                }}
              />
              <Area
                type="monotone"
                dataKey="analyses"
                stackId="1"
                stroke="#3b82f6"
                fill="#3b82f6"
                fillOpacity={0.3}
                name="Total Analyses"
              />
              <Area
                type="monotone"
                dataKey="threats"
                stackId="2"
                stroke="#ef4444"
                fill="#ef4444"
                fillOpacity={0.3}
                name="Threats Found"
              />
            </AreaChart>
          </ResponsiveContainer>
        </motion.div>

        {/* File Types Distribution */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-slate-900/50 rounded-lg p-6 border border-slate-800"
        >
          <h3 className="text-lg font-semibold text-white mb-6">File Types Analyzed</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={fileTypeData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={120}
                paddingAngle={5}
                dataKey="value"
              >
                {fileTypeData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  color: '#fff'
                }}
              />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </motion.div>
      </div>

      {/* Recent Activity */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="bg-slate-900/50 rounded-lg p-6 border border-slate-800"
      >
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-white">Recent Analyses</h3>
          <button
            onClick={() => navigate('/history')}
            className="text-blue-400 hover:text-blue-300 text-sm font-medium"
          >
            View All →
          </button>
        </div>
        
        <div className="space-y-4">
          {recentAnalyses.length > 0 ? (
            recentAnalyses.map((analysis) => (
              <div
                key={analysis.id}
                className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg hover:bg-slate-800/70 transition-colors cursor-pointer"
                onClick={() => navigate(`/analysis/${analysis.id}`)}
              >
                <div className="flex items-center space-x-4">
                  <FileText className="w-5 h-5 text-blue-400" />
                  <div>
                    <h4 className="text-sm font-medium text-white">{analysis.file_name}</h4>
                    <p className="text-xs text-slate-400">{analysis.file_type}</p>
                  </div>
                </div>
                <div className="flex items-center space-x-4">
                  <div className="text-right">
                    <p className={`text-sm font-medium ${
                      analysis.threat_score > 50 ? 'text-red-400' : 'text-green-400'
                    }`}>
                      {analysis.threat_score > 0 ? `${analysis.threat_score} threat score` : 'No threats'}
                    </p>
                    <p className="text-xs text-slate-400">
                      {new Date(analysis.upload_time).toLocaleDateString()}
                    </p>
                  </div>
                  <div className={`w-2 h-2 rounded-full ${
                    analysis.status === 'completed' ? 'bg-green-400' : 
                    analysis.status === 'processing' ? 'bg-yellow-400 animate-pulse' : 
                    analysis.status === 'failed' ? 'bg-red-400' : 'bg-slate-400'
                  }`}></div>
                </div>
              </div>
            ))
          ) : (
            <div className="text-center py-8">
              <FileText className="w-12 h-12 text-slate-400 mx-auto mb-4" />
              <p className="text-slate-400">No recent analyses found</p>
              <button
                onClick={() => navigate('/upload')}
                className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                Upload Your First File
              </button>
            </div>
          )}
        </div>
      </motion.div>

      {/* System Health */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="bg-slate-900/50 rounded-lg p-6 border border-slate-800"
      >
        <h3 className="text-lg font-semibold text-white mb-6">System Health</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[
            { name: 'Parser Engine', status: systemHealth.parserEngine.status, icon: Cpu, load: systemHealth.parserEngine.load, color: 'text-green-400' },
            { name: 'Rule Engine', status: systemHealth.ruleEngine.status, icon: Shield, load: systemHealth.ruleEngine.load, color: 'text-green-400' },
            { name: 'Local Storage', status: systemHealth.localStorage.status, icon: HardDrive, load: systemHealth.localStorage.load, color: 'text-blue-400' },
          ].map((service) => {
            const Icon = service.icon
            const statusColor = service.status === 'operational' ? 'bg-green-400' : 
                               service.status === 'degraded' ? 'bg-yellow-400' : 'bg-red-400'
            const statusText = service.status === 'operational' ? 'Operational' : 
                              service.status === 'degraded' ? 'Degraded' : 'Error'
            
            return (
              <div key={service.name} className="flex items-center space-x-3">
                <Icon className={`w-5 h-5 ${service.color}`} />
                <div className="flex-1">
                  <p className="text-sm font-medium text-white">{service.name}</p>
                  <div className="flex items-center space-x-2 mt-1">
                    <div className={`w-2 h-2 rounded-full ${statusColor}`}></div>
                    <span className={`text-xs ${
                      service.status === 'operational' ? 'text-green-400' : 
                      service.status === 'degraded' ? 'text-yellow-400' : 'text-red-400'
                    }`}>{statusText}</span>
                    <span className="text-xs text-slate-400">({service.load}% load)</span>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </motion.div>
    </div>
  )
}

export default Dashboard