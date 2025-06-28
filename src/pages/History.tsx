import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import {
  Search,
  Filter,
  Download,
  Eye,
  Trash2,
  Calendar,
  FileText,
  AlertTriangle,
  Clock,
  CheckCircle,
  XCircle,
  RefreshCw,
  BarChart3,
  Star,
  Tag
} from 'lucide-react'
import { historyService } from '../services/historyService'
import { formatDate, formatFileSize } from '../utils/formatters'
import toast from 'react-hot-toast'

const History: React.FC = () => {
  const navigate = useNavigate()
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [historyData, setHistoryData] = useState<any[]>([])
  const [stats, setStats] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [pagination, setPagination] = useState({
    limit: 20,
    offset: 0,
    total: 0
  })

  useEffect(() => {
    loadHistoryData()
    loadStats()
  }, [])

  useEffect(() => {
    loadHistoryData()
  }, [statusFilter, severityFilter, pagination.offset])

  const loadHistoryData = async () => {
    try {
      setLoading(true)
      
      const params: any = {
        limit: pagination.limit,
        offset: pagination.offset
      }
      
      if (statusFilter !== 'all') params.status = statusFilter
      if (severityFilter !== 'all') params.severity = severityFilter
      if (searchTerm) params.search = searchTerm
      
      const response = await historyService.getHistory(params)
      
      setHistoryData(response.analyses || [])
      setPagination(prev => ({
        ...prev,
        total: response.total || 0
      }))
    } catch (error: any) {
      console.error('Failed to load history:', error)
      toast.error('Failed to load analysis history')
    } finally {
      setLoading(false)
    }
  }

  const loadStats = async () => {
    try {
      const statsData = await historyService.getHistoryStats()
      setStats(statsData)
    } catch (error: any) {
      console.error('Failed to load stats:', error)
    }
  }

  const deleteAnalysis = async (analysisId: string) => {
    if (!confirm('Are you sure you want to delete this analysis?')) return
    
    try {
      await historyService.deleteAnalysis(analysisId)
      toast.success('Analysis deleted successfully')
      loadHistoryData()
    } catch (error: any) {
      console.error('Failed to delete analysis:', error)
      toast.error('Failed to delete analysis')
    }
  }

  const exportHistory = async () => {
    try {
      const data = await historyService.exportHistory('json')
      
      // Create download link
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `analysis_history_${new Date().toISOString().split('T')[0]}.json`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)
      
      toast.success('History exported successfully')
    } catch (error: any) {
      console.error('Export failed:', error)
      toast.error('Failed to export history')
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-400" />
      case 'processing':
      case 'analyzing':
        return <Clock className="w-5 h-5 text-yellow-400 animate-spin" />
      case 'failed':
        return <XCircle className="w-5 h-5 text-red-400" />
      default:
        return <Clock className="w-5 h-5 text-slate-400" />
    }
  }

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'critical':
        return 'text-red-400 bg-red-900/30'
      case 'high':
        return 'text-orange-400 bg-orange-900/30'
      case 'medium':
        return 'text-yellow-400 bg-yellow-900/30'
      case 'low':
        return 'text-green-400 bg-green-900/30'
      default:
        return 'text-slate-400 bg-slate-900/30'
    }
  }

  const filteredData = historyData.filter(item => {
    const matchesSearch = searchTerm === '' || 
                         item.file_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         item.id?.toLowerCase().includes(searchTerm.toLowerCase())
    return matchesSearch
  })

  const statsData = stats ? [
    {
      title: 'Total Analyses',
      value: stats.total_analyses?.toString() || '0',
      icon: FileText,
      color: 'text-blue-400'
    },
    {
      title: 'Completed',
      value: stats.by_status?.completed?.toString() || '0',
      icon: CheckCircle,
      color: 'text-green-400'
    },
    {
      title: 'High Risk Files',
      value: stats.by_severity ? (stats.by_severity.high + stats.by_severity.critical).toString() : '0',
      icon: AlertTriangle,
      color: 'text-red-400'
    },
    {
      title: 'Total Threats',
      value: stats.total_threats_found?.toString() || '0',
      icon: Eye,
      color: 'text-yellow-400'
    }
  ] : []

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Analysis History</h1>
          <p className="text-slate-400 mt-2">
            View and manage your forensic analysis history and results
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <button 
            onClick={loadHistoryData}
            className="flex items-center space-x-2 px-4 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Refresh</span>
          </button>
          <button 
            onClick={exportHistory}
            className="flex items-center space-x-2 px-4 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors"
          >
            <Download className="w-4 h-4" />
            <span>Export History</span>
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {statsData.map((stat, index) => {
          const Icon = stat.icon
          return (
            <motion.div
              key={stat.title}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className="bg-slate-900/50 rounded-lg p-6 border border-slate-800"
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-slate-400">{stat.title}</p>
                  <p className="text-2xl font-bold text-white mt-1">{stat.value}</p>
                </div>
                <Icon className={`w-8 h-8 ${stat.color}`} />
              </div>
            </motion.div>
          )
        })}
      </div>

      {/* Filters */}
      <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-800">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="flex items-center space-x-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                type="text"
                placeholder="Search analyses..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent w-64"
              />
            </div>
            
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="all">All Threat Levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="all">All Statuses</option>
              <option value="completed">Completed</option>
              <option value="processing">Processing</option>
              <option value="failed">Failed</option>
            </select>
          </div>
          
          <div className="flex items-center space-x-2">
            <Calendar className="w-4 h-4 text-slate-400" />
            <span className="text-sm text-slate-400">Showing last 30 days</span>
          </div>
        </div>
      </div>

      {/* History Table */}
      <div className="bg-slate-900/50 rounded-lg border border-slate-800 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700 bg-slate-800/50">
                  <th className="px-6 py-4 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    File
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Threat Level
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Threat Score
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    IOCs
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Duration
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Date
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {filteredData.map((item, index) => (
                  <motion.tr
                    key={item.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className="hover:bg-slate-800/50 transition-colors"
                  >
                    <td className="px-6 py-4">
                      <div>
                        <div className="text-sm font-medium text-white">{item.file_name}</div>
                        <div className="text-sm text-slate-400">ID: {item.id}</div>
                        {item.tags && item.tags.length > 0 && (
                          <div className="flex items-center space-x-1 mt-1">
                            {item.tags.slice(0, 2).map((tag: string) => (
                              <span key={tag} className="px-2 py-1 bg-blue-900/30 text-blue-300 text-xs rounded">
                                {tag}
                              </span>
                            ))}
                            {item.tags.length > 2 && (
                              <span className="text-xs text-slate-400">+{item.tags.length - 2}</span>
                            )}
                          </div>
                        )}
                      </div>
                    </td>
                    
                    <td className="px-6 py-4">
                      <span className="text-sm text-slate-300">{item.file_type}</span>
                    </td>
                    
                    <td className="px-6 py-4">
                      <span className={`px-2 py-1 text-xs rounded-full ${getThreatLevelColor(item.severity)}`}>
                        {item.severity.toUpperCase()}
                      </span>
                    </td>
                    
                    <td className="px-6 py-4">
                      <div className="flex items-center space-x-2">
                        <span className="text-sm text-white font-medium">{item.threat_score}</span>
                        <div className="w-16 bg-slate-700 rounded-full h-2">
                          <div
                            className={`h-2 rounded-full ${
                              item.threat_score >= 80 ? 'bg-red-500' :
                              item.threat_score >= 60 ? 'bg-orange-500' :
                              item.threat_score >= 30 ? 'bg-yellow-500' : 'bg-green-500'
                            }`}
                            style={{ width: `${item.threat_score}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    
                    <td className="px-6 py-4">
                      <span className="text-sm text-white">{item.iocs_count || 0}</span>
                    </td>
                    
                    <td className="px-6 py-4">
                      <span className="text-sm text-slate-400">{item.duration || 'N/A'}</span>
                    </td>
                    
                    <td className="px-6 py-4">
                      <div className="text-sm text-slate-400">
                        {formatDate(item.upload_time)}
                      </div>
                    </td>
                    
                    <td className="px-6 py-4">
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => navigate(`/analysis/${item.id}`)}
                          className="text-blue-400 hover:text-blue-300 transition-colors"
                          title="View Analysis"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => navigate(`/analysis/${item.id}`)}
                          className="text-green-400 hover:text-green-300 transition-colors"
                          title="View Charts"
                        >
                          <BarChart3 className="w-4 h-4" />
                        </button>
                        <button 
                          className="text-slate-400 hover:text-yellow-400 transition-colors"
                          title="Add to Favorites"
                        >
                          <Star className="w-4 h-4" />
                        </button>
                        <button 
                          className="text-slate-400 hover:text-blue-400 transition-colors"
                          title="Add Tags"
                        >
                          <Tag className="w-4 h-4" />
                        </button>
                        <button 
                          onClick={() => deleteAnalysis(item.id)}
                          className="text-slate-400 hover:text-red-400 transition-colors"
                          title="Delete Analysis"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {!loading && filteredData.length === 0 && (
          <div className="text-center py-12">
            <FileText className="w-12 h-12 text-slate-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-slate-300 mb-2">No analyses found</h3>
            <p className="text-slate-400">
              {searchTerm || severityFilter !== 'all' || statusFilter !== 'all'
                ? 'Try adjusting your search or filter criteria.'
                : 'Upload your first file to start analyzing.'
              }
            </p>
            {searchTerm === '' && severityFilter === 'all' && statusFilter === 'all' && (
              <button
                onClick={() => navigate('/upload')}
                className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                Upload Files
              </button>
            )}
          </div>
        )}
      </div>
      
      {/* Pagination */}
      {pagination.total > pagination.limit && (
        <div className="flex items-center justify-between">
          <div className="text-sm text-slate-400">
            Showing {pagination.offset + 1} to {Math.min(pagination.offset + pagination.limit, pagination.total)} of {pagination.total} results
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setPagination(prev => ({ ...prev, offset: Math.max(0, prev.offset - prev.limit) }))}
              disabled={pagination.offset === 0}
              className="px-3 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors disabled:opacity-50"
            >
              Previous
            </button>
            <button
              onClick={() => setPagination(prev => ({ ...prev, offset: prev.offset + prev.limit }))}
              disabled={pagination.offset + pagination.limit >= pagination.total}
              className="px-3 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors disabled:opacity-50"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

export default History