import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  Shield,
  Plus,
  Search,
  Filter,
  Download,
  Upload,
  Edit,
  Trash2,
  Play,
  Eye,
  FileText,
  Code,
  AlertTriangle,
  CheckCircle,
  XCircle,
  RefreshCw,
  Settings,
  Copy,
  Pause
} from 'lucide-react'
import { rulesService } from '../services/rulesService'
import toast from 'react-hot-toast'

const RuleManager: React.FC = () => {
  const [activeTab, setActiveTab] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedRule, setSelectedRule] = useState<any>(null)
  const [showEditor, setShowEditor] = useState(false)
  const [rules, setRules] = useState<any[]>([])
  const [stats, setStats] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [pagination, setPagination] = useState({
    limit: 50,
    offset: 0,
    total: 0
  })

  useEffect(() => {
    loadRules()
    loadStats()
  }, [])

  useEffect(() => {
    loadRules()
  }, [activeTab, searchTerm, pagination.offset])

  const loadRules = async () => {
    try {
      setLoading(true)
      
      const filters: any = {
        limit: pagination.limit,
        offset: pagination.offset
      }
      
      if (activeTab !== 'all') filters.type = activeTab
      if (searchTerm) filters.search = searchTerm
      
      const response = await rulesService.getRules(filters)
      
      setRules(response.rules || [])
      setPagination(prev => ({
        ...prev,
        total: response.total || 0
      }))
      
    } catch (error: any) {
      console.error('Failed to load rules:', error)
      toast.error('Failed to load rules')
    } finally {
      setLoading(false)
    }
  }

  const loadStats = async () => {
    try {
      const statsData = await rulesService.getRuleStats()
      setStats(statsData)
    } catch (error: any) {
      console.error('Failed to load rule stats:', error)
    }
  }

  const deleteRule = async (ruleId: string) => {
    if (!confirm('Are you sure you want to delete this rule?')) return
    
    try {
      await rulesService.deleteRule(ruleId)
      toast.success('Rule deleted successfully')
      loadRules()
    } catch (error: any) {
      console.error('Failed to delete rule:', error)
      toast.error('Failed to delete rule')
    }
  }

  const toggleRule = async (ruleId: string, currentEnabled: boolean) => {
    try {
      await rulesService.updateRule(ruleId, { isEnabled: !currentEnabled })
      toast.success(`Rule ${!currentEnabled ? 'enabled' : 'disabled'}`)
      loadRules()
    } catch (error: any) {
      console.error('Failed to toggle rule:', error)
      toast.error('Failed to update rule')
    }
  }

  const exportRules = async () => {
    try {
      const data = await rulesService.exportRules('json')
      
      // Create download link
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `rules_export_${new Date().toISOString().split('T')[0]}.json`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)
      
      toast.success('Rules exported successfully')
    } catch (error: any) {
      console.error('Export failed:', error)
      toast.error('Failed to export rules')
    }
  }

  const handleImportRules = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files
    if (!files || files.length === 0) return
    
    try {
      const file = files[0]
      await rulesService.importRules(file)
      toast.success('Rules imported successfully')
      loadRules()
    } catch (error: any) {
      console.error('Import failed:', error)
      toast.error('Failed to import rules')
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-400 bg-red-900/30'
      case 'high':
        return 'text-orange-400 bg-orange-900/30'
      case 'medium':
        return 'text-yellow-400 bg-yellow-900/30'
      case 'low':
        return 'text-green-400 bg-green-900/30'
      default:
        return 'text-blue-400 bg-blue-900/30'
    }
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'yara':
        return <FileText className="w-4 h-4" />
      case 'sigma':
        return <Shield className="w-4 h-4" />
      case 'custom':
        return <Code className="w-4 h-4" />
      default:
        return <FileText className="w-4 h-4" />
    }
  }

  const tabs = [
    { id: 'all', label: 'All Rules', count: stats?.total_rules || 0 },
    { id: 'yara', label: 'YARA', count: stats?.rules_by_type?.yara || 0 },
    { id: 'sigma', label: 'Sigma', count: stats?.rules_by_type?.sigma || 0 },
    { id: 'custom', label: 'Custom', count: stats?.rules_by_type?.custom || 0 },
  ]

  const statsData = stats ? [
    {
      title: 'Total Rules',
      value: stats.total_rules?.toString() || '0',
      icon: Shield,
      color: 'text-blue-400'
    },
    {
      title: 'Active Rules',
      value: stats.enabled_rules?.toString() || '0',
      icon: CheckCircle,
      color: 'text-green-400'
    },
    {
      title: 'High Severity',
      value: (stats.rules_by_severity?.high || 0) + (stats.rules_by_severity?.critical || 0),
      icon: AlertTriangle,
      color: 'text-red-400'
    },
    {
      title: 'Recent Matches',
      value: stats.total_matches_last_24h?.toString() || '0',
      icon: Eye,
      color: 'text-yellow-400'
    }
  ] : []

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Rule Manager</h1>
          <p className="text-slate-400 mt-2">
            Manage YARA, Sigma, and custom detection rules for comprehensive threat detection
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <button 
            onClick={loadRules}
            className="flex items-center space-x-2 px-4 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Refresh</span>
          </button>
          <button 
            onClick={exportRules}
            className="flex items-center space-x-2 px-4 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors"
          >
            <Download className="w-4 h-4" />
            <span>Export Rules</span>
          </button>
          <div className="relative">
            <input
              type="file"
              id="rule-import"
              className="hidden"
              accept=".json,.yml,.yaml,.yar,.yara"
              onChange={handleImportRules}
            />
            <label 
              htmlFor="rule-import"
              className="flex items-center space-x-2 px-4 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors cursor-pointer"
            >
              <Upload className="w-4 h-4" />
              <span>Import Rules</span>
            </label>
          </div>
          <button
            onClick={() => setShowEditor(true)}
            className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            <Plus className="w-4 h-4" />
            <span>New Rule</span>
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

      {/* Rules Management */}
      <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-800">
        {/* Filters */}
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-6">
          <div className="flex items-center space-x-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                type="text"
                placeholder="Search rules..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent w-64"
              />
            </div>
            <button className="flex items-center space-x-2 px-3 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors">
              <Filter className="w-4 h-4" />
              <span>Advanced Filters</span>
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="border-b border-slate-700 mb-6">
          <nav className="flex space-x-8">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`py-2 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-400'
                    : 'border-transparent text-slate-400 hover:text-slate-300'
                }`}
              >
                {tab.label} ({tab.count})
              </button>
            ))}
          </nav>
        </div>

        {/* Rules Table */}
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Rule
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Severity
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Matches
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Modified
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {rules.map((rule, index) => (
                  <motion.tr
                    key={rule.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className="hover:bg-slate-800/50 transition-colors"
                  >
                    <td className="px-4 py-4">
                      <div>
                        <div className="text-sm font-medium text-white">{rule.name}</div>
                        <div className="text-sm text-slate-400 mt-1">{rule.description}</div>
                        <div className="flex items-center space-x-2 mt-2">
                          <span className="px-2 py-1 bg-blue-900/30 text-blue-300 text-xs rounded">
                            {rule.category}
                          </span>
                          <span className="text-xs text-slate-500">by {rule.author}</span>
                        </div>
                      </div>
                    </td>
                    
                    <td className="px-4 py-4">
                      <div className="flex items-center">
                        {getTypeIcon(rule.type)}
                        <span className="ml-2 text-sm text-white capitalize">{rule.type}</span>
                      </div>
                    </td>
                    
                    <td className="px-4 py-4">
                      <span className={`px-2 py-1 text-xs rounded-full ${getSeverityColor(rule.severity)}`}>
                        {rule.severity.toUpperCase()}
                      </span>
                    </td>
                    
                    <td className="px-4 py-4">
                      <div className="flex items-center">
                        <div className={`w-2 h-2 rounded-full mr-2 ${
                          rule.isEnabled ? 'bg-green-400' : 'bg-slate-400'
                        }`} />
                        <span className={`text-sm ${
                          rule.isEnabled ? 'text-green-400' : 'text-slate-400'
                        }`}>
                          {rule.isEnabled ? 'Active' : 'Disabled'}
                        </span>
                      </div>
                    </td>
                    
                    <td className="px-4 py-4">
                      <span className="text-sm text-white">{rule.matchCount}</span>
                    </td>
                    
                    <td className="px-4 py-4">
                      <div className="text-sm text-slate-400">
                        {new Date(rule.updatedAt).toLocaleDateString()}
                      </div>
                    </td>
                    
                    <td className="px-4 py-4">
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => setSelectedRule(rule)}
                          className="text-blue-400 hover:text-blue-300 transition-colors"
                          title="View Rule"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        <button 
                          className="text-slate-400 hover:text-white transition-colors"
                          title="Test Rule"
                        >
                          <Play className="w-4 h-4" />
                        </button>
                        <button 
                          className="text-slate-400 hover:text-white transition-colors"
                          title="Edit Rule"
                        >
                          <Edit className="w-4 h-4" />
                        </button>
                        <button 
                          className="text-slate-400 hover:text-white transition-colors"
                          title="Copy Rule"
                        >
                          <Copy className="w-4 h-4" />
                        </button>
                        <button 
                          onClick={() => toggleRule(rule.id, rule.isEnabled)}
                          className={`transition-colors ${
                            rule.isEnabled 
                              ? 'text-slate-400 hover:text-yellow-400' 
                              : 'text-slate-400 hover:text-green-400'
                          }`}
                          title={rule.isEnabled ? 'Disable Rule' : 'Enable Rule'}
                        >
                          {rule.isEnabled ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                        </button>
                        <button 
                          onClick={() => deleteRule(rule.id)}
                          className="text-slate-400 hover:text-red-400 transition-colors"
                          title="Delete Rule"
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

        {!loading && rules.length === 0 && (
          <div className="text-center py-12">
            <Shield className="w-12 h-12 text-slate-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-slate-300 mb-2">No rules found</h3>
            <p className="text-slate-400">
              {searchTerm 
                ? 'Try adjusting your search terms.'
                : 'Create your first detection rule to get started.'
              }
            </p>
          </div>
        )}
      </div>

      {/* Rule Viewer Modal */}
      {selectedRule && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-slate-900 rounded-lg border border-slate-700 max-w-4xl w-full max-h-[80vh] overflow-hidden"
          >
            <div className="flex items-center justify-between p-6 border-b border-slate-700">
              <div>
                <h3 className="text-lg font-semibold text-white">{selectedRule.name}</h3>
                <p className="text-sm text-slate-400 mt-1">{selectedRule.description}</p>
              </div>
              <button
                onClick={() => setSelectedRule(null)}
                className="text-slate-400 hover:text-white transition-colors"
              >
                <XCircle className="w-6 h-6" />
              </button>
            </div>
            
            <div className="p-6 overflow-y-auto max-h-96">
              <pre className="bg-slate-800 p-4 rounded-lg text-sm text-slate-300 font-mono overflow-x-auto">
                {selectedRule.content}
              </pre>
            </div>
          </motion.div>
        </div>
      )}
    </div>
  )
}

export default RuleManager