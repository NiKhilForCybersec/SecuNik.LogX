import { useParams, useNavigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { useAnalysisStore } from '../store/useAnalysisStore'
import { useApi } from '../hooks/useApi'
import { analysisAPI } from '../services/analysisAPI'
import { useNotification } from '../contexts/NotificationContext'
import { useSignalR } from '../hooks/useSignalR'
import { 
  ArrowLeft, 
  Download, 
  RefreshCw, 
  AlertTriangle,
  Shield,
  Brain,
  FileText,
  Activity
} from 'lucide-react'
import DataTable from '../components/DataTable'
import ThreatChart from '../components/ThreatChart'
import LogViewer from '../components/LogViewer'

export default function AnalysisDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { currentAnalysis, setCurrentAnalysis } = useAnalysisStore()
  const { joinAnalysisGroup, leaveAnalysisGroup } = useSignalR()
  const { success, error } = useNotification()
  
  // Tabs
  const [activeTab, setActiveTab] = useState<'overview' | 'iocs' | 'mitre' | 'logs'>('overview')
  
  // Fetch analysis details
  const { data: analysis, loading, execute: fetchAnalysis } = useApi(() => 
    analysisAPI.getAnalysis(id!)
  )
  
  // Fetch full results
  const { data: results, execute: fetchResults } = useApi(() =>
    analysisAPI.getResults(id!)
  )
  
  useEffect(() => {
    if (id) {
      fetchAnalysis()
      fetchResults()
      joinAnalysisGroup(id)
    }
    
    return () => {
      if (id) leaveAnalysisGroup(id)
    }
  }, [id])
  
  useEffect(() => {
    if (analysis) {
      setCurrentAnalysis(analysis)
    }
  }, [analysis])
  
  const handleExport = async (format: 'json' | 'pdf' | 'csv') => {
    try {
      const blob = await analysisAPI.exportAnalysis(id!, format)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `analysis_${id}.${format}`
      a.click()
      URL.revokeObjectURL(url)
      success(`Exported as ${format.toUpperCase()}`)
    } catch (err) {
      error('Export failed')
    }
  }
  
  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    )
  }
  
  if (!analysis) {
    return (
      <div className="p-6">
        <p className="text-slate-400">Analysis not found</p>
      </div>
    )
  }
  
  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="mb-6">
        <button
          onClick={() => navigate('/analysis')}
          className="flex items-center text-slate-400 hover:text-white mb-4 transition-colors"
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Analyses
        </button>
        
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">
              {analysis.fileName}
            </h1>
            <div className="flex items-center space-x-4 text-sm text-slate-400">
              <span>ID: {analysis.id}</span>
              <span>•</span>
              <span>{new Date(analysis.createdAt).toLocaleString()}</span>
              <span>•</span>
              <span className={`px-2 py-1 rounded text-xs ${
                analysis.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                analysis.status === 'processing' ? 'bg-blue-500/20 text-blue-400' :
                'bg-red-500/20 text-red-400'
              }`}>
                {analysis.status}
              </span>
            </div>
          </div>
          
          <div className="flex space-x-2">
            <button
              onClick={() => handleExport('json')}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg text-sm text-white flex items-center transition-colors"
            >
              <Download className="w-4 h-4 mr-2" />
              Export
            </button>
          </div>
        </div>
      </div>
      
      {/* Threat Level Alert */}
      {analysis.threatLevel !== 'low' && (
        <div className={`mb-6 p-4 rounded-lg border ${
          analysis.threatLevel === 'critical' ? 'bg-red-500/10 border-red-500/50 text-red-400' :
          analysis.threatLevel === 'high' ? 'bg-orange-500/10 border-orange-500/50 text-orange-400' :
          'bg-yellow-500/10 border-yellow-500/50 text-yellow-400'
        }`}>
          <div className="flex items-center">
            <AlertTriangle className="w-5 h-5 mr-2" />
            <span className="font-medium">
              {analysis.threatLevel.toUpperCase()} Threat Level Detected
            </span>
          </div>
        </div>
      )}
      
      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-slate-900 rounded-lg p-4 border border-slate-800">
          <div className="flex items-center justify-between mb-2">
            <FileText className="w-5 h-5 text-slate-400" />
            <span className="text-2xl font-bold text-white">
              {(analysis.fileSize / 1024 / 1024).toFixed(2)} MB
            </span>
          </div>
          <p className="text-sm text-slate-400">File Size</p>
        </div>
        
        <div className="bg-slate-900 rounded-lg p-4 border border-slate-800">
          <div className="flex items-center justify-between mb-2">
            <Shield className="w-5 h-5 text-orange-400" />
            <span className="text-2xl font-bold text-white">
              {analysis.iocCount}
            </span>
          </div>
          <p className="text-sm text-slate-400">IOCs Detected</p>
        </div>
        
        <div className="bg-slate-900 rounded-lg p-4 border border-slate-800">
          <div className="flex items-center justify-between mb-2">
            <Brain className="w-5 h-5 text-purple-400" />
            <span className="text-2xl font-bold text-white">
              {analysis.mitreCount}
            </span>
          </div>
          <p className="text-sm text-slate-400">MITRE Techniques</p>
        </div>
        
        <div className="bg-slate-900 rounded-lg p-4 border border-slate-800">
          <div className="flex items-center justify-between mb-2">
            <Activity className="w-5 h-5 text-green-400" />
            <span className="text-2xl font-bold text-white">
              {analysis.progress}%
            </span>
          </div>
          <p className="text-sm text-slate-400">Completion</p>
        </div>
      </div>
      
      {/* Tabs */}
      <div className="border-b border-slate-800 mb-6">
        <nav className="-mb-px flex space-x-8">
          {['overview', 'iocs', 'mitre', 'logs'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab as any)}
              className={`py-2 px-1 border-b-2 font-medium text-sm transition-colors ${
                activeTab === tab
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-slate-400 hover:text-white'
              }`}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </nav>
      </div>
      
      {/* Tab Content */}
      <div className="bg-slate-900 rounded-lg border border-slate-800 p-6">
        {activeTab === 'overview' && results && (
          <div className="space-y-6">
            <ThreatChart data={results.threatTimeline || []} />
            <div className="prose prose-invert max-w-none">
              <h3 className="text-xl font-semibold text-white mb-4">
                Executive Summary
              </h3>
              <p className="text-slate-300">
                {results.summary || 'Analysis summary will appear here once processing is complete.'}
              </p>
            </div>
          </div>
        )}
        
        {activeTab === 'iocs' && results?.iocs && (
          <DataTable
            data={results.iocs}
            columns={[
              { key: 'type', label: 'Type' },
              { key: 'value', label: 'Indicator' },
              { key: 'confidence', label: 'Confidence' },
              { key: 'context', label: 'Context' }
            ]}
          />
        )}
        
        {activeTab === 'mitre' && results?.mitreTechniques && (
          <DataTable
            data={results.mitreTechniques}
            columns={[
              { key: 'techniqueId', label: 'Technique ID' },
              { key: 'name', label: 'Name' },
              { key: 'tactic', label: 'Tactic' },
              { key: 'confidence', label: 'Confidence' }
            ]}
          />
        )}
        
        {activeTab === 'logs' && (
          <LogViewer 
            content={results?.rawLogs || '// Log content will appear here'} 
            language="log"
          />
        )}
      </div>
    </div>
  )
}