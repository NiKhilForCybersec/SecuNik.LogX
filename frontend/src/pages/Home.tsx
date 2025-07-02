import { useEffect } from 'react'
import { useAppStore } from '../store/useAppStore'
import { useAnalysisStore } from '../store/useAnalysisStore'
import { useApi } from '../hooks/useApi'
import { analysisAPI } from '../services/analysisAPI'
import { useSignalR } from '../hooks/useSignalR'
import { 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  Clock,
  TrendingUp,
  FileSearch,
  Shield,
  Brain
} from 'lucide-react'

export default function Home() {
  const { systemStatus, activeAnalyses } = useAppStore()
  const { analyses } = useAnalysisStore()
  const { isConnected } = useSignalR()
  
  // Fetch initial data
  const { execute: fetchAnalyses } = useApi(analysisAPI.getAnalyses)
  
  useEffect(() => {
    fetchAnalyses({ pageSize: 100 })
      .then(result => {
        if (result) {
          useAnalysisStore.getState().setAnalyses(result.items)
        }
      })
  }, [])
  
  // Calculate stats from REAL data
  const stats = {
    totalAnalyses: analyses.length,
    activeAnalyses: analyses.filter(a => a.status === 'processing').length,
    completedAnalyses: analyses.filter(a => a.status === 'completed').length,
    threatBreakdown: {
      critical: analyses.filter(a => a.threatLevel === 'critical').length,
      high: analyses.filter(a => a.threatLevel === 'high').length,
      medium: analyses.filter(a => a.threatLevel === 'medium').length,
      low: analyses.filter(a => a.threatLevel === 'low').length,
    },
    totalIOCs: analyses.reduce((sum, a) => sum + a.iocCount, 0),
    totalMITRE: analyses.reduce((sum, a) => sum + a.mitreCount, 0),
  }
  
  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">
          Forensics Dashboard
        </h1>
        <p className="text-slate-400">
          Real-time system monitoring and analysis overview
        </p>
      </div>
      
      {/* System Status Bar */}
      <div className="bg-slate-900 rounded-lg p-4 border border-slate-800">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="flex items-center">
              <div className={`w-3 h-3 rounded-full mr-2 ${
                isConnected ? 'bg-green-400' : 'bg-red-400'
              }`} />
              <span className="text-sm text-slate-300">
                System Status: {systemStatus}
              </span>
            </div>
            <div className="text-sm text-slate-400">
              Active Analyses: {stats.activeAnalyses}
            </div>
          </div>
          <div className="text-sm text-slate-400">
            {new Date().toLocaleString()}
          </div>
        </div>
      </div>
      
      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Analyses */}
        <div className="bg-slate-900 rounded-lg p-6 border border-slate-800">
          <div className="flex items-center justify-between mb-4">
            <FileSearch className="w-8 h-8 text-blue-400" />
            <span className="text-xs text-slate-500 uppercase">Total</span>
          </div>
          <div className="text-2xl font-bold text-white">
            {stats.totalAnalyses}
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Analyses performed
          </p>
        </div>
        
        {/* Active Analyses */}
        <div className="bg-slate-900 rounded-lg p-6 border border-slate-800">
          <div className="flex items-center justify-between mb-4">
            <Activity className="w-8 h-8 text-green-400" />
            <span className="text-xs text-slate-500 uppercase">Active</span>
          </div>
          <div className="text-2xl font-bold text-white">
            {stats.activeAnalyses}
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Currently processing
          </p>
        </div>
        
        {/* Total IOCs */}
        <div className="bg-slate-900 rounded-lg p-6 border border-slate-800">
          <div className="flex items-center justify-between mb-4">
            <Shield className="w-8 h-8 text-orange-400" />
            <span className="text-xs text-slate-500 uppercase">IOCs</span>
          </div>
          <div className="text-2xl font-bold text-white">
            {stats.totalIOCs}
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Indicators detected
          </p>
        </div>
        
        {/* MITRE Techniques */}
        <div className="bg-slate-900 rounded-lg p-6 border border-slate-800">
          <div className="flex items-center justify-between mb-4">
            <Brain className="w-8 h-8 text-purple-400" />
            <span className="text-xs text-slate-500 uppercase">MITRE</span>
          </div>
          <div className="text-2xl font-bold text-white">
            {stats.totalMITRE}
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Techniques mapped
          </p>
        </div>
      </div>
      
      {/* Threat Level Distribution */}
      <div className="bg-slate-900 rounded-lg p-6 border border-slate-800">
        <h2 className="text-xl font-semibold text-white mb-4">
          Threat Level Distribution
        </h2>
        <div className="space-y-3">
          {Object.entries(stats.threatBreakdown).map(([level, count]) => (
            <div key={level} className="flex items-center justify-between">
              <div className="flex items-center">
                <div className={`w-3 h-3 rounded-full mr-3 ${
                  level === 'critical' ? 'bg-red-500' :
                  level === 'high' ? 'bg-orange-500' :
                  level === 'medium' ? 'bg-yellow-500' :
                  'bg-green-500'
                }`} />
                <span className="text-sm text-slate-300 capitalize">
                  {level}
                </span>
              </div>
              <div className="flex items-center">
                <span className="text-sm font-medium text-white mr-4">
                  {count}
                </span>
                <div className="w-32 h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div 
                    className={`h-full ${
                      level === 'critical' ? 'bg-red-500' :
                      level === 'high' ? 'bg-orange-500' :
                      level === 'medium' ? 'bg-yellow-500' :
                      'bg-green-500'
                    }`}
                    style={{ width: `${stats.totalAnalyses > 0 ? (count / stats.totalAnalyses) * 100 : 0}%` }}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
      
      {/* Recent Activity */}
      <div className="bg-slate-900 rounded-lg p-6 border border-slate-800">
        <h2 className="text-xl font-semibold text-white mb-4">
          Recent Analyses
        </h2>
        <div className="space-y-2">
          {analyses.slice(0, 5).map(analysis => (
            <div key={analysis.id} className="flex items-center justify-between py-2 border-b border-slate-800 last:border-0">
              <div className="flex items-center">
                <div className={`w-2 h-2 rounded-full mr-3 ${
                  analysis.status === 'completed' ? 'bg-green-400' :
                  analysis.status === 'processing' ? 'bg-blue-400 animate-pulse' :
                  analysis.status === 'failed' ? 'bg-red-400' :
                  'bg-slate-400'
                }`} />
                <div>
                  <p className="text-sm text-white">{analysis.fileName}</p>
                  <p className="text-xs text-slate-500">
                    {new Date(analysis.createdAt).toLocaleString()}
                  </p>
                </div>
              </div>
              <div className="flex items-center space-x-4">
                <span className={`text-xs px-2 py-1 rounded ${
                  analysis.threatLevel === 'critical' ? 'bg-red-500/20 text-red-400' :
                  analysis.threatLevel === 'high' ? 'bg-orange-500/20 text-orange-400' :
                  analysis.threatLevel === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                  'bg-green-500/20 text-green-400'
                }`}>
                  {analysis.threatLevel}
                </span>
                {analysis.status === 'processing' && (
                  <span className="text-xs text-slate-400">
                    {analysis.progress}%
                  </span>
                )}
              </div>
            </div>
          ))}
          {analyses.length === 0 && (
            <p className="text-sm text-slate-500 text-center py-4">
              No analyses yet. Upload a file to get started.
            </p>
          )}
        </div>
      </div>
    </div>
  )
}