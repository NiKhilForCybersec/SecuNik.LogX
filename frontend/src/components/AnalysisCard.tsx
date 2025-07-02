import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { 
  FileSearch, 
  AlertTriangle, 
  Shield, 
  Clock,
  Eye,
  Trash2,
  Download,
  MoreVertical,
  CheckCircle,
  XCircle,
  Loader2
} from 'lucide-react'

interface Analysis {
  id: string
  fileName: string
  fileSize: number
  status: 'pending' | 'processing' | 'completed' | 'failed'
  progress: number
  threatLevel: 'critical' | 'high' | 'medium' | 'low'
  iocCount: number
  mitreCount: number
  createdAt: string
  completedAt?: string
}

interface AnalysisCardProps {
  analysis: Analysis
  onDelete: (id: string) => void
}

export default function AnalysisCard({ analysis, onDelete }: AnalysisCardProps) {
  const navigate = useNavigate()
  const [showMenu, setShowMenu] = useState(false)
  
  const getStatusIcon = () => {
    switch (analysis.status) {
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-400" />
      case 'processing':
        return <Loader2 className="w-5 h-5 text-blue-400 animate-spin" />
      case 'failed':
        return <XCircle className="w-5 h-5 text-red-400" />
      default:
        return <Clock className="w-5 h-5 text-slate-400" />
    }
  }
  
  const getThreatLevelColor = () => {
    switch (analysis.threatLevel) {
      case 'critical':
        return 'text-red-400 bg-red-400/10 border-red-400/30'
      case 'high':
        return 'text-orange-400 bg-orange-400/10 border-orange-400/30'
      case 'medium':
        return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30'
      default:
        return 'text-green-400 bg-green-400/10 border-green-400/30'
    }
  }
  
  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  }
  
  const formatDuration = () => {
    if (!analysis.completedAt) return null
    const start = new Date(analysis.createdAt).getTime()
    const end = new Date(analysis.completedAt).getTime()
    const duration = Math.floor((end - start) / 1000)
    
    if (duration < 60) return `${duration}s`
    const minutes = Math.floor(duration / 60)
    const seconds = duration % 60
    return `${minutes}m ${seconds}s`
  }
  
  const handleView = () => {
    navigate(`/analysis/${analysis.id}`)
  }
  
  const handleDownload = () => {
    // TODO: Implement download functionality
    console.log('Download report for:', analysis.id)
  }
  
  return (
    <div className="bg-slate-900 rounded-lg border border-slate-800 hover:border-slate-700 transition-all">
      {/* Header */}
      <div className="p-4 border-b border-slate-800">
        <div className="flex items-start justify-between mb-2">
          <div className="flex items-center space-x-2">
            {getStatusIcon()}
            <span className="text-sm text-slate-400 capitalize">
              {analysis.status}
            </span>
          </div>
          <div className="relative">
            <button
              onClick={() => setShowMenu(!showMenu)}
              className="text-slate-400 hover:text-white transition-colors p-1"
            >
              <MoreVertical className="w-4 h-4" />
            </button>
            
            {/* Dropdown Menu */}
            {showMenu && (
              <>
                <div 
                  className="fixed inset-0 z-10" 
                  onClick={() => setShowMenu(false)}
                />
                <div className="absolute right-0 mt-2 w-48 bg-slate-800 rounded-lg shadow-lg border border-slate-700 z-20">
                  <button
                    onClick={() => {
                      handleView()
                      setShowMenu(false)
                    }}
                    className="w-full px-4 py-2 text-left text-sm text-slate-300 hover:bg-slate-700 flex items-center"
                  >
                    <Eye className="w-4 h-4 mr-2" />
                    View Details
                  </button>
                  <button
                    onClick={() => {
                      handleDownload()
                      setShowMenu(false)
                    }}
                    className="w-full px-4 py-2 text-left text-sm text-slate-300 hover:bg-slate-700 flex items-center"
                  >
                    <Download className="w-4 h-4 mr-2" />
                    Download Report
                  </button>
                  <button
                    onClick={() => {
                      onDelete(analysis.id)
                      setShowMenu(false)
                    }}
                    className="w-full px-4 py-2 text-left text-sm text-red-400 hover:bg-slate-700 flex items-center"
                  >
                    <Trash2 className="w-4 h-4 mr-2" />
                    Delete
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
        
        <h3 className="text-white font-medium truncate" title={analysis.fileName}>
          {analysis.fileName}
        </h3>
        <p className="text-sm text-slate-500 mt-1">
          {formatFileSize(analysis.fileSize)}
        </p>
      </div>
      
      {/* Progress Bar (for processing) */}
      {analysis.status === 'processing' && (
        <div className="px-4 py-2 border-b border-slate-800">
          <div className="flex items-center justify-between text-xs mb-1">
            <span className="text-slate-400">Processing</span>
            <span className="text-white">{analysis.progress}%</span>
          </div>
          <div className="w-full h-1.5 bg-slate-700 rounded-full overflow-hidden">
            <div 
              className="h-full bg-blue-500 transition-all duration-300"
              style={{ width: `${analysis.progress}%` }}
            />
          </div>
        </div>
      )}
      
      {/* Stats */}
      <div className="p-4 space-y-3">
        {/* Threat Level */}
        <div className="flex items-center justify-between">
          <span className="text-sm text-slate-400">Threat Level</span>
          <span className={`text-xs px-2 py-1 rounded border ${getThreatLevelColor()}`}>
            {analysis.threatLevel.toUpperCase()}
          </span>
        </div>
        
        {/* IOCs */}
        <div className="flex items-center justify-between">
          <div className="flex items-center text-sm text-slate-400">
            <Shield className="w-4 h-4 mr-1" />
            IOCs
          </div>
          <span className="text-sm text-white font-medium">
            {analysis.iocCount}
          </span>
        </div>
        
        {/* MITRE */}
        <div className="flex items-center justify-between">
          <div className="flex items-center text-sm text-slate-400">
            <AlertTriangle className="w-4 h-4 mr-1" />
            MITRE
          </div>
          <span className="text-sm text-white font-medium">
            {analysis.mitreCount}
          </span>
        </div>
        
        {/* Time */}
        <div className="pt-2 border-t border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>{new Date(analysis.createdAt).toLocaleDateString()}</span>
            {analysis.completedAt && formatDuration() && (
              <span>{formatDuration()}</span>
            )}
          </div>
        </div>
      </div>
      
      {/* Action Button */}
      {analysis.status === 'completed' && (
        <div className="p-4 pt-0">
          <button
            onClick={handleView}
            className="w-full py-2 px-4 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors flex items-center justify-center text-sm"
          >
            <Eye className="w-4 h-4 mr-2" />
            View Analysis
          </button>
        </div>
      )}
    </div>
  )
}