import { useEffect, useState } from 'react'
import { useAnalysisStore } from '../store/useAnalysisStore'
import { useAppStore } from '../store/useAppStore'
import { useApi } from '../hooks/useApi'
import { analysisAPI } from '../services/analysisAPI'
import { useSignalR } from '../hooks/useSignalR'
import { useNotification } from '../contexts/NotificationContext'
import FileUpload from '../components/FileUpload'
import AnalysisCard from '../components/AnalysisCard'
import SearchFilter from '../components/SearchFilter'
import { 
  FileSearch, 
  RefreshCw,
  AlertCircle,
  Loader2
} from 'lucide-react'

export default function AnalysisPage() {
  const { analyses, setAnalyses, filters, setFilters } = useAnalysisStore()
  const { setActiveAnalyses } = useAppStore()
  const { joinAnalysisGroup, leaveAnalysisGroup } = useSignalR()
  const { error: showError } = useNotification()
  
  const [refreshing, setRefreshing] = useState(false)
  
  // API hooks
  const { execute: fetchAnalyses, loading } = useApi(analysisAPI.getAnalyses)
  const { execute: deleteAnalysis } = useApi(analysisAPI.deleteAnalysis)
  
  // Fetch analyses on mount and when filters change
  useEffect(() => {
    loadAnalyses()
  }, [filters])
  
  // Join SignalR groups for active analyses
  useEffect(() => {
    const activeAnalyses = analyses.filter(a => a.status === 'processing')
    setActiveAnalyses(activeAnalyses.length)
    
    // Join groups for real-time updates
    activeAnalyses.forEach(analysis => {
      joinAnalysisGroup(analysis.id)
    })
    
    // Cleanup: leave groups
    return () => {
      activeAnalyses.forEach(analysis => {
        leaveAnalysisGroup(analysis.id)
      })
    }
  }, [analyses, joinAnalysisGroup, leaveAnalysisGroup, setActiveAnalyses])
  
  const loadAnalyses = async () => {
    try {
      const result = await fetchAnalyses({
        pageSize: 100,
        searchTerm: filters.searchTerm,
        status: filters.status,
        threatLevel: filters.threatLevel,
        startDate: filters.startDate,
        endDate: filters.endDate
      })
      
      if (result) {
        setAnalyses(result.items)
      }
    } catch (err) {
      showError('Failed to load analyses')
    }
  }
  
  const handleRefresh = async () => {
    setRefreshing(true)
    await loadAnalyses()
    setRefreshing(false)
  }
  
  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this analysis?')) return
    
    try {
      await deleteAnalysis(id)
      await loadAnalyses()
    } catch (err) {
      showError('Failed to delete analysis')
    }
  }
  
  const handleUploadSuccess = () => {
    // Refresh the list after successful upload
    loadAnalyses()
  }
  
  // Filter analyses based on current filters
  const filteredAnalyses = analyses.filter(analysis => {
    if (filters.searchTerm && !analysis.fileName.toLowerCase().includes(filters.searchTerm.toLowerCase())) {
      return false
    }
    if (filters.status && analysis.status !== filters.status) {
      return false
    }
    if (filters.threatLevel && analysis.threatLevel !== filters.threatLevel) {
      return false
    }
    return true
  })
  
  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">
            Analysis Management
          </h1>
          <p className="text-slate-400">
            Upload and analyze forensic artifacts
          </p>
        </div>
        <button
          onClick={handleRefresh}
          disabled={refreshing}
          className="flex items-center px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>
      
      {/* File Upload Section */}
      <div className="bg-slate-900 rounded-lg p-6 border border-slate-800">
        <h2 className="text-xl font-semibold text-white mb-4">
          Upload New File
        </h2>
        <FileUpload onUploadSuccess={handleUploadSuccess} />
      </div>
      
      {/* Search and Filters */}
      <SearchFilter 
        filters={filters}
        onFiltersChange={setFilters}
      />
      
      {/* Analysis List */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-white">
            Analysis Results
          </h2>
          <span className="text-sm text-slate-400">
            {filteredAnalyses.length} of {analyses.length} analyses
          </span>
        </div>
        
        {loading && !refreshing ? (
          <div className="bg-slate-900 rounded-lg p-12 border border-slate-800 text-center">
            <Loader2 className="w-8 h-8 text-blue-400 animate-spin mx-auto mb-4" />
            <p className="text-slate-400">Loading analyses...</p>
          </div>
        ) : filteredAnalyses.length === 0 ? (
          <div className="bg-slate-900 rounded-lg p-12 border border-slate-800 text-center">
            <FileSearch className="w-12 h-12 text-slate-600 mx-auto mb-4" />
            <p className="text-slate-400 mb-2">No analyses found</p>
            <p className="text-sm text-slate-500">
              {filters.searchTerm || filters.status || filters.threatLevel 
                ? 'Try adjusting your filters'
                : 'Upload a file to get started'}
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredAnalyses.map(analysis => (
              <AnalysisCard
                key={analysis.id}
                analysis={analysis}
                onDelete={handleDelete}
              />
            ))}
          </div>
        )}
      </div>
      
      {/* Active Analyses Warning */}
      {analyses.some(a => a.status === 'processing') && (
        <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4 flex items-start">
          <AlertCircle className="w-5 h-5 text-blue-400 mr-3 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-blue-400 font-medium">
              Active analyses in progress
            </p>
            <p className="text-sm text-slate-400 mt-1">
              Real-time updates are enabled. Analysis results will update automatically.
            </p>
          </div>
        </div>
      )}
    </div>
  )
}