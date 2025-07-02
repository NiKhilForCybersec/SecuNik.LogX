import { useState, useEffect } from 'react'
import { 
  Search, 
  Filter, 
  Calendar,
  ChevronDown,
  X
} from 'lucide-react'

interface Filters {
  searchTerm: string
  status: string | null
  threatLevel: string | null
  startDate: string | null
  endDate: string | null
}

interface SearchFilterProps {
  filters: Filters
  onFiltersChange: (filters: Filters) => void
}

export default function SearchFilter({ filters, onFiltersChange }: SearchFilterProps) {
  const [showFilters, setShowFilters] = useState(false)
  const [localSearchTerm, setLocalSearchTerm] = useState(filters.searchTerm)
  
  // Debounce search input
  useEffect(() => {
    const timer = setTimeout(() => {
      if (localSearchTerm !== filters.searchTerm) {
        onFiltersChange({ ...filters, searchTerm: localSearchTerm })
      }
    }, 300)
    
    return () => clearTimeout(timer)
  }, [localSearchTerm])
  
  const handleStatusChange = (status: string | null) => {
    onFiltersChange({ ...filters, status })
  }
  
  const handleThreatLevelChange = (threatLevel: string | null) => {
    onFiltersChange({ ...filters, threatLevel })
  }
  
  const handleDateChange = (field: 'startDate' | 'endDate', value: string) => {
    onFiltersChange({ ...filters, [field]: value || null })
  }
  
  const clearFilters = () => {
    setLocalSearchTerm('')
    onFiltersChange({
      searchTerm: '',
      status: null,
      threatLevel: null,
      startDate: null,
      endDate: null
    })
  }
  
  const hasActiveFilters = () => {
    return filters.searchTerm || filters.status || filters.threatLevel || filters.startDate || filters.endDate
  }
  
  return (
    <div className="space-y-4">
      {/* Search Bar */}
      <div className="flex gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-slate-400" />
          <input
            type="text"
            value={localSearchTerm}
            onChange={(e) => setLocalSearchTerm(e.target.value)}
            placeholder="Search by filename..."
            className="w-full pl-10 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-slate-600 transition-colors"
          />
        </div>
        <button
          onClick={() => setShowFilters(!showFilters)}
          className={`px-4 py-2 rounded-lg border transition-colors flex items-center ${
            hasActiveFilters()
              ? 'bg-blue-600 border-blue-600 text-white'
              : 'bg-slate-900 border-slate-800 text-white hover:border-slate-700'
          }`}
        >
          <Filter className="w-4 h-4 mr-2" />
          Filters
          {hasActiveFilters() && (
            <span className="ml-2 bg-white/20 px-1.5 py-0.5 rounded text-xs">
              Active
            </span>
          )}
        </button>
      </div>
      
      {/* Filter Panel */}
      {showFilters && (
        <div className="bg-slate-900 rounded-lg border border-slate-800 p-4 space-y-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-white font-medium">Advanced Filters</h3>
            {hasActiveFilters() && (
              <button
                onClick={clearFilters}
                className="text-sm text-slate-400 hover:text-white transition-colors flex items-center"
              >
                <X className="w-4 h-4 mr-1" />
                Clear all
              </button>
            )}
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Status Filter */}
            <div>
              <label className="block text-sm text-slate-400 mb-2">
                Status
              </label>
              <div className="relative">
                <select
                  value={filters.status || ''}
                  onChange={(e) => handleStatusChange(e.target.value || null)}
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white appearance-none focus:outline-none focus:border-slate-600 pr-8"
                >
                  <option value="">All Statuses</option>
                  <option value="pending">Pending</option>
                  <option value="processing">Processing</option>
                  <option value="completed">Completed</option>
                  <option value="failed">Failed</option>
                </select>
                <ChevronDown className="absolute right-2 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
              </div>
            </div>
            
            {/* Threat Level Filter */}
            <div>
              <label className="block text-sm text-slate-400 mb-2">
                Threat Level
              </label>
              <div className="relative">
                <select
                  value={filters.threatLevel || ''}
                  onChange={(e) => handleThreatLevelChange(e.target.value || null)}
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white appearance-none focus:outline-none focus:border-slate-600 pr-8"
                >
                  <option value="">All Levels</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
                <ChevronDown className="absolute right-2 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
              </div>
            </div>
            
            {/* Start Date */}
            <div>
              <label className="block text-sm text-slate-400 mb-2">
                Start Date
              </label>
              <div className="relative">
                <input
                  type="date"
                  value={filters.startDate || ''}
                  onChange={(e) => handleDateChange('startDate', e.target.value)}
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-slate-600"
                />
                <Calendar className="absolute right-2 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
              </div>
            </div>
            
            {/* End Date */}
            <div>
              <label className="block text-sm text-slate-400 mb-2">
                End Date
              </label>
              <div className="relative">
                <input
                  type="date"
                  value={filters.endDate || ''}
                  onChange={(e) => handleDateChange('endDate', e.target.value)}
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-slate-600"
                />
                <Calendar className="absolute right-2 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
              </div>
            </div>
          </div>
          
          {/* Filter Summary */}
          {hasActiveFilters() && (
            <div className="pt-4 border-t border-slate-800">
              <div className="flex items-center flex-wrap gap-2">
                <span className="text-sm text-slate-400">Active filters:</span>
                {filters.searchTerm && (
                  <span className="px-2 py-1 bg-slate-800 text-slate-300 rounded text-xs">
                    Search: "{filters.searchTerm}"
                  </span>
                )}
                {filters.status && (
                  <span className="px-2 py-1 bg-slate-800 text-slate-300 rounded text-xs capitalize">
                    Status: {filters.status}
                  </span>
                )}
                {filters.threatLevel && (
                  <span className="px-2 py-1 bg-slate-800 text-slate-300 rounded text-xs capitalize">
                    Threat: {filters.threatLevel}
                  </span>
                )}
                {(filters.startDate || filters.endDate) && (
                  <span className="px-2 py-1 bg-slate-800 text-slate-300 rounded text-xs">
                    Date: {filters.startDate || '...'} to {filters.endDate || '...'}
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}