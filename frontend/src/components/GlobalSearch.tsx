import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, X, FileText, Shield, Code, Hash } from 'lucide-react'
import { useAnalysisStore } from '../store/useAnalysisStore'
import { useApi } from '../hooks/useApi'
import { analysisAPI } from '../services/analysisAPI'
import { debounce } from '../hooks/useDebounce'

export function GlobalSearch() {
  const [isOpen, setIsOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<any[]>([])
  const inputRef = useRef<HTMLInputElement>(null)
  const navigate = useNavigate()
  
  // Search functionality
  const searchAnalyses = useCallback(
    debounce(async (searchQuery: string) => {
      if (!searchQuery.trim()) {
        setResults([])
        return
      }
      
      try {
        const response = await analysisAPI.getAnalyses({ 
          search: searchQuery,
          pageSize: 5 
        })
        setResults(response.items)
      } catch (error) {
        console.error('Search failed:', error)
        setResults([])
      }
    }, 300),
    []
  )
  
  // Keyboard shortcut (Cmd/Ctrl + K)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setIsOpen(true)
      }
      if (e.key === 'Escape' && isOpen) {
        setIsOpen(false)
      }
    }
    
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen])
  
  // Focus input when opened
  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus()
    }
  }, [isOpen])
  
  // Handle search
  useEffect(() => {
    searchAnalyses(query)
  }, [query, searchAnalyses])
  
  const handleSelect = (analysisId: string) => {
    navigate(`/analysis/${analysisId}`)
    setIsOpen(false)
    setQuery('')
  }
  
  if (!isOpen) return null
  
  return (
    <>
      {/* Backdrop */}
      <div 
        className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50"
        onClick={() => setIsOpen(false)}
      />
      
      {/* Search Modal */}
      <div className="fixed inset-x-0 top-20 mx-auto max-w-2xl z-50 p-4">
        <div className="bg-slate-900 rounded-lg shadow-2xl border border-slate-800 overflow-hidden">
          {/* Search Input */}
          <div className="flex items-center px-4 py-3 border-b border-slate-800">
            <Search className="w-5 h-5 text-slate-400 mr-3" />
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search analyses, files, IOCs..."
              className="flex-1 bg-transparent text-white placeholder-slate-500 outline-none"
            />
            <button
              onClick={() => setIsOpen(false)}
              className="p-1 hover:bg-slate-800 rounded transition-colors"
            >
              <X className="w-4 h-4 text-slate-400" />
            </button>
          </div>
          
          {/* Results */}
          {query && (
            <div className="max-h-96 overflow-y-auto">
              {results.length > 0 ? (
                <div className="py-2">
                  <div className="px-4 py-2 text-xs text-slate-500 uppercase">
                    Analyses
                  </div>
                  {results.map((analysis) => (
                    <button
                      key={analysis.id}
                      onClick={() => handleSelect(analysis.id)}
                      className="w-full px-4 py-3 hover:bg-slate-800 flex items-center justify-between transition-colors"
                    >
                      <div className="flex items-center">
                        <FileText className="w-4 h-4 text-slate-400 mr-3" />
                        <div className="text-left">
                          <div className="text-sm text-white">
                            {analysis.fileName}
                          </div>
                          <div className="text-xs text-slate-500">
                            {analysis.status} • {analysis.threatLevel}
                          </div>
                        </div>
                      </div>
                      <div className="text-xs text-slate-500">
                        {new Date(analysis.createdAt).toLocaleDateString()}
                      </div>
                    </button>
                  ))}
                </div>
              ) : (
                <div className="px-4 py-8 text-center text-slate-500">
                  No results found for "{query}"
                </div>
              )}
            </div>
          )}
          
          {/* Help */}
          <div className="px-4 py-2 border-t border-slate-800 text-xs text-slate-500">
            <kbd className="px-2 py-1 bg-slate-800 rounded">↵</kbd> to select
            {' • '}
            <kbd className="px-2 py-1 bg-slate-800 rounded">ESC</kbd> to close
          </div>
        </div>
      </div>
    </>
  )
}