import { create } from 'zustand'
import { devtools } from 'zustand/middleware'

interface Analysis {
  id: string
  fileName: string
  status: 'pending' | 'processing' | 'completed' | 'failed'
  progress: number
  threatLevel: 'low' | 'medium' | 'high' | 'critical'
  createdAt: string
  iocCount: number
  mitreCount: number
}

interface AnalysisState {
  // Data
  analyses: Analysis[]
  currentAnalysis: Analysis | null
  isLoading: boolean
  error: string | null
  
  // Filters
  filter: {
    status: string
    threatLevel: string
    dateRange: { start: Date | null; end: Date | null }
  }
  
  // Actions
  setAnalyses: (analyses: Analysis[]) => void
  addAnalysis: (analysis: Analysis) => void
  updateAnalysis: (id: string, updates: Partial<Analysis>) => void
  removeAnalysis: (id: string) => void
  setCurrentAnalysis: (analysis: Analysis | null) => void
  setLoading: (loading: boolean) => void
  setError: (error: string | null) => void
  setFilter: (filter: Partial<AnalysisState['filter']>) => void
  clearFilters: () => void
}

export const useAnalysisStore = create<AnalysisState>()(
  devtools(
    (set) => ({
      // Initial state
      analyses: [],
      currentAnalysis: null,
      isLoading: false,
      error: null,
      filter: {
        status: 'all',
        threatLevel: 'all',
        dateRange: { start: null, end: null }
      },
      
      // Actions
      setAnalyses: (analyses) => set({ analyses }),
      addAnalysis: (analysis) => set((state) => ({ 
        analyses: [analysis, ...state.analyses] 
      })),
      updateAnalysis: (id, updates) => set((state) => ({
        analyses: state.analyses.map(a => a.id === id ? { ...a, ...updates } : a)
      })),
      removeAnalysis: (id) => set((state) => ({
        analyses: state.analyses.filter(a => a.id !== id)
      })),
      setCurrentAnalysis: (analysis) => set({ currentAnalysis: analysis }),
      setLoading: (loading) => set({ isLoading: loading }),
      setError: (error) => set({ error }),
      setFilter: (filter) => set((state) => ({ 
        filter: { ...state.filter, ...filter } 
      })),
      clearFilters: () => set({ 
        filter: { status: 'all', threatLevel: 'all', dateRange: { start: null, end: null } } 
      })
    }),
    {
      name: 'analysis-storage',
    }
  )
)