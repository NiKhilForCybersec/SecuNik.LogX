import { create } from 'zustand'
import { devtools } from 'zustand/middleware'

interface AppState {
  // System Status
  isConnected: boolean
  systemStatus: 'online' | 'offline' | 'degraded'
  activeAnalyses: number
  
  // UI State
  sidebarCollapsed: boolean
  theme: 'dark' // Only dark for now
  
  // Actions
  setConnected: (connected: boolean) => void
  setSystemStatus: (status: 'online' | 'offline' | 'degraded') => void
  setSidebarCollapsed: (collapsed: boolean) => void
  incrementActiveAnalyses: () => void
  decrementActiveAnalyses: () => void
}

export const useAppStore = create<AppState>()(
  devtools(
    (set) => ({
      // Initial state
      isConnected: false,
      systemStatus: 'offline',
      activeAnalyses: 0,
      sidebarCollapsed: false,
      theme: 'dark',
      
      // Actions
      setConnected: (connected) => set({ isConnected: connected }),
      setSystemStatus: (status) => set({ systemStatus: status }),
      setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),
      incrementActiveAnalyses: () => set((state) => ({ activeAnalyses: state.activeAnalyses + 1 })),
      decrementActiveAnalyses: () => set((state) => ({ activeAnalyses: Math.max(0, state.activeAnalyses - 1) })),
    }),
    {
      name: 'app-storage',
    }
  )
)