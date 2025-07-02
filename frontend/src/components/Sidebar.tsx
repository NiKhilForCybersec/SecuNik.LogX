import { Link, useLocation } from 'react-router-dom'
import { 
  Home, 
  Search, 
  Shield, 
  Code,
  Activity,
  Database,
  X,
  ChevronLeft,
  ChevronRight 
} from 'lucide-react'
import { useState } from 'react'

interface SidebarProps {
  onClose?: () => void
}

interface NavItem {
  path: string
  label: string
  description: string
  icon: React.ComponentType<{ className?: string }>
}

export default function Sidebar({ onClose }: SidebarProps) {
  const location = useLocation()
  const [isCollapsed, setIsCollapsed] = useState(false)
  
  const navItems: NavItem[] = [
    { 
      path: '/', 
      label: 'Dashboard', 
      description: 'Overview and analytics',
      icon: Home 
    },
    { 
      path: '/analysis', 
      label: 'Analysis', 
      description: 'Forensic file analysis',
      icon: Search 
    },
    { 
      path: '/rules', 
      label: 'Detection Rules', 
      description: 'YARA and Sigma rules',
      icon: Shield 
    },
    { 
      path: '/parsers', 
      label: 'Log Parsers', 
      description: 'Custom log parsers',
      icon: Code 
    },
  ]
  
  // Mock stats for now - will be connected to stores in later batches
  const stats = {
    totalFiles: 0,
    threatsFound: 0,
    storageUsed: 0,
    storageTotal: 100
  }
  
  return (
    <nav className={`${
      isCollapsed ? 'w-20' : 'w-80'
    } bg-slate-900/95 backdrop-blur-sm border-r border-slate-800 transition-all duration-300 flex flex-col h-full`}>
      {/* Header */}
      <div className="flex items-center justify-between p-6 border-b border-slate-800">
        <div className={`flex items-center space-x-3 ${isCollapsed ? 'hidden' : 'flex'}`}>
          <div className="p-2 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">SecuNik LogX</h1>
            <p className="text-sm text-slate-400">Local Forensics Platform</p>
          </div>
        </div>
        
        {/* Collapse button for desktop */}
        <button
          onClick={() => setIsCollapsed(!isCollapsed)}
          className="hidden lg:block p-2 hover:bg-slate-800 rounded-lg transition-colors text-slate-400 hover:text-white"
        >
          {isCollapsed ? <ChevronRight size={20} /> : <ChevronLeft size={20} />}
        </button>
        
        {/* Close button for mobile */}
        {onClose && (
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors lg:hidden"
          >
            <X className="w-5 h-5" />
          </button>
        )}
        
        {/* Icon only when collapsed */}
        {isCollapsed && (
          <div className="p-2 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg">
            <Shield className="w-6 h-6 text-white" />
          </div>
        )}
      </div>
      
      {/* System Status */}
      {!isCollapsed && (
        <div className="px-6 py-4 border-b border-slate-800">
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
              <div className="flex items-center space-x-2">
                <Activity className="w-4 h-4 text-green-400" />
                <span className="text-sm text-white">Analysis Engine</span>
              </div>
              <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
            </div>
            
            <div className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
              <div className="flex items-center space-x-2">
                <Database className="w-4 h-4 text-blue-400" />
                <span className="text-sm text-white">Local Storage</span>
              </div>
              <span className="text-xs text-slate-400">{stats.storageUsed} GB / {stats.storageTotal} GB</span>
            </div>
          </div>
        </div>
      )}
      
      {/* Navigation Items */}
      <nav className="flex-1 px-6 py-4 space-y-2 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon
          const isActive = location.pathname === item.path || 
                          (item.path === '/analysis' && location.pathname.startsWith('/analysis'))
          
          return (
            <Link
              key={item.path}
              to={item.path}
              className={`
                group flex flex-col px-4 py-3 rounded-lg transition-all duration-200
                ${isActive 
                  ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg' 
                  : 'text-slate-300 hover:text-white hover:bg-slate-800'
                }
              `}
            >
              <div className="flex items-center space-x-3">
                <Icon className={`h-5 w-5 transition-colors ${
                  isActive ? 'text-white' : 'text-slate-400 group-hover:text-white'
                }`} />
                {!isCollapsed && (
                  <>
                    <span className="font-medium">{item.label}</span>
                    {isActive && (
                      <div className="ml-auto w-2 h-2 bg-white rounded-full" />
                    )}
                  </>
                )}
              </div>
              {!isCollapsed && (
                <p className={`text-xs mt-1 ml-8 ${
                  isActive ? 'text-blue-100' : 'text-slate-500 group-hover:text-slate-400'
                }`}>
                  {item.description}
                </p>
              )}
            </Link>
          )
        })}
      </nav>
      
      {/* Quick Stats */}
      {!isCollapsed && (
        <div className="p-6 border-t border-slate-800">
          <div className="grid grid-cols-2 gap-3">
            <div className="text-center p-3 bg-slate-800/30 rounded-lg">
              <div className="text-lg font-bold text-white">{stats.totalFiles}</div>
              <div className="text-xs text-slate-400">Total Files</div>
            </div>
            <div className="text-center p-3 bg-slate-800/30 rounded-lg">
              <div className="text-lg font-bold text-orange-400">{stats.threatsFound}</div>
              <div className="text-xs text-slate-400">Threats Found</div>
            </div>
          </div>
        </div>
      )}
    </nav>
  )
}