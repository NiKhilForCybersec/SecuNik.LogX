import React, { useState, useEffect } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  Shield,
  BarChart3,
  Upload,
  Search,
  History,
  Code2,
  FileText,
  X,
  Database,
  Cpu,
  HardDrive,
  Activity
} from 'lucide-react'
import { historyService } from '../services/historyService'
import { uploadService } from '../services/uploadService'

interface SidebarProps {
  onClose: () => void
}

const Sidebar: React.FC<SidebarProps> = ({ onClose }) => {
  const location = useLocation()
  const [stats, setStats] = useState({
    totalFiles: 0,
    threatsFound: 0,
    storageUsed: 0,
    storageTotal: 0
  })

  useEffect(() => {
    loadStats()
  }, [])

  const loadStats = async () => {
    try {
      const [historyStats, storageInfo] = await Promise.all([
        historyService.getHistoryStats(),
        uploadService.listUploads({ limit: 1 }) // Just to get storage info
      ])

      setStats({
        totalFiles: historyStats?.total_analyses || 0,
        threatsFound: historyStats?.total_threats_found || 0,
        storageUsed: storageInfo?.storage_info?.used_space || 0,
        storageTotal: storageInfo?.storage_info?.total_space || 0
      })
    } catch (error) {
      console.error('Failed to load sidebar stats:', error)
    }
  }

  const navigation = [
    { 
      name: 'Dashboard', 
      href: '/dashboard', 
      icon: BarChart3, 
      description: 'Analysis overview & statistics' 
    },
    { 
      name: 'Upload & Analyze', 
      href: '/upload', 
      icon: Upload, 
      description: 'Drag-drop files for analysis' 
    },
    { 
      name: 'Parser Studio', 
      href: '/parsers', 
      icon: Code2, 
      description: 'Custom parser development' 
    },
    { 
      name: 'Rule Manager', 
      href: '/rules', 
      icon: FileText, 
      description: 'YARA & Sigma rules' 
    },
    { 
      name: 'Analysis Results', 
      href: '/analysis', 
      icon: Search, 
      description: 'Timeline & findings view' 
    },
    { 
      name: 'History', 
      href: '/history', 
      icon: History, 
      description: 'Past analysis archive' 
    },
  ]

  // Format storage usage
  const formatStorage = () => {
    if (!stats.storageTotal) return '0 / 0 GB'
    
    const usedGB = (stats.storageUsed / (1024 * 1024 * 1024)).toFixed(1)
    const totalGB = (stats.storageTotal / (1024 * 1024 * 1024)).toFixed(1)
    
    return `${usedGB} / ${totalGB} GB`
  }

  // Calculate storage percentage
  const storagePercentage = stats.storageTotal ? 
    Math.round((stats.storageUsed / stats.storageTotal) * 100) : 0

  return (
    <div className="flex flex-col w-80 bg-slate-900/95 backdrop-blur-sm border-r border-slate-800">
      {/* Header */}
      <div className="flex items-center justify-between p-6 border-b border-slate-800">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">SecuNik LogX</h1>
            <p className="text-sm text-slate-400">Local Forensics Platform</p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors lg:hidden"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* System Status */}
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
            <span className="text-xs text-slate-400">{formatStorage()}</span>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-6 py-4 space-y-2">
        {navigation.map((item) => {
          const Icon = item.icon
          const isActive = location.pathname === item.href || 
                          (item.href === '/analysis' && location.pathname.startsWith('/analysis'))
          
          return (
            <NavLink
              key={item.name}
              to={item.href}
              className={({ isActive: linkActive }) => {
                const active = linkActive || isActive
                return `group flex flex-col px-4 py-3 text-sm font-medium rounded-lg transition-all duration-200 ${
                  active
                    ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg'
                    : 'text-slate-300 hover:text-white hover:bg-slate-800'
                }`
              }}
            >
              {({ isActive: linkActive }) => {
                const active = linkActive || isActive
                return (
                  <>
                    <div className="flex items-center space-x-3">
                      <Icon className={`h-5 w-5 transition-colors ${
                        active ? 'text-white' : 'text-slate-400 group-hover:text-white'
                      }`} />
                      <span>{item.name}</span>
                      {active && (
                        <motion.div
                          layoutId="activeTab"
                          className="ml-auto w-2 h-2 bg-white rounded-full"
                          initial={false}
                          transition={{ type: "spring", stiffness: 500, damping: 30 }}
                        />
                      )}
                    </div>
                    <p className={`text-xs mt-1 ml-8 ${
                      active ? 'text-blue-100' : 'text-slate-500 group-hover:text-slate-400'
                    }`}>
                      {item.description}
                    </p>
                  </>
                )
              }}
            </NavLink>
          )
        })}
      </nav>

      {/* Quick Stats */}
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
    </div>
  )
}

export default Sidebar