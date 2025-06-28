import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  Menu,
  Bell,
  Search,
  User,
  Settings,
  LogOut,
  Activity,
  Clock,
  AlertTriangle,
  Database
} from 'lucide-react'
import { historyService } from '../services/historyService'
import { uploadService } from '../services/uploadService'

interface HeaderProps {
  onMenuClick: () => void
  sidebarOpen: boolean
}

const Header: React.FC<HeaderProps> = ({ onMenuClick, sidebarOpen }) => {
  const [showNotifications, setShowNotifications] = useState(false)
  const [showProfile, setShowProfile] = useState(false)
  const [recentAlerts, setRecentAlerts] = useState<any[]>([])
  const [storageInfo, setStorageInfo] = useState<any>({
    usedSpace: 0,
    totalSpace: 0,
    usagePercentage: 0
  })

  useEffect(() => {
    loadRecentAlerts()
    loadStorageInfo()
  }, [])

  const loadRecentAlerts = async () => {
    try {
      // Get recent analyses with high threat scores
      const history = await historyService.getHistory({
        limit: 3,
        min_threat_score: 70
      })

      if (history?.analyses?.length > 0) {
        const alerts = history.analyses.map((analysis: any) => ({
          id: analysis.id,
          type: analysis.threat_score > 80 ? 'warning' : 'info',
          message: `${analysis.severity.toUpperCase()} risk patterns detected in ${analysis.file_name}`,
          time: new Date(analysis.upload_time).toLocaleString()
        }))
        setRecentAlerts(alerts)
      } else {
        // Fallback to some default alerts if no high-threat analyses found
        setRecentAlerts([
          { id: 1, type: 'info', message: 'System ready for analysis', time: new Date().toLocaleString() },
          { id: 2, type: 'success', message: 'All parsers operational', time: new Date().toLocaleString() }
        ])
      }
    } catch (error) {
      console.error('Failed to load recent alerts:', error)
      // Set default alerts on error
      setRecentAlerts([
        { id: 1, type: 'info', message: 'System ready for analysis', time: new Date().toLocaleString() }
      ])
    }
  }

  const loadStorageInfo = async () => {
    try {
      const response = await uploadService.listUploads({ limit: 1 })
      if (response?.storage_info) {
        const { used_space, total_space } = response.storage_info
        const usagePercentage = total_space > 0 ? Math.round((used_space / total_space) * 100) : 0
        
        setStorageInfo({
          usedSpace: used_space,
          totalSpace: total_space,
          usagePercentage
        })
      }
    } catch (error) {
      console.error('Failed to load storage info:', error)
    }
  }

  return (
    <header className="bg-slate-900/95 backdrop-blur-sm border-b border-slate-800 px-6 py-4">
      <div className="flex items-center justify-between">
        {/* Left side */}
        <div className="flex items-center space-x-4">
          <button
            onClick={onMenuClick}
            className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
          >
            <Menu className="w-5 h-5" />
          </button>

          {/* Global Search */}
          <div className="relative hidden md:block">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search files, analyses, IOCs..."
              className="pl-10 pr-4 py-2 w-96 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
            />
          </div>
        </div>

        {/* Right side */}
        <div className="flex items-center space-x-4">
          {/* System Status */}
          <div className="hidden lg:flex items-center space-x-2 px-3 py-2 bg-slate-800 rounded-lg">
            <Activity className="w-4 h-4 text-green-400" />
            <span className="text-sm text-white">Engine: </span>
            <span className="text-sm font-medium text-green-400">Ready</span>
          </div>

          {/* Storage Status */}
          <div className="hidden lg:flex items-center space-x-2 px-3 py-2 bg-slate-800 rounded-lg">
            <Database className="w-4 h-4 text-blue-400" />
            <span className="text-sm text-white">Storage: </span>
            <span className="text-sm font-medium text-blue-400">{storageInfo.usagePercentage}% used</span>
          </div>

          {/* Notifications */}
          <div className="relative">
            <button
              onClick={() => setShowNotifications(!showNotifications)}
              className="relative p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
            >
              <Bell className="w-5 h-5" />
              {recentAlerts.length > 0 && (
                <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full"></span>
              )}
            </button>

            {showNotifications && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 10 }}
                className="absolute right-0 mt-2 w-80 bg-slate-800 border border-slate-700 rounded-lg shadow-xl z-50"
              >
                <div className="p-4 border-b border-slate-700">
                  <h3 className="text-sm font-medium text-white">Recent Alerts</h3>
                </div>
                <div className="max-h-80 overflow-y-auto">
                  {recentAlerts.length > 0 ? (
                    recentAlerts.map((alert) => (
                      <div key={alert.id} className="p-4 border-b border-slate-700 last:border-b-0 hover:bg-slate-700/50">
                        <div className="flex items-start space-x-3">
                          <AlertTriangle className={`w-4 h-4 mt-1 ${
                            alert.type === 'warning' ? 'text-yellow-400' :
                            alert.type === 'success' ? 'text-green-400' : 'text-blue-400'
                          }`} />
                          <div className="flex-1">
                            <p className="text-sm text-white">{alert.message}</p>
                            <p className="text-xs text-slate-400 mt-1">{alert.time}</p>
                          </div>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="p-4 text-center">
                      <p className="text-sm text-slate-400">No recent alerts</p>
                    </div>
                  )}
                </div>
              </motion.div>
            )}
          </div>

          {/* Profile */}
          <div className="relative">
            <button
              onClick={() => setShowProfile(!showProfile)}
              className="flex items-center space-x-2 p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
            >
              <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
                <User className="w-4 h-4 text-white" />
              </div>
              <span className="hidden md:block text-sm text-white">Analyst</span>
            </button>

            {showProfile && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 10 }}
                className="absolute right-0 mt-2 w-48 bg-slate-800 border border-slate-700 rounded-lg shadow-xl z-50"
              >
                <div className="p-4 border-b border-slate-700">
                  <p className="text-sm font-medium text-white">Forensics Analyst</p>
                  <p className="text-xs text-slate-400">Local Session</p>
                </div>
                <div className="p-2">
                  <button className="flex items-center space-x-2 w-full px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-slate-700 rounded-lg transition-colors">
                    <Settings className="w-4 h-4" />
                    <span>Settings</span>
                  </button>
                  <button className="flex items-center space-x-2 w-full px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-slate-700 rounded-lg transition-colors">
                    <LogOut className="w-4 h-4" />
                    <span>Exit</span>
                  </button>
                </div>
              </motion.div>
            )}
          </div>
        </div>
      </div>
    </header>
  )
}

export default Header