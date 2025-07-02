import { Bell, Settings, User, Menu, Clock } from 'lucide-react'

interface HeaderProps {
  onMenuClick?: () => void
}

export default function Header({ onMenuClick }: HeaderProps) {
  const currentTime = new Date().toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit'
  })

  return (
    <header className="h-16 bg-slate-900/95 backdrop-blur-sm border-b border-slate-800 px-6 flex items-center justify-between">
      {/* Left Section */}
      <div className="flex items-center space-x-4">
        {/* Mobile menu button */}
        <button
          onClick={onMenuClick}
          className="p-2 hover:bg-slate-800 rounded-lg transition-colors text-slate-400 hover:text-slate-100 lg:hidden"
        >
          <Menu size={20} />
        </button>
        
        <div>
          <h2 className="text-lg font-semibold text-slate-100">
            Digital Forensics Platform
          </h2>
          <div className="flex items-center space-x-2 text-xs text-slate-400">
            <Clock className="w-3 h-3" />
            <span>Last sync: {currentTime}</span>
          </div>
        </div>
      </div>
      
      {/* Right Section */}
      <div className="flex items-center space-x-4">
        {/* Version Badge */}
        <span className="text-xs px-2 py-1 bg-slate-800 rounded text-slate-400">
          v1.0.0
        </span>
        
        {/* Status Indicator */}
        <div className="flex items-center space-x-2 px-3 py-1 bg-slate-800/50 rounded-lg">
          <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
          <span className="text-xs text-slate-400">System Online</span>
        </div>
        
        {/* Future Action Buttons - No functionality yet */}
        <div className="flex items-center space-x-2">
          <button className="p-2 hover:bg-slate-800 rounded-lg transition-colors text-slate-400 hover:text-slate-100">
            <Bell size={20} />
          </button>
          <button className="p-2 hover:bg-slate-800 rounded-lg transition-colors text-slate-400 hover:text-slate-100">
            <Settings size={20} />
          </button>
          <button className="p-2 hover:bg-slate-800 rounded-lg transition-colors text-slate-400 hover:text-slate-100">
            <User size={20} />
          </button>
        </div>
      </div>
    </header>
  )
}