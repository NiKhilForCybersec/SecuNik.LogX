import { Shield, GitBranch, Calendar, ArrowRight } from 'lucide-react'

export default function RulePage() {
  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">
          Detection Rules
        </h1>
        <p className="text-slate-400">
          Manage and deploy forensic detection rules
        </p>
      </div>
      
      {/* Coming Soon Card */}
      <div className="bg-slate-900 rounded-lg p-8 border border-slate-800 text-center max-w-2xl mx-auto mt-12">
        <Shield className="w-16 h-16 text-blue-400 mx-auto mb-6" />
        <h2 className="text-2xl font-semibold text-white mb-4">
          Rule Management Coming Soon
        </h2>
        <p className="text-slate-400 mb-8 max-w-lg mx-auto">
          The rule management system will allow you to create, edit, and deploy custom detection rules 
          for forensic analysis. This feature is currently under development.
        </p>
        
        {/* Feature Preview */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-8 text-left">
          <div className="bg-slate-800/50 rounded-lg p-4">
            <GitBranch className="w-8 h-8 text-green-400 mb-3" />
            <h3 className="text-white font-medium mb-1">Version Control</h3>
            <p className="text-sm text-slate-400">
              Track rule changes with built-in versioning
            </p>
          </div>
          <div className="bg-slate-800/50 rounded-lg p-4">
            <Shield className="w-8 h-8 text-blue-400 mb-3" />
            <h3 className="text-white font-medium mb-1">Rule Templates</h3>
            <p className="text-sm text-slate-400">
              Start with pre-built detection templates
            </p>
          </div>
          <div className="bg-slate-800/50 rounded-lg p-4">
            <Calendar className="w-8 h-8 text-purple-400 mb-3" />
            <h3 className="text-white font-medium mb-1">Scheduled Scans</h3>
            <p className="text-sm text-slate-400">
              Automate rule execution on schedules
            </p>
          </div>
        </div>
        
        {/* Timeline */}
        <div className="mt-12 pt-8 border-t border-slate-800">
          <div className="flex items-center justify-center text-sm text-slate-400">
            <span>Expected in Batch 11</span>
            <ArrowRight className="w-4 h-4 mx-2" />
            <span className="text-blue-400 font-medium">Q1 2025</span>
          </div>
        </div>
      </div>
    </div>
  )
}