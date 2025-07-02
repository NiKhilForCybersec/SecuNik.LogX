import { Code, FileCode, Zap, ArrowRight } from 'lucide-react'

export default function ParserPage() {
  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">
          Parser Development
        </h1>
        <p className="text-slate-400">
          Create custom parsers for forensic artifacts
        </p>
      </div>
      
      {/* Coming Soon Card */}
      <div className="bg-slate-900 rounded-lg p-8 border border-slate-800 text-center max-w-2xl mx-auto mt-12">
        <Code className="w-16 h-16 text-purple-400 mx-auto mb-6" />
        <h2 className="text-2xl font-semibold text-white mb-4">
          Parser Studio Coming Soon
        </h2>
        <p className="text-slate-400 mb-8 max-w-lg mx-auto">
          The parser development studio will provide a powerful environment for creating custom parsers 
          to extract and analyze data from various forensic artifact formats.
        </p>
        
        {/* Feature Preview */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-8 text-left">
          <div className="bg-slate-800/50 rounded-lg p-4">
            <FileCode className="w-8 h-8 text-orange-400 mb-3" />
            <h3 className="text-white font-medium mb-1">Visual Editor</h3>
            <p className="text-sm text-slate-400">
              Build parsers with drag-and-drop components
            </p>
          </div>
          <div className="bg-slate-800/50 rounded-lg p-4">
            <Zap className="w-8 h-8 text-yellow-400 mb-3" />
            <h3 className="text-white font-medium mb-1">Live Testing</h3>
            <p className="text-sm text-slate-400">
              Test parsers on sample data in real-time
            </p>
          </div>
          <div className="bg-slate-800/50 rounded-lg p-4">
            <Code className="w-8 h-8 text-purple-400 mb-3" />
            <h3 className="text-white font-medium mb-1">Code Generation</h3>
            <p className="text-sm text-slate-400">
              Export parsers as reusable modules
            </p>
          </div>
        </div>
        
        {/* Supported Formats Preview */}
        <div className="mt-8 p-4 bg-slate-800/30 rounded-lg">
          <h3 className="text-sm font-medium text-slate-300 mb-3">
            Planned Format Support
          </h3>
          <div className="flex flex-wrap gap-2 justify-center">
            {['JSON', 'XML', 'CSV', 'Binary', 'Registry', 'EventLog', 'PCAP', 'Memory Dump'].map(format => (
              <span key={format} className="px-3 py-1 bg-slate-800 text-slate-300 rounded-full text-xs">
                {format}
              </span>
            ))}
          </div>
        </div>
        
        {/* Timeline */}
        <div className="mt-12 pt-8 border-t border-slate-800">
          <div className="flex items-center justify-center text-sm text-slate-400">
            <span>Expected in Batch 12</span>
            <ArrowRight className="w-4 h-4 mx-2" />
            <span className="text-purple-400 font-medium">Q2 2025</span>
          </div>
        </div>
      </div>
    </div>
  )
}