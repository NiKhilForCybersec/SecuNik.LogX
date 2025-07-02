import { useState } from 'react'
import { Info, ExternalLink, Shield } from 'lucide-react'
import clsx from 'clsx'

interface MITRETechnique {
  techniqueId: string
  name: string
  tactic: string
  confidence: number
  description?: string
  detections?: number
  subTechniques?: string[]
}

interface MITREMatrixProps {
  techniques: MITRETechnique[]
  className?: string
}

// MITRE ATT&CK tactics in order
const TACTICS = [
  { id: 'reconnaissance', name: 'Reconnaissance', color: 'blue' },
  { id: 'resource-development', name: 'Resource Development', color: 'indigo' },
  { id: 'initial-access', name: 'Initial Access', color: 'purple' },
  { id: 'execution', name: 'Execution', color: 'pink' },
  { id: 'persistence', name: 'Persistence', color: 'red' },
  { id: 'privilege-escalation', name: 'Privilege Escalation', color: 'orange' },
  { id: 'defense-evasion', name: 'Defense Evasion', color: 'amber' },
  { id: 'credential-access', name: 'Credential Access', color: 'yellow' },
  { id: 'discovery', name: 'Discovery', color: 'lime' },
  { id: 'lateral-movement', name: 'Lateral Movement', color: 'green' },
  { id: 'collection', name: 'Collection', color: 'emerald' },
  { id: 'command-and-control', name: 'Command and Control', color: 'teal' },
  { id: 'exfiltration', name: 'Exfiltration', color: 'cyan' },
  { id: 'impact', name: 'Impact', color: 'sky' }
]

export default function MITREMatrix({ techniques, className }: MITREMatrixProps) {
  const [selectedTechnique, setSelectedTechnique] = useState<MITRETechnique | null>(null)
  const [hoveredTechnique, setHoveredTechnique] = useState<string | null>(null)

  // Group techniques by tactic
  const techniquesByTactic = techniques.reduce((acc, technique) => {
    const tacticId = technique.tactic.toLowerCase().replace(/\s+/g, '-')
    if (!acc[tacticId]) acc[tacticId] = []
    acc[tacticId].push(technique)
    return acc
  }, {} as Record<string, MITRETechnique[]>)

  // Get confidence color
  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 80) return 'bg-red-500/20 border-red-500/50 text-red-400'
    if (confidence >= 60) return 'bg-orange-500/20 border-orange-500/50 text-orange-400'
    if (confidence >= 40) return 'bg-yellow-500/20 border-yellow-500/50 text-yellow-400'
    return 'bg-blue-500/20 border-blue-500/50 text-blue-400'
  }

  const getHeatmapIntensity = (confidence: number) => {
    return `${confidence}%`
  }

  return (
    <div className={clsx('space-y-4', className)}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <Shield className="w-5 h-5 text-purple-400" />
          <h3 className="text-lg font-semibold text-white">MITRE ATT&CK Matrix</h3>
          <span className="text-sm text-slate-400">
            {techniques.length} techniques detected
          </span>
        </div>
        
        {/* Legend */}
        <div className="flex items-center space-x-4 text-xs">
          <span className="text-slate-400">Confidence:</span>
          <div className="flex items-center space-x-2">
            <div className="flex items-center space-x-1">
              <div className="w-3 h-3 bg-blue-500/20 border border-blue-500/50 rounded"></div>
              <span className="text-slate-400">Low</span>
            </div>
            <div className="flex items-center space-x-1">
              <div className="w-3 h-3 bg-yellow-500/20 border border-yellow-500/50 rounded"></div>
              <span className="text-slate-400">Medium</span>
            </div>
            <div className="flex items-center space-x-1">
              <div className="w-3 h-3 bg-orange-500/20 border border-orange-500/50 rounded"></div>
              <span className="text-slate-400">High</span>
            </div>
            <div className="flex items-center space-x-1">
              <div className="w-3 h-3 bg-red-500/20 border border-red-500/50 rounded"></div>
              <span className="text-slate-400">Critical</span>
            </div>
          </div>
        </div>
      </div>

      {/* Matrix Grid */}
      <div className="overflow-x-auto">
        <div className="min-w-max bg-slate-900 rounded-lg border border-slate-800 p-4">
          <div className="grid grid-cols-7 gap-2">
            {TACTICS.map((tactic) => (
              <div key={tactic.id} className="space-y-2">
                {/* Tactic Header */}
                <div className="text-center p-2 bg-slate-800 rounded-lg">
                  <h4 className="text-xs font-medium text-white whitespace-nowrap">
                    {tactic.name}
                  </h4>
                </div>
                
                {/* Techniques */}
                <div className="space-y-1">
                  {techniquesByTactic[tactic.id]?.map((technique) => (
                    <button
                      key={technique.techniqueId}
                      onClick={() => setSelectedTechnique(technique)}
                      onMouseEnter={() => setHoveredTechnique(technique.techniqueId)}
                      onMouseLeave={() => setHoveredTechnique(null)}
                      className={clsx(
                        'w-full p-2 rounded border text-xs font-medium transition-all',
                        getConfidenceColor(technique.confidence),
                        'hover:scale-105 hover:shadow-lg'
                      )}
                      style={{
                        opacity: hoveredTechnique && hoveredTechnique !== technique.techniqueId ? 0.5 : 1
                      }}
                    >
                      <div className="text-left">
                        <div className="font-mono">{technique.techniqueId}</div>
                        <div className="text-[10px] opacity-75 line-clamp-2">
                          {technique.name}
                        </div>
                      </div>
                    </button>
                  )) || (
                    <div className="h-16 border border-dashed border-slate-700 rounded"></div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Technique Detail Modal */}
      {selectedTechnique && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 rounded-lg border border-slate-800 max-w-2xl w-full max-h-[80vh] overflow-y-auto">
            {/* Modal Header */}
            <div className="sticky top-0 bg-slate-900 border-b border-slate-800 p-4">
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="text-lg font-semibold text-white">
                    {selectedTechnique.techniqueId}: {selectedTechnique.name}
                  </h3>
                  <div className="flex items-center space-x-3 mt-1">
                    <span className="text-sm text-slate-400">
                      Tactic: {selectedTechnique.tactic}
                    </span>
                    <span className={clsx(
                      'px-2 py-0.5 text-xs rounded-full',
                      getConfidenceColor(selectedTechnique.confidence)
                    )}>
                      {selectedTechnique.confidence}% Confidence
                    </span>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedTechnique(null)}
                  className="text-slate-400 hover:text-white"
                >
                  ✕
                </button>
              </div>
            </div>
            
            {/* Modal Content */}
            <div className="p-4 space-y-4">
              {selectedTechnique.description && (
                <div>
                  <h4 className="text-sm font-medium text-white mb-2">Description</h4>
                  <p className="text-sm text-slate-300">
                    {selectedTechnique.description}
                  </p>
                </div>
              )}
              
              {selectedTechnique.detections !== undefined && (
                <div className="bg-slate-800/50 rounded-lg p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-400">Detections</span>
                    <span className="text-2xl font-bold text-white">
                      {selectedTechnique.detections}
                    </span>
                  </div>
                </div>
              )}
              
              {selectedTechnique.subTechniques && selectedTechnique.subTechniques.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-white mb-2">Sub-techniques</h4>
                  <div className="flex flex-wrap gap-2">
                    {selectedTechnique.subTechniques.map((subTechnique, index) => (
                      <span
                        key={index}
                        className="px-2 py-1 text-xs bg-slate-800 text-slate-300 rounded"
                      >
                        {subTechnique}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              
              <div className="pt-2">
                <a
                  href={`https://attack.mitre.org/techniques/${selectedTechnique.techniqueId.replace('.', '/')}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center space-x-2 text-sm text-blue-400 hover:text-blue-300"
                >
                  <ExternalLink className="w-4 h-4" />
                  <span>View on MITRE ATT&CK</span>
                </a>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}