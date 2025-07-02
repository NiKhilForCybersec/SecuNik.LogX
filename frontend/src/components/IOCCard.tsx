import { useState } from 'react'
import { 
  Globe, 
  Hash, 
  AtSign, 
  FileText, 
  Server,
  Shield,
  AlertTriangle,
  Copy,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Clock,
  Info
} from 'lucide-react'
import clsx from 'clsx'

interface IOCEnrichment {
  source: string
  reputation?: number
  tags?: string[]
  lastSeen?: string
  reportCount?: number
  geoLocation?: string
  asn?: string
  registrar?: string
}

interface IOCData {
  id: string
  type: 'ip' | 'domain' | 'hash' | 'email' | 'file' | 'url'
  value: string
  confidence: number
  threatLevel: 'low' | 'medium' | 'high' | 'critical'
  context: string
  firstSeen: string
  lastSeen?: string
  enrichments?: IOCEnrichment[]
  relatedIOCs?: number
  tags?: string[]
}

interface IOCCardProps {
  data: IOCData
  className?: string
  expandable?: boolean
}

export default function IOCCard({ data, className, expandable = true }: IOCCardProps) {
  const [isExpanded, setIsExpanded] = useState(false)
  const [copySuccess, setCopySuccess] = useState(false)

  const getIcon = () => {
    switch (data.type) {
      case 'ip':
        return <Server className="w-5 h-5" />
      case 'domain':
      case 'url':
        return <Globe className="w-5 h-5" />
      case 'hash':
        return <Hash className="w-5 h-5" />
      case 'email':
        return <AtSign className="w-5 h-5" />
      case 'file':
        return <FileText className="w-5 h-5" />
      default:
        return <Shield className="w-5 h-5" />
    }
  }

  const getThreatColor = () => {
    switch (data.threatLevel) {
      case 'critical':
        return 'text-red-400 bg-red-500/10 border-red-500/30'
      case 'high':
        return 'text-orange-400 bg-orange-500/10 border-orange-500/30'
      case 'medium':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30'
      default:
        return 'text-green-400 bg-green-500/10 border-green-500/30'
    }
  }

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 80) return 'text-green-400'
    if (confidence >= 60) return 'text-yellow-400'
    return 'text-orange-400'
  }

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(data.value)
      setCopySuccess(true)
      setTimeout(() => setCopySuccess(false), 2000)
    } catch (err) {
      console.error('Failed to copy:', err)
    }
  }

  const handleExternalLookup = () => {
    let url = ''
    switch (data.type) {
      case 'ip':
        url = `https://www.virustotal.com/gui/ip-address/${data.value}`
        break
      case 'domain':
        url = `https://www.virustotal.com/gui/domain/${data.value}`
        break
      case 'hash':
        url = `https://www.virustotal.com/gui/file/${data.value}`
        break
      case 'url':
        url = `https://www.virustotal.com/gui/url/${encodeURIComponent(data.value)}`
        break
    }
    if (url) window.open(url, '_blank')
  }

  return (
    <div className={clsx(
      'bg-slate-900 rounded-lg border border-slate-800 overflow-hidden',
      className
    )}>
      {/* Header */}
      <div className="p-4">
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center space-x-3">
            <div className={clsx(
              'p-2 rounded-lg',
              getThreatColor()
            )}>
              {getIcon()}
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xs text-slate-400 uppercase tracking-wider">
                  {data.type}
                </span>
                <span className={clsx(
                  'px-2 py-0.5 text-xs rounded-full font-medium',
                  getThreatColor()
                )}>
                  {data.threatLevel.toUpperCase()}
                </span>
              </div>
              <div className="flex items-center space-x-2 mt-1">
                <code className="text-sm text-white font-mono break-all">
                  {data.value}
                </code>
              </div>
            </div>
          </div>
          
          <div className="flex items-center space-x-1">
            <button
              onClick={handleCopy}
              className="p-1.5 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition-colors"
              title="Copy IOC"
            >
              {copySuccess ? (
                <span className="text-xs text-green-400">✓</span>
              ) : (
                <Copy className="w-4 h-4" />
              )}
            </button>
            {['ip', 'domain', 'hash', 'url'].includes(data.type) && (
              <button
                onClick={handleExternalLookup}
                className="p-1.5 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition-colors"
                title="External lookup"
              >
                <ExternalLink className="w-4 h-4" />
              </button>
            )}
            {expandable && (
              <button
                onClick={() => setIsExpanded(!isExpanded)}
                className="p-1.5 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition-colors"
                title={isExpanded ? 'Collapse' : 'Expand'}
              >
                {isExpanded ? (
                  <ChevronUp className="w-4 h-4" />
                ) : (
                  <ChevronDown className="w-4 h-4" />
                )}
              </button>
            )}
          </div>
        </div>

        {/* Key Metrics */}
        <div className="grid grid-cols-3 gap-3">
          <div className="bg-slate-800/50 rounded p-2">
            <div className="text-xs text-slate-400 mb-1">Confidence</div>
            <div className={clsx(
              'text-lg font-semibold',
              getConfidenceColor(data.confidence)
            )}>
              {data.confidence}%
            </div>
          </div>
          
          {data.relatedIOCs !== undefined && (
            <div className="bg-slate-800/50 rounded p-2">
              <div className="text-xs text-slate-400 mb-1">Related IOCs</div>
              <div className="text-lg font-semibold text-white">
                {data.relatedIOCs}
              </div>
            </div>
          )}
          
          <div className="bg-slate-800/50 rounded p-2">
            <div className="text-xs text-slate-400 mb-1">First Seen</div>
            <div className="text-sm font-medium text-white">
              {new Date(data.firstSeen).toLocaleDateString()}
            </div>
          </div>
        </div>

        {/* Context */}
        <div className="mt-3 pt-3 border-t border-slate-800">
          <div className="flex items-start space-x-2">
            <Info className="w-4 h-4 text-slate-400 mt-0.5 flex-shrink-0" />
            <p className="text-sm text-slate-300">{data.context}</p>
          </div>
        </div>

        {/* Tags */}
        {data.tags && data.tags.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-2">
            {data.tags.map((tag, index) => (
              <span
                key={index}
                className="px-2 py-1 text-xs bg-blue-500/20 text-blue-400 rounded-full"
              >
                {tag}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Expanded Content */}
      {isExpanded && data.enrichments && data.enrichments.length > 0 && (
        <div className="border-t border-slate-800 p-4 bg-slate-800/30">
          <h4 className="text-sm font-medium text-white mb-3">
            Threat Intelligence Enrichment
          </h4>
          
          <div className="space-y-3">
            {data.enrichments.map((enrichment, index) => (
              <div
                key={index}
                className="bg-slate-900 rounded-lg p-3 border border-slate-700"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-white">
                    {enrichment.source}
                  </span>
                  {enrichment.reputation !== undefined && (
                    <div className="flex items-center space-x-2">
                      <span className="text-xs text-slate-400">Reputation:</span>
                      <span className={clsx(
                        'text-sm font-medium',
                        enrichment.reputation < 30 ? 'text-red-400' :
                        enrichment.reputation < 70 ? 'text-yellow-400' :
                        'text-green-400'
                      )}>
                        {enrichment.reputation}/100
                      </span>
                    </div>
                  )}
                </div>
                
                <div className="grid grid-cols-2 gap-2 text-xs">
                  {enrichment.geoLocation && (
                    <div>
                      <span className="text-slate-400">Location:</span>{' '}
                      <span className="text-slate-300">{enrichment.geoLocation}</span>
                    </div>
                  )}
                  {enrichment.asn && (
                    <div>
                      <span className="text-slate-400">ASN:</span>{' '}
                      <span className="text-slate-300">{enrichment.asn}</span>
                    </div>
                  )}
                  {enrichment.registrar && (
                    <div>
                      <span className="text-slate-400">Registrar:</span>{' '}
                      <span className="text-slate-300">{enrichment.registrar}</span>
                    </div>
                  )}
                  {enrichment.lastSeen && (
                    <div>
                      <span className="text-slate-400">Last Seen:</span>{' '}
                      <span className="text-slate-300">
                        {new Date(enrichment.lastSeen).toLocaleDateString()}
                      </span>
                    </div>
                  )}
                  {enrichment.reportCount !== undefined && (
                    <div>
                      <span className="text-slate-400">Reports:</span>{' '}
                      <span className="text-slate-300">{enrichment.reportCount}</span>
                    </div>
                  )}
                </div>
                
                {enrichment.tags && enrichment.tags.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {enrichment.tags.map((tag, tagIndex) => (
                      <span
                        key={tagIndex}
                        className="px-1.5 py-0.5 text-xs bg-slate-700 text-slate-300 rounded"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}