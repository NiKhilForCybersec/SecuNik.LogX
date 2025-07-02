import { IOC_TYPES, REGEX_PATTERNS } from '../../shared/config/constants'
import type { IOC, ExtractedIOC, IOCType } from '../../shared/types/api'

// IOC extraction from text
export function extractIOCs(text: string): ExtractedIOC[] {
  const iocs: ExtractedIOC[] = []
  
  // Extract IPs
  const ipv4Matches = text.match(new RegExp(REGEX_PATTERNS.IPV4.source, 'g')) || []
  ipv4Matches.forEach(match => {
    iocs.push({
      type: IOC_TYPES.IPV4,
      value: match,
      confidence: 95,
      context: getContext(text, match)
    })
  })
  
  // Extract domains
  const domainMatches = text.match(new RegExp(REGEX_PATTERNS.DOMAIN.source, 'g')) || []
  domainMatches.forEach(match => {
    // Filter out common false positives
    if (!isCommonDomain(match)) {
      iocs.push({
        type: IOC_TYPES.DOMAIN,
        value: match,
        confidence: 85,
        context: getContext(text, match)
      })
    }
  })
  
  // Extract hashes
  const md5Matches = text.match(new RegExp(REGEX_PATTERNS.MD5.source, 'gi')) || []
  md5Matches.forEach(match => {
    iocs.push({
      type: IOC_TYPES.MD5,
      value: match.toLowerCase(),
      confidence: 100,
      context: getContext(text, match)
    })
  })
  
  const sha256Matches = text.match(new RegExp(REGEX_PATTERNS.SHA256.source, 'gi')) || []
  sha256Matches.forEach(match => {
    iocs.push({
      type: IOC_TYPES.SHA256,
      value: match.toLowerCase(),
      confidence: 100,
      context: getContext(text, match)
    })
  })
  
  return deduplicateIOCs(iocs)
}

// Get context around IOC
function getContext(text: string, ioc: string, contextLength: number = 50): string {
  const index = text.indexOf(ioc)
  if (index === -1) return ''
  
  const start = Math.max(0, index - contextLength)
  const end = Math.min(text.length, index + ioc.length + contextLength)
  
  let context = text.substring(start, end)
  if (start > 0) context = '...' + context
  if (end < text.length) context = context + '...'
  
  return context
}

// Deduplicate IOCs
function deduplicateIOCs(iocs: ExtractedIOC[]): ExtractedIOC[] {
  const seen = new Map<string, ExtractedIOC>()
  
  iocs.forEach(ioc => {
    const key = `${ioc.type}:${ioc.value}`
    const existing = seen.get(key)
    
    if (!existing || existing.confidence < ioc.confidence) {
      seen.set(key, ioc)
    }
  })
  
  return Array.from(seen.values())
}

// Check if domain is common/benign
function isCommonDomain(domain: string): boolean {
  const commonDomains = [
    'localhost',
    'example.com',
    'test.com',
    'google.com',
    'microsoft.com',
    'windows.com',
    'apple.com'
  ]
  
  return commonDomains.some(common => 
    domain === common || domain.endsWith(`.${common}`)
  )
}

// Validate IOC format
export function isValidIOC(value: string, type: IOCType): boolean {
  const pattern = REGEX_PATTERNS[type.toUpperCase() as keyof typeof REGEX_PATTERNS]
  return pattern ? pattern.test(value) : false
}

// Group IOCs by type
export function groupIOCsByType(iocs: IOC[]): Record<IOCType, IOC[]> {
  return iocs.reduce((acc, ioc) => {
    if (!acc[ioc.type]) acc[ioc.type] = []
    acc[ioc.type].push(ioc)
    return acc
  }, {} as Record<IOCType, IOC[]>)
}

// Calculate IOC statistics
export function calculateIOCStats(iocs: IOC[]) {
  const grouped = groupIOCsByType(iocs)
  const typeCount = Object.entries(grouped).map(([type, items]) => ({
    type,
    count: items.length,
    avgConfidence: items.reduce((sum, ioc) => sum + ioc.confidence, 0) / items.length
  }))
  
  return {
    total: iocs.length,
    byType: typeCount,
    highConfidence: iocs.filter(ioc => ioc.confidence >= 90).length,
    uniqueTypes: Object.keys(grouped).length
  }
}

// Export IOCs to different formats
export function exportIOCs(iocs: IOC[], format: 'json' | 'csv' | 'stix'): string {
  switch (format) {
    case 'json':
      return JSON.stringify(iocs, null, 2)
      
    case 'csv':
      const headers = ['Type', 'Value', 'Confidence', 'First Seen', 'Context']
      const rows = iocs.map(ioc => [
        ioc.type,
        ioc.value,
        ioc.confidence.toString(),
        ioc.firstSeen,
        ioc.context.replace(/,/g, ';')
      ])
      return [headers, ...rows].map(row => row.join(',')).join('\n')
      
    case 'stix':
      // Simplified STIX 2.1 format
      return JSON.stringify({
        type: 'bundle',
        id: `bundle--${crypto.randomUUID()}`,
        objects: iocs.map(ioc => ({
          type: 'indicator',
          id: `indicator--${crypto.randomUUID()}`,
          created: ioc.firstSeen,
          modified: ioc.lastSeen || ioc.firstSeen,
          pattern: `[${getSTIXPattern(ioc)}]`,
          labels: ['malicious-activity'],
          confidence: ioc.confidence
        }))
      }, null, 2)
      
    default:
      throw new Error(`Unsupported format: ${format}`)
  }
}

// Get STIX pattern for IOC
function getSTIXPattern(ioc: IOC): string {
  switch (ioc.type) {
    case IOC_TYPES.IPV4:
      return `ipv4-addr:value = '${ioc.value}'`
    case IOC_TYPES.DOMAIN:
      return `domain-name:value = '${ioc.value}'`
    case IOC_TYPES.URL:
      return `url:value = '${ioc.value}'`
    case IOC_TYPES.MD5:
      return `file:hashes.MD5 = '${ioc.value}'`
    case IOC_TYPES.SHA256:
      return `file:hashes.SHA256 = '${ioc.value}'`
    default:
      return `x-custom:value = '${ioc.value}'`
  }
}

// Search IOCs in threat intelligence feeds
export async function checkThreatIntel(ioc: string): Promise<{
  malicious: boolean
  sources: string[]
  lastSeen?: string
}> {
  // This would integrate with threat intel APIs
  // For now, return mock data
  const knownBad = ['192.168.1.100', 'malicious.com', 'evil.exe']
  
  return {
    malicious: knownBad.includes(ioc),
    sources: knownBad.includes(ioc) ? ['VirusTotal', 'AlienVault'] : [],
    lastSeen: knownBad.includes(ioc) ? new Date().toISOString() : undefined
  }
}