import { MITRE_CONFIG } from '../../shared/config/constants'
import type { MITRETechnique, IOC } from '../../shared/types/api'

// MITRE technique database (simplified)
const TECHNIQUE_DATABASE: MITRETechnique[] = [
  {
    techniqueId: 'T1059',
    name: 'Command and Scripting Interpreter',
    description: 'Adversaries may abuse command and script interpreters to execute commands',
    tactic: 'Execution',
    confidence: 0,
    evidence: []
  },
  {
    techniqueId: 'T1055',
    name: 'Process Injection',
    description: 'Adversaries may inject code into processes',
    tactic: 'Defense Evasion',
    confidence: 0,
    evidence: []
  },
  {
    techniqueId: 'T1082',
    name: 'System Information Discovery',
    description: 'Adversaries may attempt to get detailed information about the system',
    tactic: 'Discovery',
    confidence: 0,
    evidence: []
  },
  {
    techniqueId: 'T1071',
    name: 'Application Layer Protocol',
    description: 'Adversaries may communicate using application layer protocols',
    tactic: 'Command and Control',
    confidence: 0,
    evidence: []
  },
  {
    techniqueId: 'T1486',
    name: 'Data Encrypted for Impact',
    description: 'Adversaries may encrypt data on target systems',
    tactic: 'Impact',
    confidence: 0,
    evidence: []
  }
]

// Map IOCs to MITRE techniques
export function mapIOCsToTechniques(iocs: IOC[], logContent?: string): MITRETechnique[] {
  const techniques: MITRETechnique[] = []
  
  // Check for command execution patterns
  if (hasCommandExecution(iocs, logContent)) {
    techniques.push({
      ...TECHNIQUE_DATABASE[0],
      confidence: 85,
      evidence: ['PowerShell commands detected', 'cmd.exe execution found']
    })
  }
  
  // Check for process injection indicators
  if (hasProcessInjection(iocs, logContent)) {
    techniques.push({
      ...TECHNIQUE_DATABASE[1],
      confidence: 75,
      evidence: ['Suspicious process memory modifications', 'Code injection patterns']
    })
  }
  
  // Check for system discovery
  if (hasSystemDiscovery(iocs, logContent)) {
    techniques.push({
      ...TECHNIQUE_DATABASE[2],
      confidence: 70,
      evidence: ['System enumeration commands', 'WMI queries detected']
    })
  }
  
  // Check for C2 communication
  if (hasC2Communication(iocs)) {
    techniques.push({
      ...TECHNIQUE_DATABASE[3],
      confidence: 80,
      evidence: ['External IP connections', 'Suspicious domains contacted']
    })
  }
  
  // Check for ransomware indicators
  if (hasRansomwareIndicators(iocs, logContent)) {
    techniques.push({
      ...TECHNIQUE_DATABASE[4],
      confidence: 90,
      evidence: ['File encryption activity', 'Ransom note files created']
    })
  }
  
  return techniques.filter(t => t.confidence >= MITRE_CONFIG.CONFIDENCE_THRESHOLD)
}

// Detection helper functions
function hasCommandExecution(iocs: IOC[], logContent?: string): boolean {
  const cmdIndicators = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']
  const hasProcessIOC = iocs.some(ioc => 
    ioc.type === 'process' && cmdIndicators.some(cmd => ioc.value.toLowerCase().includes(cmd))
  )
  
  if (logContent) {
    const cmdPatterns = /(?:cmd|powershell|wscript)(?:\.exe)?\s+.*(?:\/c|\/k|-command|-file)/gi
    return cmdPatterns.test(logContent) || hasProcessIOC
  }
  
  return hasProcessIOC
}

function hasProcessInjection(iocs: IOC[], logContent?: string): boolean {
  const injectionAPIs = ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread']
  
  if (logContent) {
    return injectionAPIs.some(api => logContent.includes(api))
  }
  
  return false
}

function hasSystemDiscovery(iocs: IOC[], logContent?: string): boolean {
  const discoveryCommands = ['systeminfo', 'whoami', 'net user', 'net group', 'wmic']
  
  if (logContent) {
    return discoveryCommands.some(cmd => logContent.toLowerCase().includes(cmd))
  }
  
  return false
}

function hasC2Communication(iocs: IOC[]): boolean {
  // Check for external IPs and suspicious domains
  const externalIPs = iocs.filter(ioc => 
    ioc.type === 'ipv4' && !isPrivateIP(ioc.value)
  )
  
  const suspiciousDomains = iocs.filter(ioc =>
    ioc.type === 'domain' && isSuspiciousDomain(ioc.value)
  )
  
  return externalIPs.length > 0 || suspiciousDomains.length > 0
}

function hasRansomwareIndicators(iocs: IOC[], logContent?: string): boolean {
  const ransomExtensions = ['.encrypted', '.locked', '.crypto', '.enc', '.cry']
  const ransomNotes = ['readme.txt', 'decrypt_instructions', 'how_to_decrypt']
  
  const hasRansomFiles = iocs.some(ioc =>
    ioc.type === 'filename' && (
      ransomExtensions.some(ext => ioc.value.endsWith(ext)) ||
      ransomNotes.some(note => ioc.value.toLowerCase().includes(note))
    )
  )
  
  if (logContent) {
    const encryptionPatterns = /(?:encrypt|cipher|ransom|bitcoin|decrypt)/gi
    return encryptionPatterns.test(logContent) || hasRansomFiles
  }
  
  return hasRansomFiles
}

// Helper utilities
function isPrivateIP(ip: string): boolean {
  const parts = ip.split('.').map(Number)
  return (
    parts[0] === 10 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168)
  )
}

function isSuspiciousDomain(domain: string): boolean {
  const suspiciousPatterns = [
    /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/, // IP as domain
    /[0-9]{5,}/, // Many numbers
    /^[a-z]{20,}\./, // Very long random subdomain
    /\.(tk|ml|ga|cf)$/, // Suspicious TLDs
  ]
  
  return suspiciousPatterns.some(pattern => pattern.test(domain))
}

// Get MITRE matrix view
export function getMITREMatrix(techniques: MITRETechnique[]): Record<string, MITRETechnique[]> {
  const matrix: Record<string, MITRETechnique[]> = {}
  
  MITRE_CONFIG.TACTICS.forEach(tactic => {
    matrix[tactic] = techniques.filter(t => t.tactic === tactic)
  })
  
  return matrix
}

// Calculate threat score based on techniques
export function calculateThreatScore(techniques: MITRETechnique[]): number {
  if (techniques.length === 0) return 0
  
  const weights = {
    'Initial Access': 0.8,
    'Execution': 0.9,
    'Persistence': 0.85,
    'Privilege Escalation': 0.9,
    'Defense Evasion': 0.85,
    'Credential Access': 0.95,
    'Discovery': 0.6,
    'Lateral Movement': 0.9,
    'Collection': 0.7,
    'Command and Control': 0.85,
    'Exfiltration': 0.95,
    'Impact': 1.0
  }
  
  let totalScore = 0
  let totalWeight = 0
  
  techniques.forEach(technique => {
    const weight = weights[technique.tactic as keyof typeof weights] || 0.5
    totalScore += (technique.confidence / 100) * weight
    totalWeight += weight
  })
  
  return Math.round((totalScore / totalWeight) * 100)
}

// Export techniques to ATT&CK Navigator format
export function exportToNavigator(techniques: MITRETechnique[]): string {
  const layer = {
    name: 'SecuNik LogX Analysis',
    versions: {
      attack: '14',
      navigator: '4.9.1',
      layer: '4.5'
    },
    domain: 'enterprise-attack',
    description: 'Techniques detected during forensic analysis',
    techniques: techniques.map(t => ({
      techniqueID: t.techniqueId,
      score: t.confidence,
      color: getColorForConfidence(t.confidence),
      comment: t.evidence.join('; ')
    }))
  }
  
  return JSON.stringify(layer, null, 2)
}

function getColorForConfidence(confidence: number): string {
  if (confidence >= 90) return '#ff0000' // Red
  if (confidence >= 70) return '#ff9900' // Orange
  if (confidence >= 50) return '#ffff00' // Yellow
  return '#00ff00' // Green
}