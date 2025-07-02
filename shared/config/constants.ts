// API Configuration
export const API_CONFIG = {
  BASE_URL: process.env.VITE_API_URL || 'http://localhost:5000/api',
  SIGNALR_URL: process.env.VITE_SIGNALR_URL || 'http://localhost:5000/analysishub',
  TIMEOUT: 30000,
  RETRY_COUNT: 3,
  RETRY_DELAY: 1000
} as const

// File Upload Configuration
export const FILE_CONFIG = {
  MAX_SIZE: 100 * 1024 * 1024, // 100MB
  ALLOWED_EXTENSIONS: ['.log', '.txt', '.json', '.xml', '.csv', '.evtx', '.pcap', '.dmp'],
  CHUNK_SIZE: 1024 * 1024, // 1MB chunks
  MIME_TYPES: {
    '.log': 'text/plain',
    '.txt': 'text/plain',
    '.json': 'application/json',
    '.xml': 'application/xml',
    '.csv': 'text/csv',
    '.evtx': 'application/octet-stream',
    '.pcap': 'application/vnd.tcpdump.pcap',
    '.dmp': 'application/octet-stream'
  }
} as const

// Analysis Configuration
export const ANALYSIS_CONFIG = {
  TYPES: ['standard', 'deep', 'quick', 'custom'] as const,
  STATUSES: ['pending', 'processing', 'completed', 'failed'] as const,
  THREAT_LEVELS: ['low', 'medium', 'high', 'critical'] as const,
  REFRESH_INTERVAL: 5000, // 5 seconds
  MAX_RETRIES: 3
} as const

// IOC Types
export const IOC_TYPES = {
  IPV4: 'ipv4',
  IPV6: 'ipv6',
  DOMAIN: 'domain',
  URL: 'url',
  EMAIL: 'email',
  MD5: 'md5',
  SHA1: 'sha1',
  SHA256: 'sha256',
  FILENAME: 'filename',
  REGISTRY: 'registry',
  MUTEX: 'mutex',
  PROCESS: 'process'
} as const

// MITRE ATT&CK Configuration
export const MITRE_CONFIG = {
  TACTICS: [
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Command and Control',
    'Exfiltration',
    'Impact'
  ],
  CONFIDENCE_THRESHOLD: 70,
  MAX_TECHNIQUES_DISPLAY: 50
} as const

// UI Configuration
export const UI_CONFIG = {
  THEME: 'dark' as const,
  ANIMATIONS: {
    DURATION: 300,
    EASING: 'ease-in-out'
  },
  PAGINATION: {
    DEFAULT_PAGE_SIZE: 10,
    PAGE_SIZE_OPTIONS: [10, 25, 50, 100]
  },
  DEBOUNCE_DELAY: 300,
  TOAST_DURATION: 4000,
  SKELETON_DELAY: 200
} as const

// Chart Configuration
export const CHART_CONFIG = {
  COLORS: {
    primary: '#3b82f6',
    secondary: '#8b5cf6',
    success: '#10b981',
    warning: '#f59e0b',
    danger: '#ef4444',
    info: '#06b6d4'
  },
  DEFAULT_HEIGHT: 300,
  ANIMATION_DURATION: 1000
} as const

// Error Messages
export const ERROR_MESSAGES = {
  GENERIC: 'An unexpected error occurred. Please try again.',
  NETWORK: 'Network error. Please check your connection.',
  FILE_TOO_LARGE: 'File size exceeds the maximum limit.',
  INVALID_FILE_TYPE: 'Invalid file type. Please upload a supported format.',
  ANALYSIS_FAILED: 'Analysis failed. Please try again or contact support.',
  NOT_FOUND: 'The requested resource was not found.',
  UNAUTHORIZED: 'You are not authorized to perform this action.',
  SERVER_ERROR: 'Server error. Please try again later.'
} as const

// Success Messages
export const SUCCESS_MESSAGES = {
  FILE_UPLOADED: 'File uploaded successfully',
  ANALYSIS_STARTED: 'Analysis started successfully',
  ANALYSIS_COMPLETED: 'Analysis completed successfully',
  DELETED: 'Successfully deleted',
  EXPORTED: 'Successfully exported',
  COPIED: 'Copied to clipboard'
} as const

// Regular Expressions
export const REGEX_PATTERNS = {
  IPV4: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
  IPV6: /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/,
  DOMAIN: /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/,
  EMAIL: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
  MD5: /^[a-fA-F0-9]{32}$/,
  SHA1: /^[a-fA-F0-9]{40}$/,
  SHA256: /^[a-fA-F0-9]{64}$/,
  URL: /^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$/
} as const

// Type exports
export type AnalysisType = typeof ANALYSIS_CONFIG.TYPES[number]
export type AnalysisStatus = typeof ANALYSIS_CONFIG.STATUSES[number]
export type ThreatLevel = typeof ANALYSIS_CONFIG.THREAT_LEVELS[number]
export type IOCType = typeof IOC_TYPES[keyof typeof IOC_TYPES]