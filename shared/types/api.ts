// Base types
export interface ApiResponse<T = any> {
  data: T
  success: boolean
  message?: string
  errors?: string[]
}

export interface PaginatedResponse<T> {
  items: T[]
  totalCount: number
  pageNumber: number
  pageSize: number
  totalPages: number
}

// Analysis types
export interface Analysis {
  id: string
  fileName: string
  fileHash: string
  fileSize: number
  status: AnalysisStatus
  progress: number
  threatLevel: ThreatLevel
  analysisType: AnalysisType
  createdAt: string
  updatedAt: string
  completedAt?: string
  createdBy?: string
  iocCount: number
  mitreCount: number
  results?: AnalysisResults
}

export interface AnalysisResults {
  summary: string
  iocs: IOC[]
  mitreTechniques: MITRETechnique[]
  threatTimeline: ThreatTimelinePoint[]
  recommendations: string[]
  rawLogs?: string
  metadata: Record<string, any>
}

export interface CreateAnalysisRequest {
  fileName: string
  fileHash: string
  fileSize: number
  analysisType: AnalysisType
}

export interface UpdateAnalysisRequest {
  status?: AnalysisStatus
  progress?: number
  threatLevel?: ThreatLevel
  results?: Partial<AnalysisResults>
}

// IOC types
export interface IOC {
  id: string
  type: IOCType
  value: string
  confidence: number
  context: string
  firstSeen: string
  lastSeen: string
  count: number
  enrichment?: IOCEnrichment
}

export interface IOCEnrichment {
  reputation?: string
  geoLocation?: string
  asnInfo?: string
  threatIntel?: string[]
  relatedIOCs?: string[]
}

export interface ExtractedIOC {
  type: IOCType
  value: string
  confidence: number
  context: string
}

// MITRE types
export interface MITRETechnique {
  techniqueId: string
  name: string
  description: string
  tactic: string
  confidence: number
  evidence: string[]
  mitigations?: string[]
}

// File types
export interface FileUploadResponse {
  fileId: string
  fileName: string
  fileSize: number
  hash: string
  uploadedAt: string
}

export interface FileValidationResult {
  valid: boolean
  error?: string
  warnings?: string[]
}

// Parser types
export interface Parser {
  id: string
  name: string
  description: string
  language: string
  code: string
  version: string
  isEnabled: boolean
  lastModified: string
  performance?: ParserPerformance
}

export interface ParserPerformance {
  averageExecutionTime: number
  successRate: number
  lastExecuted?: string
  totalExecutions: number
}

// Rule types
export interface Rule {
  id: string
  name: string
  type: 'yara' | 'sigma'
  content: string
  severity: ThreatLevel
  tags: string[]
  isEnabled: boolean
  hitCount: number
  lastHit?: string
  createdAt: string
  updatedAt: string
}

// SignalR types
export interface AnalysisProgressUpdate {
  analysisId: string
  progress: number
  status: AnalysisStatus
  message?: string
}

export interface IOCNotification {
  analysisId: string
  ioc: ExtractedIOC
  timestamp: string
}

export interface MITRENotification {
  analysisId: string
  technique: MITRETechnique
  timestamp: string
}

export interface AnalysisCompleteNotification {
  analysisId: string
  threatLevel: ThreatLevel
  summary: string
  duration: number
}

// Chart types
export interface ThreatTimelinePoint {
  timestamp: string
  threatLevel: number
  iocCount: number
  confidence: number
  events: string[]
}

export interface DashboardStats {
  totalAnalyses: number
  activeAnalyses: number
  completedAnalyses: number
  failedAnalyses: number
  threatBreakdown: Record<ThreatLevel, number>
  totalIOCs: number
  totalMITRETechniques: number
  recentActivity: Analysis[]
}

// Error types
export interface ApiError {
  statusCode: number
  errorCode: string
  message: string
  details?: Record<string, any>
  correlationId?: string
  timestamp: string
}

// Import types from constants
import type { AnalysisType, AnalysisStatus, ThreatLevel, IOCType } from '../config/constants'