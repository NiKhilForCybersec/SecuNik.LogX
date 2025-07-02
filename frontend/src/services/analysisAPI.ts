import { apiClient } from './apiClient'

// Types matching backend DTOs from Batch 4
export interface CreateAnalysisRequest {
  fileName: string
  fileHash: string
  fileSize: number
  analysisType: string
}

export interface AnalysisResponse {
  id: string
  fileName: string
  fileHash: string
  fileSize: number
  status: string
  progress: number
  threatLevel: string
  createdAt: string
  updatedAt: string
  iocCount: number
  mitreCount: number
  results?: any
}

export interface FileUploadResponse {
  fileId: string
  fileName: string
  fileSize: number
  hash: string
}

// Analysis API endpoints
export const analysisAPI = {
  // Get all analyses
  getAnalyses: async (params?: {
    page?: number
    pageSize?: number
    status?: string
    threatLevel?: string
  }): Promise<{ items: AnalysisResponse[]; totalCount: number }> => {
    return apiClient.get('/analysis', params)
  },

  // Get single analysis
  getAnalysis: async (id: string): Promise<AnalysisResponse> => {
    return apiClient.get(`/analysis/${id}`)
  },

  // Create new analysis
  createAnalysis: async (data: CreateAnalysisRequest): Promise<AnalysisResponse> => {
    return apiClient.post('/analysis', data)
  },

  // Update analysis
  updateAnalysis: async (id: string, data: Partial<AnalysisResponse>): Promise<AnalysisResponse> => {
    return apiClient.put(`/analysis/${id}`, data)
  },

  // Delete analysis
  deleteAnalysis: async (id: string): Promise<void> => {
    return apiClient.delete(`/analysis/${id}`)
  },

  // Start analysis
  startAnalysis: async (id: string): Promise<void> => {
    return apiClient.post(`/analysis/${id}/start`)
  },

  // Stop analysis
  stopAnalysis: async (id: string): Promise<void> => {
    return apiClient.post(`/analysis/${id}/stop`)
  },

  // Upload file for analysis
  uploadFile: async (file: File, onProgress?: (progress: number) => void): Promise<FileUploadResponse> => {
    return apiClient.uploadFile('/file/upload', file, onProgress)
  },

  // Get analysis results
  getResults: async (id: string): Promise<any> => {
    return apiClient.get(`/analysis/${id}/results`)
  },

  // Export analysis
  exportAnalysis: async (id: string, format: 'json' | 'pdf' | 'csv'): Promise<Blob> => {
    const response = await fetch(`${import.meta.env.VITE_API_URL || 'http://localhost:5000/api'}/analysis/${id}/export?format=${format}`)
    if (!response.ok) throw new Error('Export failed')
    return response.blob()
  }
}