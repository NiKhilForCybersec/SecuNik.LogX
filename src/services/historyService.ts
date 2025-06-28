import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

export interface HistoryParams {
  limit?: number;
  offset?: number;
  start_date?: string;
  end_date?: string;
  min_threat_score?: number;
  severity?: string;
  status?: string;
  file_type?: string;
  has_iocs?: boolean;
  search?: string;
}

export const historyService = {
  // Get analysis history
  async getHistory(params: HistoryParams = {}): Promise<any> {
    try {
      const queryParams = new URLSearchParams();
      
      if (params.limit) queryParams.append('limit', params.limit.toString());
      if (params.offset) queryParams.append('offset', params.offset.toString());
      if (params.start_date) queryParams.append('start_date', params.start_date);
      if (params.end_date) queryParams.append('end_date', params.end_date);
      if (params.min_threat_score) queryParams.append('min_threat_score', params.min_threat_score.toString());
      if (params.severity) queryParams.append('severity', params.severity);
      if (params.status) queryParams.append('status', params.status);
      if (params.file_type) queryParams.append('file_type', params.file_type);
      if (params.has_iocs !== undefined) queryParams.append('has_iocs', params.has_iocs.toString());
      if (params.search) queryParams.append('search', params.search);

      const response = await axios.get(`${API_URL}/analysis/history?${queryParams.toString()}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Get analysis details
  async getAnalysisDetails(analysisId: string): Promise<any> {
    try {
      const response = await axios.get(`${API_URL}/analysis/result/${analysisId}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Delete analysis
  async deleteAnalysis(analysisId: string): Promise<any> {
    try {
      const response = await axios.delete(`${API_URL}/analysis/${analysisId}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Add tags to analysis
  async addTags(analysisId: string, tags: string[]): Promise<any> {
    try {
      const response = await axios.post(`${API_URL}/analysis/${analysisId}/tags`, { tags });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Update notes
  async updateNotes(analysisId: string, notes: string): Promise<any> {
    try {
      const response = await axios.put(`${API_URL}/analysis/${analysisId}/notes`, { notes });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Get history statistics
  async getHistoryStats(days = 30): Promise<any> {
    try {
      const response = await axios.get(`${API_URL}/analysis/stats?days=${days}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Export history
  async exportHistory(format = 'json'): Promise<any> {
    try {
      const response = await axios.get(`${API_URL}/analysis/export?format=${format}`, {
        responseType: format === 'pdf' ? 'blob' : 'json'
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Compare analyses
  async compareAnalyses(analysisIds: string[]): Promise<any> {
    try {
      const response = await axios.post(`${API_URL}/analysis/compare`, { analysis_ids: analysisIds });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  handleError(error: any): any {
    if (error.response?.data) {
      return {
        error: error.response.data.detail?.message || 'History operation failed',
        message: error.response.data.detail?.message || 'An error occurred',
        error_code: error.response.data.detail?.error_code,
        status_code: error.response.status,
        details: error.response.data.detail?.details || {}
      };
    }
    return {
      error: 'NetworkError',
      message: 'Failed to connect to server',
      status_code: 0,
      type: 'network_error'
    };
  }
};