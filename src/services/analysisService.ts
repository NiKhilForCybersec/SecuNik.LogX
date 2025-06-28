import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

export interface AnalysisOptions {
  analyzers?: string[];
  deepScan?: boolean;
  extractIocs?: boolean;
  checkVirusTotal?: boolean;
  enableAI?: boolean;
  maxEvents?: number;
  timeoutMinutes?: number;
  parserID?: string;
  analysisOptions?: Record<string, any>;
}

export interface AnalysisResult {
  analysis_id: string;
  file_name: string;
  file_hash: string;
  status: string;
  progress: number;
  threat_score?: number;
  severity?: string;
  start_time?: string;
  completion_time?: string;
  error_message?: string;
}

export const analysisService = {
  // Start analysis
  async startAnalysis(uploadId: string, options: AnalysisOptions = {}): Promise<AnalysisResult> {
    try {
      const response = await axios.post(`${API_URL}/analysis/${uploadId}`, {
        analyzers: options.analyzers || ['yara', 'sigma', 'mitre', 'ai', 'patterns'],
        options: {
          deepScan: options.deepScan ?? true,
          extractIocs: options.extractIocs ?? true,
          checkVirusTotal: options.checkVirusTotal ?? false,
          enableAI: options.enableAI ?? false,
          maxEvents: options.maxEvents ?? 100000,
          timeoutMinutes: options.timeoutMinutes ?? 30,
          parserID: options.parserID,
          ...options.analysisOptions
        }
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Check analysis status
  async getAnalysisStatus(analysisId: string): Promise<AnalysisResult> {
    try {
      const response = await axios.get(`${API_URL}/analysis/status/${analysisId}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Get analysis results
  async getAnalysisResults(analysisId: string): Promise<any> {
    try {
      const response = await axios.get(`${API_URL}/analysis/result/${analysisId}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Cancel analysis
  async cancelAnalysis(analysisId: string): Promise<any> {
    try {
      const response = await axios.post(`${API_URL}/analysis/cancel/${analysisId}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Export analysis report
  async exportAnalysis(analysisId: string, format = 'json'): Promise<any> {
    try {
      const response = await axios.get(`${API_URL}/analysis/export/${analysisId}?format=${format}`, {
        responseType: format === 'pdf' ? 'blob' : 'json'
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Get timeline events
  async getTimelineEvents(analysisId: string, filters = {}): Promise<any> {
    try {
      const queryParams = new URLSearchParams();
      Object.entries(filters).forEach(([key, value]) => {
        queryParams.append(key, String(value));
      });
      
      const response = await axios.get(
        `${API_URL}/analysis/${analysisId}/timeline?${queryParams.toString()}`
      );
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Get IOCs
  async getIOCs(analysisId: string): Promise<any> {
    try {
      const response = await axios.get(`${API_URL}/analysis/${analysisId}/iocs`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Get rule matches
  async getRuleMatches(analysisId: string, ruleType?: string): Promise<any> {
    try {
      let url = `${API_URL}/analysis/${analysisId}/rule-matches`;
      if (ruleType) {
        url += `?type=${ruleType}`;
      }
      const response = await axios.get(url);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Get MITRE ATT&CK mapping
  async getMitreMapping(analysisId: string): Promise<any> {
    try {
      const response = await axios.get(`${API_URL}/analysis/${analysisId}/mitre`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Get AI insights
  async getAIInsights(analysisId: string): Promise<any> {
    try {
      const response = await axios.get(`${API_URL}/analysis/${analysisId}/ai-insights`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Add analysis notes
  async addNotes(analysisId: string, notes: string): Promise<any> {
    try {
      const response = await axios.post(`${API_URL}/analysis/${analysisId}/notes`, { notes });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Add analysis tags
  async addTags(analysisId: string, tags: string[]): Promise<any> {
    try {
      const response = await axios.post(`${API_URL}/analysis/${analysisId}/tags`, { tags });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Mark false positives
  async markFalsePositives(analysisId: string, matchIds: string[]): Promise<any> {
    try {
      const response = await axios.post(`${API_URL}/analysis/${analysisId}/false-positives`, { match_ids: matchIds });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  handleError(error: any): any {
    if (error.response?.data) {
      return {
        error: error.response.data.detail?.message || 'Analysis failed',
        message: error.response.data.detail?.message || 'An error occurred during analysis',
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