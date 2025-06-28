import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

export interface UploadOptions {
  autoAnalyze?: boolean;
  tags?: string[];
  preferredParserId?: string;
  onProgress?: (progress: number) => void;
}

export interface UploadResult {
  id: string;
  filename: string;
  file_size: number;
  file_hash: string;
  content_type: string;
  file_path: string;
  status: string;
  parser_detected?: string;
  parser_id?: string;
  auto_analyze: boolean;
  tags: string[];
  uploaded_at: string;
}

export const uploadService = {
  // Upload single file
  async uploadFile(file: File, options: UploadOptions = {}): Promise<UploadResult> {
    const formData = new FormData();
    formData.append('file', file);
    
    // Add optional parameters
    if (options.autoAnalyze) {
      formData.append('autoAnalyze', 'true');
    }
    
    if (options.tags && Array.isArray(options.tags)) {
      formData.append('tags', JSON.stringify(options.tags));
    }

    if (options.preferredParserId) {
      formData.append('preferredParserId', options.preferredParserId);
    }

    try {
      const response = await axios.post(`${API_URL}/file/upload`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        },
        onUploadProgress: (progressEvent) => {
          if (options.onProgress && progressEvent.total) {
            const percentCompleted = Math.round(
              (progressEvent.loaded * 100) / progressEvent.total
            );
            options.onProgress(percentCompleted);
          }
        }
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Check upload status
  async getUploadStatus(uploadId: string): Promise<any> {
    try {
      const response = await axios.get(`${API_URL}/file/upload/${uploadId}/status`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Download a file
  async downloadFile(analysisId: string, filename: string): Promise<Blob> {
    try {
      const response = await axios.get(`${API_URL}/file/download/${analysisId}/${filename}`, {
        responseType: 'blob'
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // List uploads
  async listUploads(params: { limit?: number; offset?: number } = {}): Promise<any> {
    try {
      const queryParams = new URLSearchParams();
      
      if (params.limit) queryParams.append('limit', params.limit.toString());
      if (params.offset) queryParams.append('offset', params.offset.toString());

      const response = await axios.get(`${API_URL}/file/uploads?${queryParams.toString()}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Delete upload
  async deleteUpload(uploadId: string): Promise<any> {
    try {
      const response = await axios.delete(`${API_URL}/file/upload/${uploadId}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Validate file without uploading
  async validateFile(file: File): Promise<any> {
    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await axios.post(`${API_URL}/file/validate`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Get supported file types
  async getSupportedFileTypes(): Promise<any> {
    try {
      const response = await axios.get(`${API_URL}/file/supported-types`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  handleError(error: any): any {
    if (error.response?.data) {
      return {
        error: error.response.data.detail?.message || 'Upload failed',
        message: error.response.data.detail?.message || 'An error occurred during upload',
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