import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

export interface ParserCreateDto {
  name: string;
  description: string;
  version: string;
  author: string;
  supportedExtensions: string[];
  codeContent?: string;
  configuration?: Record<string, any>;
}

export interface ParserUpdateDto {
  description?: string;
  version?: string;
  isEnabled?: boolean;
  supportedExtensions?: string[];
  configuration?: Record<string, any>;
  codeContent?: string;
  priority?: number;
}

export const parserService = {
  // Get all parsers
  async getParsers(params: { type?: string; enabled?: boolean; extension?: string } = {}): Promise<any> {
    try {
      const queryParams = new URLSearchParams();
      
      if (params.type) queryParams.append('type', params.type);
      if (params.enabled !== undefined) queryParams.append('enabled', params.enabled.toString());
      if (params.extension) queryParams.append('extension', params.extension);

      const response = await axios.get(`${API_URL}/parser?${queryParams.toString()}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Get parser by ID
  async getParser(id: string): Promise<any> {
    try {
      const response = await axios.get(`${API_URL}/parser/${id}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Create a new parser
  async createParser(parserData: ParserCreateDto): Promise<any> {
    try {
      const response = await axios.post(`${API_URL}/parser`, parserData);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Update an existing parser
  async updateParser(id: string, parserData: ParserUpdateDto): Promise<any> {
    try {
      const response = await axios.put(`${API_URL}/parser/${id}`, parserData);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Delete a parser
  async deleteParser(id: string): Promise<any> {
    try {
      const response = await axios.delete(`${API_URL}/parser/${id}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Validate parser code
  async validateParser(code: string): Promise<any> {
    try {
      const response = await axios.post(`${API_URL}/parser/validate`, code);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Test a parser with sample content
  async testParser(id: string, testContent: string): Promise<any> {
    try {
      const response = await axios.post(`${API_URL}/parser/${id}/test`, testContent);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Get parser statistics
  async getParserStatistics(): Promise<any> {
    try {
      const response = await axios.get(`${API_URL}/parser/statistics`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Suggest parser for a file
  async suggestParser(filePath: string, content: string): Promise<any> {
    try {
      const response = await axios.post(`${API_URL}/parser/suggest`, {
        filePath,
        content
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  handleError(error: any): any {
    if (error.response?.data) {
      return {
        error: error.response.data.detail?.message || 'Parser operation failed',
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