import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

export interface RuleCreateDto {
  name: string;
  description: string;
  type: string;
  category: string;
  severity: string;
  content: string;
  author: string;
  tags?: string[];
  references?: string[];
  ruleId?: string;
  priority?: number;
}

export interface RuleUpdateDto {
  description?: string;
  category?: string;
  severity?: string;
  content?: string;
  isEnabled?: boolean;
  tags?: string[];
  references?: string[];
  priority?: number;
}

export interface RuleTestDto {
  testContent: string;
  testOptions?: Record<string, any>;
}

export const rulesService = {
  // Get rules with optional filtering
  async getRules(params: {
    type?: string;
    category?: string;
    enabledOnly?: boolean;
    tags?: string;
    severity?: string;
    search?: string;
    limit?: number;
    offset?: number;
  } = {}): Promise<any> {
    try {
      const queryParams = new URLSearchParams();
      
      if (params.type) queryParams.append('type', params.type);
      if (params.category) queryParams.append('category', params.category);
      if (params.enabledOnly !== undefined) queryParams.append('enabledOnly', params.enabledOnly.toString());
      if (params.tags) queryParams.append('tags', params.tags);
      if (params.severity) queryParams.append('severity', params.severity);
      if (params.search) queryParams.append('search', params.search);
      if (params.limit) queryParams.append('limit', params.limit.toString());
      if (params.offset) queryParams.append('offset', params.offset.toString());

      const response = await axios.get(`${API_URL}/rule?${queryParams.toString()}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Get rule by ID
  async getRule(id: string): Promise<any> {
    try {
      const response = await axios.get(`${API_URL}/rule/${id}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Create a new rule
  async createRule(ruleData: RuleCreateDto): Promise<any> {
    try {
      const response = await axios.post(`${API_URL}/rule`, ruleData);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Update an existing rule
  async updateRule(id: string, ruleData: RuleUpdateDto): Promise<any> {
    try {
      const response = await axios.put(`${API_URL}/rule/${id}`, ruleData);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Delete a rule
  async deleteRule(id: string): Promise<any> {
    try {
      const response = await axios.delete(`${API_URL}/rule/${id}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Test a rule against sample content
  async testRule(id: string, testData: RuleTestDto): Promise<any> {
    try {
      const response = await axios.post(`${API_URL}/rule/${id}/test`, testData);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Validate rule content
  async validateRule(ruleData: Partial<RuleCreateDto>): Promise<any> {
    try {
      const response = await axios.post(`${API_URL}/rule/validate`, ruleData);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Import rules from file
  async importRules(file: File): Promise<any> {
    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await axios.post(`${API_URL}/rule/import`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Export rules
  async exportRules(format = 'json', type?: string): Promise<any> {
    try {
      let url = `${API_URL}/rule/export?format=${format}`;
      if (type) {
        url += `&type=${type}`;
      }
      
      const response = await axios.get(url);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Get rule statistics
  async getRuleStats(): Promise<any> {
    try {
      const response = await axios.get(`${API_URL}/rule/stats`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Get rule categories
  async getCategories(): Promise<any> {
    try {
      const response = await axios.get(`${API_URL}/rule/categories`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Get rule tags
  async getTags(): Promise<any> {
    try {
      const response = await axios.get(`${API_URL}/rule/tags`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Reload all rules
  async reloadRules(): Promise<any> {
    try {
      const response = await axios.post(`${API_URL}/rule/reload`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  handleError(error: any): any {
    if (error.response?.data) {
      return {
        error: error.response.data.detail?.message || 'Rules operation failed',
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