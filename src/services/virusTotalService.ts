import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

export interface ScanOptions {
  forceRescan?: boolean;
}

export interface BulkScanOptions {
  forceRescan?: boolean;
}

export const virusTotalService = {
  // Scan resource
  async scan(resourceType: string, resourceValue: string, options: ScanOptions = {}): Promise<any> {
    try {
      const response = await axios.post(`${API_URL}/virustotal/scan`, {
        resource_type: resourceType, // 'file', 'ip', 'domain', 'url'
        resource_value: resourceValue,
        force_rescan: options.forceRescan || false
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Bulk scan
  async bulkScan(resources: Array<{type: string, value: string}>, options: BulkScanOptions = {}): Promise<any> {
    try {
      const response = await axios.post(`${API_URL}/virustotal/scan/bulk`, {
        resources,
        force_rescan: options.forceRescan || false
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Get cached report
  async getCachedReport(resourceType: string, resourceValue: string): Promise<any> {
    try {
      const response = await axios.get(`${API_URL}/virustotal/report/${resourceType}/${encodeURIComponent(resourceValue)}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Check quota
  async getQuota(): Promise<any> {
    try {
      const response = await axios.get(`${API_URL}/virustotal/quota`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Clear cache
  async clearCache(olderThanDays = 7): Promise<any> {
    try {
      const response = await axios.post(`${API_URL}/virustotal/cache/clear?older_than_days=${olderThanDays}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Get statistics
  async getStats(days = 7): Promise<any> {
    try {
      const response = await axios.get(`${API_URL}/virustotal/stats?days=${days}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Extract IOCs
  async extractIOCs(fileHash: string): Promise<any> {
    try {
      const response = await axios.post(`${API_URL}/virustotal/iocs/extract`, {
        file_hash: fileHash
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  },

  // Convenience methods for specific resource types
  async scanFile(hash: string, forceRescan = false): Promise<any> {
    return this.scan('file', hash, { forceRescan });
  },

  async scanIP(ip: string): Promise<any> {
    return this.scan('ip', ip);
  },

  async scanDomain(domain: string): Promise<any> {
    return this.scan('domain', domain);
  },

  async scanUrl(url: string): Promise<any> {
    return this.scan('url', url);
  },

  handleError(error: any): any {
    if (error.response?.data) {
      return {
        error: error.response.data.detail?.message || 'VirusTotal operation failed',
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