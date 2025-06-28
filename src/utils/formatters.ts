import { format, formatDistanceToNow, parseISO } from 'date-fns';

// Date formatting
export const formatDate = (date?: string | Date, formatString = 'PPpp') => {
  if (!date) return 'N/A';
  
  try {
    const dateObj = typeof date === 'string' ? parseISO(date) : date;
    return format(dateObj, formatString);
  } catch (error) {
    console.error('Date formatting error:', error);
    return 'Invalid Date';
  }
};

export const formatRelativeTime = (date?: string | Date) => {
  if (!date) return 'N/A';
  
  try {
    const dateObj = typeof date === 'string' ? parseISO(date) : date;
    return formatDistanceToNow(dateObj, { addSuffix: true });
  } catch (error) {
    console.error('Relative time formatting error:', error);
    return 'Invalid Date';
  }
};

// File size formatting
export const formatFileSize = (bytes?: number) => {
  if (!bytes || bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

// Number formatting
export const formatNumber = (num?: number) => {
  if (num === null || num === undefined) return '0';
  return num.toLocaleString();
};

export const formatPercentage = (value?: number, total?: number) => {
  if (!value || !total || total === 0) return '0%';
  return `${Math.round((value / total) * 100)}%`;
};

// Threat score formatting
export const formatThreatScore = (score?: number) => {
  if (score === null || score === undefined) return 'N/A';
  return `${Math.round(score)}/100`;
};

// Duration formatting
export const formatDuration = (seconds?: number) => {
  if (!seconds || seconds === 0) return '0s';
  
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  
  if (hours > 0) {
    return `${hours}h ${minutes}m ${secs}s`;
  } else if (minutes > 0) {
    return `${minutes}m ${secs}s`;
  } else {
    return `${secs}s`;
  }
};

// Hash formatting (truncate long hashes)
export const formatHash = (hash?: string, length = 16) => {
  if (!hash) return 'N/A';
  if (hash.length <= length) return hash;
  return `${hash.substring(0, length)}...`;
};

// IP address validation and formatting
export const formatIPAddress = (ip?: string) => {
  if (!ip) return 'N/A';
  
  // Basic IP validation
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  
  if (ipv4Regex.test(ip) || ipv6Regex.test(ip)) {
    return ip;
  }
  
  return ip; // Return as-is if not a standard IP format
};

// URL formatting (truncate long URLs)
export const formatURL = (url?: string, maxLength = 50) => {
  if (!url) return 'N/A';
  if (url.length <= maxLength) return url;
  return `${url.substring(0, maxLength)}...`;
};

// Severity level formatting
export const formatSeverity = (severity?: string) => {
  if (!severity) return 'Unknown';
  return severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();
};

// Analysis status formatting
export const formatAnalysisStatus = (status?: string) => {
  if (!status) return 'Unknown';
  
  const statusMap: Record<string, string> = {
    'queued': 'Queued',
    'processing': 'Processing',
    'completed': 'Completed',
    'failed': 'Failed',
    'cancelled': 'Cancelled',
    'analyzing': 'Analyzing',
    'started': 'Started'
  };
  
  return statusMap[status] || status;
};

// File type formatting
export const formatFileType = (type?: string, subtype?: string) => {
  if (!type) return 'Unknown';
  
  if (subtype) {
    return `${type.charAt(0).toUpperCase() + type.slice(1)} (${subtype})`;
  }
  
  return type.charAt(0).toUpperCase() + type.slice(1);
};

// IOC type formatting
export const formatIOCType = (type?: string) => {
  if (!type) return 'Unknown';
  
  const typeMap: Record<string, string> = {
    'ip_address': 'IP Address',
    'domain': 'Domain',
    'url': 'URL',
    'hash': 'File Hash',
    'email': 'Email',
    'file_path': 'File Path',
    'registry_key': 'Registry Key',
    'mutex': 'Mutex',
    'user_agent': 'User Agent'
  };
  
  return typeMap[type] || type.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase());
};

// MITRE technique formatting
export const formatMITRETechnique = (techniqueId?: string, techniqueName?: string) => {
  if (!techniqueId) return 'Unknown';
  
  if (techniqueName) {
    return `${techniqueId}: ${techniqueName}`;
  }
  
  return techniqueId;
};

// Confidence score formatting
export const formatConfidence = (confidence?: number) => {
  if (confidence === null || confidence === undefined) return 'N/A';
  
  if (confidence >= 0 && confidence <= 1) {
    return `${Math.round(confidence * 100)}%`;
  }
  
  return `${Math.round(confidence)}%`;
};

// Rule type formatting
export const formatRuleType = (type?: string) => {
  if (!type) return 'Unknown';
  
  const typeMap: Record<string, string> = {
    'yara': 'YARA',
    'sigma': 'Sigma',
    'custom': 'Custom'
  };
  
  return typeMap[type] || type.toUpperCase();
};

// Error message formatting
export const formatErrorMessage = (error: any): string => {
  if (!error) return 'Unknown error';
  
  if (typeof error === 'string') {
    return error;
  }
  
  if (error.message) {
    return error.message;
  }
  
  if (error.error && error.details) {
    return `${error.error}: ${error.details}`;
  }
  
  return 'An unexpected error occurred';
};

// Progress formatting
export const formatProgress = (current?: number, total?: number) => {
  if (!current || !total || total === 0) return '0%';
  const percentage = Math.round((current / total) * 100);
  return `${percentage}% (${current}/${total})`;
};

// Tag formatting
export const formatTags = (tags?: string[], maxTags = 3) => {
  if (!tags || !Array.isArray(tags)) return [];
  
  if (tags.length <= maxTags) {
    return tags;
  }
  
  return [
    ...tags.slice(0, maxTags),
    `+${tags.length - maxTags} more`
  ];
};