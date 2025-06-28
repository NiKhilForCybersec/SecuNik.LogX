// File validation helpers
export const validateFile = (file: File, maxSize: number, allowedExtensions?: string[]): { isValid: boolean; errors: string[] } => {
  const errors: string[] = [];
  
  // Check file size
  if (file.size > maxSize) {
    errors.push(`File size exceeds maximum limit of ${formatFileSize(maxSize)}`);
  }
  
  // Check file type if allowedExtensions is provided
  if (allowedExtensions && allowedExtensions.length > 0) {
    const extension = getFileExtension(file.name);
    if (!allowedExtensions.includes(extension)) {
      errors.push(`File type ${extension} is not supported`);
    }
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

export const getFileExtension = (filename: string): string => {
  if (!filename) return '';
  const lastDot = filename.lastIndexOf('.');
  return lastDot !== -1 ? filename.substring(lastDot).toLowerCase() : '';
};

export const getFileType = (filename: string): string => {
  const extension = getFileExtension(filename);
  
  const typeMap: Record<string, string> = {
    // Log files
    '.log': 'System Log',
    '.txt': 'Text File',
    '.syslog': 'Syslog',
    
    // Windows Event Logs
    '.evtx': 'Windows Event Log',
    '.evt': 'Windows Event Log',
    
    // Network captures
    '.pcap': 'Network Capture',
    '.pcapng': 'Network Capture',
    '.cap': 'Network Capture',
    
    // Archives
    '.zip': 'ZIP Archive',
    '.rar': 'RAR Archive',
    '.7z': '7-Zip Archive',
    '.tar': 'TAR Archive',
    '.gz': 'Gzip Archive',
    
    // Email files
    '.eml': 'Email Message',
    '.msg': 'Outlook Message',
    '.mbox': 'Mailbox Archive',
    
    // Structured data
    '.json': 'JSON Data',
    '.xml': 'XML Data',
    '.csv': 'CSV Data',
    '.yaml': 'YAML Data',
    '.yml': 'YAML Data',
  };
  
  return typeMap[extension] || 'Unknown';
};

// File size formatting
export const formatFileSize = (bytes: number): string => {
  if (!bytes || bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

// Threat level helpers
export const getThreatLevelColor = (level?: string): string => {
  const colors: Record<string, string> = {
    'critical': 'text-red-400 bg-red-900/30',
    'high': 'text-orange-400 bg-orange-900/30',
    'medium': 'text-yellow-400 bg-yellow-900/30',
    'low': 'text-green-400 bg-green-900/30'
  };
  
  return colors[level?.toLowerCase() || ''] || colors.low;
};

export const getThreatLevelFromScore = (score: number): string => {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
};

// Status helpers
export const getStatusColor = (status?: string): string => {
  const colors: Record<string, string> = {
    'queued': 'text-blue-400 bg-blue-900/30',
    'processing': 'text-yellow-400 bg-yellow-900/30',
    'analyzing': 'text-yellow-400 bg-yellow-900/30',
    'completed': 'text-green-400 bg-green-900/30',
    'failed': 'text-red-400 bg-red-900/30',
    'cancelled': 'text-slate-400 bg-slate-900/30'
  };
  
  return colors[status?.toLowerCase() || ''] || colors.queued;
};

export const getSeverityColor = (severity?: string): string => {
  const colors: Record<string, string> = {
    'critical': 'text-red-400 bg-red-900/30',
    'high': 'text-orange-400 bg-orange-900/30',
    'medium': 'text-yellow-400 bg-yellow-900/30',
    'low': 'text-green-400 bg-green-900/30',
    'info': 'text-blue-400 bg-blue-900/30'
  };
  
  return colors[severity?.toLowerCase() || ''] || colors.info;
};

// URL helpers
export const isValidURL = (string: string): boolean => {
  try {
    new URL(string);
    return true;
  } catch (_) {
    return false;
  }
};

export const extractDomain = (url: string): string => {
  try {
    return new URL(url).hostname;
  } catch (_) {
    return url;
  }
};

// IP address helpers
export const isValidIPv4 = (ip: string): boolean => {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4Regex.test(ip)) return false;
  
  const parts = ip.split('.');
  return parts.every(part => {
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255;
  });
};

export const isValidIPv6 = (ip: string): boolean => {
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  return ipv6Regex.test(ip);
};

export const isValidIP = (ip: string): boolean => {
  return isValidIPv4(ip) || isValidIPv6(ip);
};

// Hash helpers
export const isValidHash = (hash: string): boolean => {
  const hashRegexes: Record<string, RegExp> = {
    md5: /^[a-fA-F0-9]{32}$/,
    sha1: /^[a-fA-F0-9]{40}$/,
    sha256: /^[a-fA-F0-9]{64}$/,
    sha512: /^[a-fA-F0-9]{128}$/
  };
  
  return Object.values(hashRegexes).some(regex => regex.test(hash));
};

export const getHashType = (hash: string): string => {
  const hashTypes: Record<number, string> = {
    32: 'MD5',
    40: 'SHA1',
    64: 'SHA256',
    128: 'SHA512'
  };
  
  return hashTypes[hash.length] || 'Unknown';
};

// Array helpers
export const chunk = <T>(array: T[], size: number): T[][] => {
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
};

export const unique = <T>(array: T[], key?: keyof T): T[] => {
  if (key) {
    const seen = new Set();
    return array.filter(item => {
      const value = item[key];
      if (seen.has(value)) {
        return false;
      }
      seen.add(value);
      return true;
    });
  }
  return [...new Set(array)];
};

// Debounce helper
export const debounce = <F extends (...args: any[]) => any>(func: F, wait: number) => {
  let timeout: number | null = null;
  
  return function(this: any, ...args: Parameters<F>) {
    const context = this;
    
    if (timeout !== null) {
      window.clearTimeout(timeout);
    }
    
    timeout = window.setTimeout(() => {
      func.apply(context, args);
    }, wait);
  };
};

// Throttle helper
export const throttle = <F extends (...args: any[]) => any>(func: F, limit: number) => {
  let inThrottle = false;
  
  return function(this: any, ...args: Parameters<F>) {
    const context = this;
    
    if (!inThrottle) {
      func.apply(context, args);
      inThrottle = true;
      setTimeout(() => {
        inThrottle = false;
      }, limit);
    }
  };
};

// Local storage helpers
export const setLocalStorage = <T>(key: string, value: T): boolean => {
  try {
    localStorage.setItem(key, JSON.stringify(value));
    return true;
  } catch (error) {
    console.error('Error setting localStorage:', error);
    return false;
  }
};

export const getLocalStorage = <T>(key: string, defaultValue: T | null = null): T | null => {
  try {
    const item = localStorage.getItem(key);
    return item ? JSON.parse(item) : defaultValue;
  } catch (error) {
    console.error('Error getting localStorage:', error);
    return defaultValue;
  }
};

export const removeLocalStorage = (key: string): boolean => {
  try {
    localStorage.removeItem(key);
    return true;
  } catch (error) {
    console.error('Error removing localStorage:', error);
    return false;
  }
};

// Download helpers
export const downloadFile = (data: BlobPart, filename: string, type = 'application/json'): void => {
  const blob = new Blob([data], { type });
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
};

export const downloadJSON = <T>(data: T, filename: string): void => {
  const jsonString = JSON.stringify(data, null, 2);
  downloadFile(jsonString, filename, 'application/json');
};

export const downloadCSV = <T extends Record<string, any>>(data: T[], filename: string): void => {
  if (!Array.isArray(data) || data.length === 0) return;
  
  const headers = Object.keys(data[0]);
  const csvContent = [
    headers.join(','),
    ...data.map(row => headers.map(header => `"${row[header] || ''}"`).join(','))
  ].join('\n');
  
  downloadFile(csvContent, filename, 'text/csv');
};

// Copy to clipboard
export const copyToClipboard = async (text: string): Promise<boolean> => {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (error) {
    console.error('Failed to copy to clipboard:', error);
    return false;
  }
};

// Generate unique ID
export const generateId = (): string => {
  return Date.now().toString(36) + Math.random().toString(36).substr(2);
};

// Sleep helper
export const sleep = (ms: number): Promise<void> => {
  return new Promise(resolve => setTimeout(resolve, ms));
};