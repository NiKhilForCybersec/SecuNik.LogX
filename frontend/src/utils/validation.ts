// File validation
export const validateFile = (file: File): { valid: boolean; error?: string } => {
  const MAX_SIZE = 100 * 1024 * 1024 // 100MB
  const ALLOWED_EXTENSIONS = ['.log', '.txt', '.json', '.xml', '.csv', '.evtx', '.pcap', '.dmp']
  
  if (file.size > MAX_SIZE) {
    return { valid: false, error: `File size exceeds ${MAX_SIZE / 1024 / 1024}MB limit` }
  }
  
  const extension = file.name.substring(file.name.lastIndexOf('.')).toLowerCase()
  if (!ALLOWED_EXTENSIONS.includes(extension)) {
    return { valid: false, error: `File type ${extension} not supported` }
  }
  
  return { valid: true }
}

// Search validation
export const validateSearchQuery = (query: string): boolean => {
  return query.length >= 2 && query.length <= 100
}

// Date range validation
export const validateDateRange = (start: Date | null, end: Date | null): boolean => {
  if (!start || !end) return true
  return start <= end && end <= new Date()
}

// IOC validation patterns
export const IOC_PATTERNS = {
  ipv4: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
  ipv6: /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/,
  domain: /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/,
  email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
  md5: /^[a-fA-F0-9]{32}$/,
  sha1: /^[a-fA-F0-9]{40}$/,
  sha256: /^[a-fA-F0-9]{64}$/,
  url: /^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$/
}

export const validateIOC = (value: string, type: string): boolean => {
  const pattern = IOC_PATTERNS[type as keyof typeof IOC_PATTERNS]
  return pattern ? pattern.test(value) : false
}

// Sanitization
export const sanitizeInput = (input: string): string => {
  return input.trim().replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
}