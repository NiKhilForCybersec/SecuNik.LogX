import { format, formatDistanceToNow, parseISO } from 'date-fns'

// File size formatting
export const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return '0 Bytes'
  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

// Date formatting
export const formatDate = (date: string | Date): string => {
  const d = typeof date === 'string' ? parseISO(date) : date
  return format(d, 'PPpp')
}

export const formatRelativeTime = (date: string | Date): string => {
  const d = typeof date === 'string' ? parseISO(date) : date
  return formatDistanceToNow(d, { addSuffix: true })
}

// Threat level formatting
export const formatThreatLevel = (level: string): {
  label: string
  color: string
  bgColor: string
  icon: string
} => {
  const levels = {
    critical: {
      label: 'Critical',
      color: 'text-red-400',
      bgColor: 'bg-red-500/20',
      icon: '🔴'
    },
    high: {
      label: 'High',
      color: 'text-orange-400',
      bgColor: 'bg-orange-500/20',
      icon: '🟠'
    },
    medium: {
      label: 'Medium',
      color: 'text-yellow-400',
      bgColor: 'bg-yellow-500/20',
      icon: '🟡'
    },
    low: {
      label: 'Low',
      color: 'text-green-400',
      bgColor: 'bg-green-500/20',
      icon: '🟢'
    }
  }
  return levels[level as keyof typeof levels] || levels.low
}

// Percentage formatting
export const formatPercentage = (value: number, decimals: number = 0): string => {
  return `${value.toFixed(decimals)}%`
}

// IOC type formatting
export const formatIOCType = (type: string): string => {
  const types: Record<string, string> = {
    ipv4: 'IPv4 Address',
    ipv6: 'IPv6 Address',
    domain: 'Domain',
    url: 'URL',
    email: 'Email',
    md5: 'MD5 Hash',
    sha1: 'SHA1 Hash',
    sha256: 'SHA256 Hash',
    filename: 'Filename',
    registry: 'Registry Key'
  }
  return types[type] || type
}

// Truncate with ellipsis
export const truncate = (str: string, length: number = 50): string => {
  if (str.length <= length) return str
  return str.substring(0, length - 3) + '...'
}

// Hash formatting (shorten for display)
export const formatHash = (hash: string): string => {
  if (hash.length <= 16) return hash
  return `${hash.substring(0, 8)}...${hash.substring(hash.length - 8)}`
}

// Status formatting
export const formatStatus = (status: string): {
  label: string
  color: string
  pulse: boolean
} => {
  const statuses = {
    pending: { label: 'Pending', color: 'text-slate-400', pulse: false },
    processing: { label: 'Processing', color: 'text-blue-400', pulse: true },
    completed: { label: 'Completed', color: 'text-green-400', pulse: false },
    failed: { label: 'Failed', color: 'text-red-400', pulse: false }
  }
  return statuses[status as keyof typeof statuses] || statuses.pending
}