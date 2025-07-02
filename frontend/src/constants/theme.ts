// Theme configuration for SecuNik LogX forensics platform
export const theme = {
  // Color palette
  colors: {
    // Background colors
    background: {
      primary: '#020617',    // slate-950
      secondary: '#0f172a',  // slate-900
      tertiary: '#1e293b',   // slate-800
      hover: '#334155',      // slate-700
    },
    
    // Text colors
    text: {
      primary: '#f1f5f9',    // slate-100
      secondary: '#cbd5e1',  // slate-300
      muted: '#94a3b8',      // slate-400
      disabled: '#64748b',   // slate-500
    },
    
    // Border colors
    border: {
      default: '#334155',    // slate-700
      subtle: '#1e293b',     // slate-800
      strong: '#475569',     // slate-600
    },
    
    // Brand colors
    brand: {
      primary: '#3b82f6',    // blue-500
      secondary: '#8b5cf6',  // purple-500
      gradient: 'from-blue-500 to-purple-600',
    },
    
    // Status colors
    status: {
      success: '#10b981',    // green-500
      warning: '#f59e0b',    // amber-500
      error: '#ef4444',      // red-500
      info: '#06b6d4',       // cyan-500
    },
    
    // Threat level colors
    threat: {
      low: '#10b981',        // green-500
      medium: '#f59e0b',     // amber-500
      high: '#f97316',       // orange-500
      critical: '#ef4444',   // red-500
    },
  },
  
  // Typography
  typography: {
    fontFamily: {
      sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      mono: ['JetBrains Mono', 'Consolas', 'Monaco', 'monospace'],
    },
    fontSize: {
      xs: '0.75rem',
      sm: '0.875rem',
      base: '1rem',
      lg: '1.125rem',
      xl: '1.25rem',
      '2xl': '1.5rem',
      '3xl': '1.875rem',
      '4xl': '2.25rem',
    },
    fontWeight: {
      normal: '400',
      medium: '500',
      semibold: '600',
      bold: '700',
    },
  },
  
  // Spacing
  spacing: {
    xs: '0.25rem',
    sm: '0.5rem',
    md: '1rem',
    lg: '1.5rem',
    xl: '2rem',
    '2xl': '3rem',
    '3xl': '4rem',
  },
  
  // Border radius
  borderRadius: {
    none: '0',
    sm: '0.125rem',
    default: '0.25rem',
    md: '0.375rem',
    lg: '0.5rem',
    xl: '0.75rem',
    full: '9999px',
  },
  
  // Shadows
  shadows: {
    sm: '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
    default: '0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06)',
    md: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
    lg: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
    xl: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
  },
  
  // Transitions
  transitions: {
    fast: '150ms ease-in-out',
    normal: '300ms ease-in-out',
    slow: '500ms ease-in-out',
  },
  
  // Z-index
  zIndex: {
    dropdown: 1000,
    modal: 1050,
    popover: 1100,
    tooltip: 1150,
    notification: 1200,
  },
} as const

// Tailwind class helpers
export const tailwindClasses = {
  // Buttons
  button: {
    base: 'inline-flex items-center justify-center font-medium rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-slate-900',
    primary: 'bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500',
    secondary: 'bg-slate-700 text-slate-100 hover:bg-slate-600 focus:ring-slate-500',
    danger: 'bg-red-600 text-white hover:bg-red-700 focus:ring-red-500',
    ghost: 'bg-transparent hover:bg-slate-800 text-slate-300 hover:text-slate-100',
    sizes: {
      sm: 'px-3 py-1.5 text-sm',
      md: 'px-4 py-2 text-base',
      lg: 'px-6 py-3 text-lg',
    },
  },
  
  // Cards
  card: {
    base: 'bg-slate-900 rounded-lg border border-slate-800',
    hover: 'hover:border-slate-700 transition-colors',
    padding: {
      sm: 'p-4',
      md: 'p-6',
      lg: 'p-8',
    },
  },
  
  // Inputs
  input: {
    base: 'w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors',
    error: 'border-red-500 focus:ring-red-500',
    disabled: 'opacity-50 cursor-not-allowed',
  },
  
  // Badges
  badge: {
    base: 'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
    success: 'bg-green-500/20 text-green-400',
    warning: 'bg-amber-500/20 text-amber-400',
    error: 'bg-red-500/20 text-red-400',
    info: 'bg-blue-500/20 text-blue-400',
  },
} as const

// Utility functions
export const getThemeColor = (path: string): string => {
  const keys = path.split('.')
  let value: any = theme
  
  for (const key of keys) {
    value = value[key]
    if (!value) return ''
  }
  
  return value
}

export const getThreatLevelColor = (level: string): string => {
  return theme.colors.threat[level as keyof typeof theme.colors.threat] || theme.colors.threat.low
}

export const getStatusColor = (status: string): string => {
  return theme.colors.status[status as keyof typeof theme.colors.status] || theme.colors.status.info
}