/// <reference types="vite/client" />

interface ImportMetaEnv {
  // API Configuration
  readonly VITE_API_URL: string
  readonly VITE_SIGNALR_URL: string
  readonly VITE_API_TIMEOUT: string
  
  // Feature Flags
  readonly VITE_ENABLE_AI_ANALYSIS: string
  readonly VITE_ENABLE_REAL_TIME: string
  readonly VITE_ENABLE_EXPORT: string
  
  // Application Info
  readonly VITE_APP_NAME: string
  readonly VITE_APP_VERSION: string
  readonly VITE_APP_ENVIRONMENT: 'development' | 'production' | 'staging'
  
  // External Services (Optional)
  readonly VITE_OPENAI_API_KEY?: string
  readonly VITE_VIRUSTOTAL_API_KEY?: string
  
  // File Upload Configuration
  readonly VITE_MAX_FILE_SIZE: string
  readonly VITE_ALLOWED_FILE_TYPES: string
  
  // Performance Configuration
  readonly VITE_DEBOUNCE_DELAY: string
  readonly VITE_POLLING_INTERVAL: string
  
  // Debug Configuration
  readonly VITE_ENABLE_DEBUG: string
  readonly VITE_LOG_LEVEL: 'error' | 'warn' | 'info' | 'debug'
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

// Global type declarations
declare global {
  interface Window {
    __APP_VERSION__: string
    __APP_BUILD_TIME__: string
  }
}

// Module declarations
declare module '*.svg' {
  import React = require('react')
  export const ReactComponent: React.FC<React.SVGProps<SVGSVGElement>>
  const src: string
  export default src
}

declare module '*.jpg' {
  const content: string
  export default content
}

declare module '*.png' {
  const content: string
  export default content
}

declare module '*.json' {
  const content: string
  export default content
}

// Extend existing types
declare module 'react' {
  interface CSSProperties {
    [key: `--${string}`]: string | number
  }
}