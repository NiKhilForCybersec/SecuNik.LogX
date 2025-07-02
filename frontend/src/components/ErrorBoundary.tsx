import { Component, ErrorInfo, ReactNode } from 'react'
import { AlertTriangle, RefreshCw, Home } from 'lucide-react'

interface Props {
  children: ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
  errorInfo: ErrorInfo | null
}

class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null, errorInfo: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo)
    this.setState({ errorInfo })
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null })
    window.location.href = '/'
  }

  handleReload = () => {
    window.location.reload()
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
          <div className="max-w-md w-full">
            {/* Glass effect card */}
            <div className="bg-slate-900/95 backdrop-blur-sm rounded-lg p-8 border border-slate-800 shadow-2xl">
              {/* Icon */}
              <div className="flex items-center justify-center w-16 h-16 bg-gradient-to-br from-red-500/20 to-orange-500/20 rounded-full mx-auto mb-6">
                <AlertTriangle className="w-8 h-8 text-orange-400" />
              </div>
              
              {/* Title */}
              <h1 className="text-2xl font-bold text-center text-white mb-2">
                Application Error
              </h1>
              
              {/* Description */}
              <p className="text-slate-400 text-center mb-6">
                An unexpected error occurred in the forensics platform. Your data is safe and no analysis was lost.
              </p>
              
              {/* Error details in development */}
              {process.env.NODE_ENV === 'development' && this.state.error && (
                <div className="bg-slate-800/50 rounded-lg p-4 mb-6 border border-slate-700">
                  <p className="text-xs font-mono text-red-400 break-all">
                    {this.state.error.toString()}
                  </p>
                  {this.state.errorInfo && (
                    <details className="mt-2">
                      <summary className="text-xs text-slate-500 cursor-pointer hover:text-slate-400">
                        Stack trace
                      </summary>
                      <pre className="text-xs text-slate-500 mt-2 overflow-auto max-h-40">
                        {this.state.errorInfo.componentStack}
                      </pre>
                    </details>
                  )}
                </div>
              )}
              
              {/* Actions */}
              <div className="flex flex-col space-y-3">
                <button
                  onClick={this.handleReset}
                  className="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white font-medium py-3 px-4 rounded-lg transition-all duration-200 flex items-center justify-center space-x-2"
                >
                  <Home className="w-4 h-4" />
                  <span>Return to Dashboard</span>
                </button>
                
                <button
                  onClick={this.handleReload}
                  className="w-full bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium py-3 px-4 rounded-lg transition-colors flex items-center justify-center space-x-2"
                >
                  <RefreshCw className="w-4 h-4" />
                  <span>Reload Page</span>
                </button>
              </div>
              
              {/* Support info */}
              <p className="text-xs text-slate-500 text-center mt-6">
                If this error persists, please check the console for more details
              </p>
            </div>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

export default ErrorBoundary