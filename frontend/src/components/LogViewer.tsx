import Editor, { Monaco } from '@monaco-editor/react'
import { useRef, useState } from 'react'
import { Search, Copy, Download, Maximize2, Minimize2 } from 'lucide-react'
import clsx from 'clsx'

interface LogViewerProps {
  content: string
  language?: string
  height?: string | number
  className?: string
  downloadFileName?: string
}

export default function LogViewer({
  content,
  language = 'log',
  height = '400px',
  className,
  downloadFileName = 'logs.txt'
}: LogViewerProps) {
  const editorRef = useRef<any>(null)
  const [isFullscreen, setIsFullscreen] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [showSearch, setShowSearch] = useState(false)
  const [copySuccess, setCopySuccess] = useState(false)

  const handleEditorDidMount = (editor: any, monaco: Monaco) => {
    editorRef.current = editor

    // Define custom log language if not exists
    monaco.languages.register({ id: 'log' })
    monaco.languages.setMonarchTokensProvider('log', {
      tokenizer: {
        root: [
          // Timestamps
          [/\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}/, 'custom-date'],
          [/\[\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}/, 'custom-date'],
          
          // Log levels
          [/\b(ERROR|FATAL|CRITICAL)\b/, 'custom-error'],
          [/\b(WARN|WARNING)\b/, 'custom-warning'],
          [/\b(INFO|INFORMATION)\b/, 'custom-info'],
          [/\b(DEBUG|TRACE|VERBOSE)\b/, 'custom-debug'],
          
          // IP addresses
          [/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/, 'custom-ip'],
          
          // URLs
          [/https?:\/\/[^\s]+/, 'custom-url'],
          
          // Strings
          [/".*?"/, 'string'],
          [/'.*?'/, 'string'],
          
          // Numbers
          [/\b\d+\b/, 'number'],
          
          // Special characters
          [/[\[\]{}()]/, 'delimiter.bracket'],
        ]
      }
    })

    // Define custom theme
    monaco.editor.defineTheme('log-dark', {
      base: 'vs-dark',
      inherit: true,
      rules: [
        { token: 'custom-date', foreground: '3b82f6' },
        { token: 'custom-error', foreground: 'ef4444', fontStyle: 'bold' },
        { token: 'custom-warning', foreground: 'f59e0b' },
        { token: 'custom-info', foreground: '10b981' },
        { token: 'custom-debug', foreground: '6b7280' },
        { token: 'custom-ip', foreground: 'a78bfa' },
        { token: 'custom-url', foreground: '60a5fa', fontStyle: 'underline' },
      ],
      colors: {
        'editor.background': '#0f172a',
        'editor.foreground': '#e2e8f0',
        'editor.lineHighlightBackground': '#1e293b',
        'editorLineNumber.foreground': '#475569',
        'editorGutter.background': '#0f172a',
        'editor.selectionBackground': '#3b82f644',
        'editor.inactiveSelectionBackground': '#3b82f622',
      }
    })

    monaco.editor.setTheme('log-dark')
  }

  const handleSearch = () => {
    if (!editorRef.current || !searchQuery) return
    
    const model = editorRef.current.getModel()
    const matches = model.findMatches(
      searchQuery,
      true, // searchOnlyEditableRange
      false, // isRegex
      false, // matchCase
      null, // wordSeparators
      true // captureMatches
    )
    
    if (matches.length > 0) {
      editorRef.current.setSelection(matches[0].range)
      editorRef.current.revealRangeInCenter(matches[0].range)
      editorRef.current.trigger('', 'actions.find')
    }
  }

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(content)
      setCopySuccess(true)
      setTimeout(() => setCopySuccess(false), 2000)
    } catch (err) {
      console.error('Failed to copy:', err)
    }
  }

  const handleDownload = () => {
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = downloadFileName
    a.click()
    URL.revokeObjectURL(url)
  }

  const toggleFullscreen = () => {
    setIsFullscreen(!isFullscreen)
  }

  return (
    <div
      className={clsx(
        'relative bg-slate-950 rounded-lg overflow-hidden border border-slate-800',
        isFullscreen && 'fixed inset-4 z-50',
        className
      )}
    >
      {/* Toolbar */}
      <div className="flex items-center justify-between px-4 py-2 bg-slate-900 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <span className="text-sm text-slate-400">Log Viewer</span>
          <span className="text-xs text-slate-500">
            ({content.split('\n').length} lines)
          </span>
        </div>
        
        <div className="flex items-center space-x-2">
          {/* Search */}
          {showSearch && (
            <div className="flex items-center space-x-2 mr-2">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                placeholder="Search logs..."
                className="px-2 py-1 text-sm bg-slate-800 border border-slate-700 rounded text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>
          )}
          
          <button
            onClick={() => setShowSearch(!showSearch)}
            className={clsx(
              'p-1.5 rounded transition-colors',
              showSearch 
                ? 'bg-blue-500/20 text-blue-400' 
                : 'hover:bg-slate-800 text-slate-400 hover:text-white'
            )}
            title="Search"
          >
            <Search className="w-4 h-4" />
          </button>
          
          <button
            onClick={handleCopy}
            className="p-1.5 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition-colors"
            title="Copy to clipboard"
          >
            {copySuccess ? (
              <span className="text-xs text-green-400">Copied!</span>
            ) : (
              <Copy className="w-4 h-4" />
            )}
          </button>
          
          <button
            onClick={handleDownload}
            className="p-1.5 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition-colors"
            title="Download"
          >
            <Download className="w-4 h-4" />
          </button>
          
          <button
            onClick={toggleFullscreen}
            className="p-1.5 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition-colors"
            title={isFullscreen ? 'Exit fullscreen' : 'Fullscreen'}
          >
            {isFullscreen ? (
              <Minimize2 className="w-4 h-4" />
            ) : (
              <Maximize2 className="w-4 h-4" />
            )}
          </button>
        </div>
      </div>
      
      {/* Editor */}
      <Editor
        height={isFullscreen ? 'calc(100% - 48px)' : height}
        language={language}
        value={content}
        onMount={handleEditorDidMount}
        options={{
          readOnly: true,
          minimap: { enabled: false },
          fontSize: 14,
          fontFamily: 'JetBrains Mono, Consolas, Monaco, monospace',
          lineNumbers: 'on',
          scrollBeyondLastLine: false,
          automaticLayout: true,
          wordWrap: 'on',
          theme: 'log-dark',
          renderWhitespace: 'none',
          scrollbar: {
            vertical: 'visible',
            horizontal: 'visible',
            verticalScrollbarSize: 10,
            horizontalScrollbarSize: 10,
          },
          padding: {
            top: 16,
            bottom: 16,
          },
          find: {
            addExtraSpaceOnTop: false,
            autoFindInSelection: 'never',
            seedSearchStringFromSelection: true,
          }
        }}
      />
      
      {/* Line indicator */}
      <div className="absolute bottom-2 right-2 text-xs text-slate-500 bg-slate-900/80 px-2 py-1 rounded">
        {editorRef.current && `Ln ${editorRef.current.getPosition()?.lineNumber || 1}`}
      </div>
    </div>
  )
}