import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  Code2,
  Play,
  Save,
  Plus,
  FileText,
  Settings,
  TestTube,
  CheckCircle,
  AlertCircle,
  Download,
  Upload,
  Trash2,
  Edit,
  Copy,
  RefreshCw
} from 'lucide-react'
import Editor from '@monaco-editor/react'
import { parserService } from '../services/parserService'
import toast from 'react-hot-toast'

const ParserStudio: React.FC = () => {
  const [activeTab, setActiveTab] = useState('editor')
  const [selectedParser, setSelectedParser] = useState<string | null>(null)
  const [parserCode, setParserCode] = useState('')
  const [parserName, setParserName] = useState('')
  const [parserDescription, setParserDescription] = useState('')
  const [supportedExtensions, setSupportedExtensions] = useState('')
  const [testInput, setTestInput] = useState('')
  const [testResults, setTestResults] = useState<any>(null)
  const [isCompiling, setIsCompiling] = useState(false)
  const [parsers, setParsers] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadParsers()
  }, [])

  useEffect(() => {
    if (selectedParser && selectedParser !== 'new') {
      loadParserDetails(selectedParser)
    } else if (selectedParser === 'new') {
      resetParserForm()
    }
  }, [selectedParser])

  const loadParsers = async () => {
    try {
      setLoading(true)
      const response = await parserService.getParsers()
      setParsers(response)
    } catch (error) {
      console.error('Failed to load parsers:', error)
      toast.error('Failed to load parsers')
    } finally {
      setLoading(false)
    }
  }

  const loadParserDetails = async (parserId: string) => {
    try {
      const parser = await parserService.getParser(parserId)
      setParserCode(parser.codeContent || '')
      setParserName(parser.name)
      setParserDescription(parser.description)
      setSupportedExtensions(parser.supportedExtensions.join(', '))
    } catch (error) {
      console.error('Failed to load parser details:', error)
      toast.error('Failed to load parser details')
    }
  }

  const resetParserForm = () => {
    setParserCode(`// SecuNik LogX Custom Parser
// Parser Name: Custom Log Parser
// Description: Parse custom application logs

using System;
using System.Text.Json;
using System.Text.RegularExpressions;
using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Core.Models;

public class CustomLogParser : IParser
{
    public string Name => "Custom Log Parser";
    public string Description => "Parses custom application logs";
    public string[] SupportedExtensions => new[] { ".log", ".txt" };

    public bool CanParse(string content)
    {
        // Check if content matches expected format
        return content.Contains("[INFO]") || content.Contains("[ERROR]") || content.Contains("[WARN]");
    }

    public ParseResult Parse(string content)
    {
        var events = new List<LogEvent>();
        var lines = content.Split('\\n');
        
        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            
            var match = Regex.Match(line, @"(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}) \\[(\\w+)\\] (.+)");
            
            if (match.Success)
            {
                var logEvent = new LogEvent
                {
                    Timestamp = DateTime.Parse(match.Groups[1].Value),
                    Level = match.Groups[2].Value,
                    Message = match.Groups[3].Value,
                    RawData = line
                };
                
                events.Add(logEvent);
            }
        }
        
        return new ParseResult
        {
            Success = true,
            Events = events,
            ParserUsed = Name,
            EventsCount = events.Count
        };
    }
}`)
    setParserName('New Custom Parser')
    setParserDescription('Parse custom application logs')
    setSupportedExtensions('.log, .txt')
    setTestInput(`2024-01-15 10:30:00 [INFO] Application started successfully
2024-01-15 10:30:01 [INFO] Database connection established
2024-01-15 10:30:15 [WARN] High memory usage detected: 85%
2024-01-15 10:31:00 [ERROR] Failed to process request: timeout
2024-01-15 10:31:05 [INFO] Request retry successful`)
  }

  const testParser = async () => {
    if (!selectedParser) {
      toast.error('Please select or create a parser first')
      return
    }
    
    setIsCompiling(true)
    setTestResults(null)
    
    try {
      let result
      
      if (selectedParser === 'new') {
        // Validate parser code first
        const validation = await parserService.validateParser(parserCode)
        if (!validation.isValid) {
          toast.error('Parser validation failed: ' + validation.errors[0])
          setTestResults({
            success: false,
            errors: validation.errors,
            warnings: validation.warnings
          })
          return
        }
        
        // Create temporary parser for testing
        const tempParser = await parserService.createParser({
          name: parserName,
          description: parserDescription,
          version: '1.0.0',
          author: 'User',
          supportedExtensions: supportedExtensions.split(',').map(ext => ext.trim()),
          codeContent: parserCode
        })
        
        // Test the parser
        result = await parserService.testParser(tempParser.id, testInput)
        
        // Delete temporary parser
        await parserService.deleteParser(tempParser.id)
      } else {
        // Test existing parser
        result = await parserService.testParser(selectedParser, testInput)
      }
      
      setTestResults(result)
      
      if (result.success) {
        toast.success('Parser test successful')
      } else {
        toast.error('Parser test failed: ' + result.errorMessage)
      }
    } catch (error: any) {
      console.error('Parser test error:', error)
      toast.error('Parser test failed: ' + error.message)
      setTestResults({
        success: false,
        errors: [error.message],
        warnings: []
      })
    } finally {
      setIsCompiling(false)
    }
  }

  const saveParser = async () => {
    try {
      if (!parserName) {
        toast.error('Parser name is required')
        return
      }
      
      if (!parserCode) {
        toast.error('Parser code is required')
        return
      }
      
      // Validate parser code
      const validation = await parserService.validateParser(parserCode)
      if (!validation.isValid) {
        toast.error('Parser validation failed: ' + validation.errors[0])
        return
      }
      
      if (selectedParser === 'new') {
        // Create new parser
        await parserService.createParser({
          name: parserName,
          description: parserDescription,
          version: '1.0.0',
          author: 'User',
          supportedExtensions: supportedExtensions.split(',').map(ext => ext.trim()),
          codeContent: parserCode
        })
        toast.success('Parser created successfully')
      } else if (selectedParser) {
        // Update existing parser
        await parserService.updateParser(selectedParser, {
          description: parserDescription,
          supportedExtensions: supportedExtensions.split(',').map(ext => ext.trim()),
          codeContent: parserCode
        })
        toast.success('Parser updated successfully')
      }
      
      // Reload parsers
      loadParsers()
    } catch (error: any) {
      console.error('Save parser error:', error)
      toast.error('Failed to save parser: ' + error.message)
    }
  }

  const deleteParser = async (parserId: string) => {
    if (!confirm('Are you sure you want to delete this parser?')) return
    
    try {
      await parserService.deleteParser(parserId)
      toast.success('Parser deleted successfully')
      
      if (selectedParser === parserId) {
        setSelectedParser(null)
      }
      
      loadParsers()
    } catch (error: any) {
      console.error('Delete parser error:', error)
      toast.error('Failed to delete parser: ' + error.message)
    }
  }

  const tabs = [
    { id: 'editor', label: 'Code Editor', icon: Code2 },
    { id: 'test', label: 'Test Parser', icon: TestTube },
    { id: 'settings', label: 'Settings', icon: Settings },
  ]

  const builtInParsers = parsers.filter(p => p.isBuiltIn)
  const customParsers = parsers.filter(p => !p.isBuiltIn)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Parser Studio</h1>
          <p className="text-slate-400 mt-2">
            Create and manage custom log parsers for specialized file formats
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <button 
            onClick={loadParsers}
            className="flex items-center space-x-2 px-4 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Refresh</span>
          </button>
          <button className="flex items-center space-x-2 px-4 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors">
            <Download className="w-4 h-4" />
            <span>Export</span>
          </button>
          <button
            onClick={saveParser}
            disabled={!selectedParser}
            className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
          >
            <Save className="w-4 h-4" />
            <span>Save Parser</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Parser List */}
        <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-800">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Parsers</h3>
            <button 
              onClick={() => setSelectedParser('new')}
              className="p-2 text-blue-400 hover:text-blue-300 hover:bg-slate-800 rounded-lg transition-colors"
            >
              <Plus className="w-4 h-4" />
            </button>
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-8">
              <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500"></div>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Built-in Parsers */}
              {builtInParsers.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-slate-400 mb-2">Built-in Parsers</h4>
                  <div className="space-y-2">
                    {builtInParsers.map((parser) => (
                      <div
                        key={parser.id}
                        className={`p-3 rounded-lg cursor-pointer transition-colors ${
                          selectedParser === parser.id
                            ? 'bg-blue-600/20 border border-blue-500/30'
                            : 'bg-slate-800/50 hover:bg-slate-800'
                        }`}
                        onClick={() => setSelectedParser(parser.id)}
                      >
                        <div className="flex items-center justify-between">
                          <p className="text-sm font-medium text-white">{parser.name}</p>
                          <div className={`w-2 h-2 rounded-full ${parser.isEnabled ? 'bg-green-400' : 'bg-slate-400'}`}></div>
                        </div>
                        <p className="text-xs text-slate-400 mt-1">Built-in</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Custom Parsers */}
              {customParsers.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-slate-400 mb-2">Custom Parsers</h4>
                  <div className="space-y-2">
                    {customParsers.map((parser) => (
                      <div
                        key={parser.id}
                        className={`p-3 rounded-lg cursor-pointer transition-colors group ${
                          selectedParser === parser.id
                            ? 'bg-blue-600/20 border border-blue-500/30'
                            : 'bg-slate-800/50 hover:bg-slate-800'
                        }`}
                        onClick={() => setSelectedParser(parser.id)}
                      >
                        <div className="flex items-center justify-between">
                          <p className="text-sm font-medium text-white">{parser.name}</p>
                          <div className="flex items-center space-x-1">
                            <div className={`w-2 h-2 rounded-full ${
                              parser.isEnabled ? 'bg-green-400' : 'bg-yellow-400'
                            }`}></div>
                            <div className="opacity-0 group-hover:opacity-100 flex space-x-1">
                              <button 
                                className="text-slate-400 hover:text-white"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  setSelectedParser(parser.id)
                                  setActiveTab('editor')
                                }}
                              >
                                <Edit className="w-3 h-3" />
                              </button>
                              <button className="text-slate-400 hover:text-white">
                                <Copy className="w-3 h-3" />
                              </button>
                              <button 
                                className="text-slate-400 hover:text-red-400"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  deleteParser(parser.id)
                                }}
                              >
                                <Trash2 className="w-3 h-3" />
                              </button>
                            </div>
                          </div>
                        </div>
                        <p className="text-xs text-slate-400 mt-1">Custom • {new Date(parser.updatedAt).toLocaleDateString()}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* New Parser Option */}
              <button
                onClick={() => setSelectedParser('new')}
                className={`w-full p-3 rounded-lg border-2 border-dashed transition-colors ${
                  selectedParser === 'new'
                    ? 'border-blue-500 bg-blue-600/10'
                    : 'border-slate-600 hover:border-slate-500'
                }`}
              >
                <div className="flex items-center justify-center space-x-2">
                  <Plus className="w-4 h-4 text-blue-400" />
                  <span className="text-sm font-medium text-blue-400">New Parser</span>
                </div>
              </button>
            </div>
          )}
        </div>

        {/* Main Content */}
        <div className="lg:col-span-3 bg-slate-900/50 rounded-lg border border-slate-800">
          {/* Tabs */}
          <div className="border-b border-slate-700">
            <nav className="flex space-x-8 px-6">
              {tabs.map((tab) => {
                const Icon = tab.icon
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`flex items-center space-x-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                      activeTab === tab.id
                        ? 'border-blue-500 text-blue-400'
                        : 'border-transparent text-slate-400 hover:text-slate-300'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    <span>{tab.label}</span>
                  </button>
                )
              })}
            </nav>
          </div>

          <div className="p-6">
            {!selectedParser ? (
              <div className="text-center py-12">
                <Code2 className="w-12 h-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-300 mb-2">No Parser Selected</h3>
                <p className="text-slate-400 mb-4">
                  Select an existing parser or create a new one to get started.
                </p>
                <button
                  onClick={() => setSelectedParser('new')}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  Create New Parser
                </button>
              </div>
            ) : (
              <>
                {/* Code Editor Tab */}
                {activeTab === 'editor' && (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-lg font-semibold text-white">Parser Code</h3>
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={testParser}
                          disabled={isCompiling}
                          className="flex items-center space-x-2 px-3 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors disabled:opacity-50"
                        >
                          <Play className="w-4 h-4" />
                          <span>{isCompiling ? 'Compiling...' : 'Test Parser'}</span>
                        </button>
                      </div>
                    </div>
                    
                    <div className="border border-slate-700 rounded-lg overflow-hidden">
                      <Editor
                        height="500px"
                        defaultLanguage="csharp"
                        value={parserCode}
                        onChange={(value) => setParserCode(value || '')}
                        theme="vs-dark"
                        options={{
                          minimap: { enabled: false },
                          fontSize: 14,
                          lineNumbers: 'on',
                          roundedSelection: false,
                          scrollBeyondLastLine: false,
                          automaticLayout: true,
                        }}
                      />
                    </div>
                  </div>
                )}

                {/* Test Parser Tab */}
                {activeTab === 'test' && (
                  <div className="space-y-6">
                    <div>
                      <h3 className="text-lg font-semibold text-white mb-4">Test Input</h3>
                      <textarea
                        value={testInput}
                        onChange={(e) => setTestInput(e.target.value)}
                        className="w-full h-32 p-4 bg-slate-800 border border-slate-700 rounded-lg text-white font-mono text-sm resize-none focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="Paste sample log data here..."
                      />
                    </div>

                    <div className="flex items-center space-x-4">
                      <button
                        onClick={testParser}
                        disabled={isCompiling}
                        className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
                      >
                        <TestTube className="w-4 h-4" />
                        <span>{isCompiling ? 'Testing...' : 'Run Test'}</span>
                      </button>
                    </div>

                    {testResults && (
                      <div className="space-y-4">
                        <div className="flex items-center space-x-2">
                          {testResults.success ? (
                            <CheckCircle className="w-5 h-5 text-green-400" />
                          ) : (
                            <AlertCircle className="w-5 h-5 text-red-400" />
                          )}
                          <h4 className="text-lg font-semibold text-white">Test Results</h4>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                          <div className="bg-slate-800/50 rounded-lg p-4">
                            <p className="text-sm text-slate-400">Events Parsed</p>
                            <p className="text-2xl font-bold text-white">{testResults.matches?.[0]?.matchCount || 0}</p>
                          </div>
                          <div className="bg-slate-800/50 rounded-lg p-4">
                            <p className="text-sm text-slate-400">Errors</p>
                            <p className="text-2xl font-bold text-red-400">{testResults.errors?.length || 0}</p>
                          </div>
                          <div className="bg-slate-800/50 rounded-lg p-4">
                            <p className="text-sm text-slate-400">Warnings</p>
                            <p className="text-2xl font-bold text-yellow-400">{testResults.warnings?.length || 0}</p>
                          </div>
                        </div>

                        {testResults.matches && testResults.matches.length > 0 && testResults.matches[0].matches && (
                          <div>
                            <h5 className="text-md font-semibold text-white mb-2">Parsed Events</h5>
                            <div className="bg-slate-800/50 rounded-lg p-4 max-h-64 overflow-y-auto">
                              {testResults.matches[0].matches.map((match: any, index: number) => (
                                <div key={index} className="flex items-center space-x-4 py-2 border-b border-slate-700 last:border-b-0">
                                  <span className="text-xs text-slate-400 font-mono">{match.timestamp || 'N/A'}</span>
                                  <span className={`text-xs px-2 py-1 rounded ${
                                    match.fields?.level === 'ERROR' ? 'bg-red-900/30 text-red-400' :
                                    match.fields?.level === 'WARN' ? 'bg-yellow-900/30 text-yellow-400' :
                                    'bg-blue-900/30 text-blue-400'
                                  }`}>
                                    {match.fields?.level || 'INFO'}
                                  </span>
                                  <span className="text-sm text-white flex-1">{match.matchedContent}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {testResults.errors && testResults.errors.length > 0 && (
                          <div>
                            <h5 className="text-md font-semibold text-white mb-2">Errors</h5>
                            <div className="bg-slate-800/50 rounded-lg p-4 max-h-64 overflow-y-auto">
                              <ul className="list-disc list-inside space-y-1">
                                {testResults.errors.map((error: string, index: number) => (
                                  <li key={index} className="text-sm text-red-400">{error}</li>
                                ))}
                              </ul>
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {/* Settings Tab */}
                {activeTab === 'settings' && (
                  <div className="space-y-6">
                    <h3 className="text-lg font-semibold text-white">Parser Settings</h3>
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-slate-400 mb-2">Parser Name</label>
                        <input
                          type="text"
                          value={parserName}
                          onChange={(e) => setParserName(e.target.value)}
                          disabled={selectedParser !== 'new'}
                          className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-slate-400 mb-2">Description</label>
                        <textarea
                          value={parserDescription}
                          onChange={(e) => setParserDescription(e.target.value)}
                          className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                          rows={3}
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-slate-400 mb-2">Supported File Extensions</label>
                        <input
                          type="text"
                          value={supportedExtensions}
                          onChange={(e) => setSupportedExtensions(e.target.value)}
                          placeholder=".log, .txt"
                          className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                        <p className="text-xs text-slate-500 mt-1">Comma-separated list of file extensions (e.g., .log, .txt)</p>
                      </div>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default ParserStudio