import { useState, useRef, DragEvent } from 'react'
import { useApi } from '../hooks/useApi'
import { analysisAPI } from '../services/analysisAPI'
import { useNotification } from '../contexts/NotificationContext'
import { 
  Upload, 
  File, 
  X, 
  AlertCircle,
  CheckCircle,
  Loader2
} from 'lucide-react'

interface FileUploadProps {
  onUploadSuccess?: () => void
}

const MAX_FILE_SIZE = 100 * 1024 * 1024 // 100MB
const ALLOWED_EXTENSIONS = ['.log', '.txt', '.json', '.xml', '.csv', '.evtx', '.pcap', '.dmp']

export default function FileUpload({ onUploadSuccess }: FileUploadProps) {
  const [isDragging, setIsDragging] = useState(false)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [uploadProgress, setUploadProgress] = useState(0)
  const fileInputRef = useRef<HTMLInputElement>(null)
  
  const { success, error: showError } = useNotification()
  const { execute: uploadFile, loading: uploading } = useApi(analysisAPI.uploadFile)
  
  const validateFile = (file: File): string | null => {
    // Check file size
    if (file.size > MAX_FILE_SIZE) {
      return `File size exceeds ${MAX_FILE_SIZE / 1024 / 1024}MB limit`
    }
    
    // Check file extension
    const extension = '.' + file.name.split('.').pop()?.toLowerCase()
    if (!ALLOWED_EXTENSIONS.includes(extension)) {
      return `File type not supported. Allowed types: ${ALLOWED_EXTENSIONS.join(', ')}`
    }
    
    return null
  }
  
  const handleDrag = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    e.stopPropagation()
  }
  
  const handleDragIn = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.dataTransfer.items && e.dataTransfer.items.length > 0) {
      setIsDragging(true)
    }
  }
  
  const handleDragOut = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
  }
  
  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
    
    const files = e.dataTransfer.files
    if (files && files.length > 0) {
      handleFileSelect(files[0])
    }
  }
  
  const handleFileSelect = (file: File) => {
    const error = validateFile(file)
    if (error) {
      showError(error)
      return
    }
    setSelectedFile(file)
    setUploadProgress(0)
  }
  
  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files
    if (files && files.length > 0) {
      handleFileSelect(files[0])
    }
  }
  
  const handleUpload = async () => {
    if (!selectedFile) return
    
    try {
      // Simulate progress updates
      const progressInterval = setInterval(() => {
        setUploadProgress(prev => {
          if (prev >= 90) {
            clearInterval(progressInterval)
            return 90
          }
          return prev + 10
        })
      }, 200)
      
      const result = await uploadFile({
        file: selectedFile,
        analysisType: 'full' // Default analysis type
      })
      
      clearInterval(progressInterval)
      setUploadProgress(100)
      
      if (result) {
        success(`File "${selectedFile.name}" uploaded successfully. Analysis started.`)
        setTimeout(() => {
          setSelectedFile(null)
          setUploadProgress(0)
          onUploadSuccess?.()
        }, 1000)
      }
    } catch (err) {
      showError(`Failed to upload file: ${err.message || 'Unknown error'}`)
      setUploadProgress(0)
    }
  }
  
  const handleCancel = () => {
    setSelectedFile(null)
    setUploadProgress(0)
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }
  
  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  }
  
  return (
    <div className="space-y-4">
      {/* Drop Zone */}
      <div
        onDrag={handleDrag}
        onDragEnter={handleDragIn}
        onDragLeave={handleDragOut}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`
          relative border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-all
          ${isDragging 
            ? 'border-blue-400 bg-blue-400/10' 
            : 'border-slate-700 hover:border-slate-600 bg-slate-800/50'
          }
          ${uploading ? 'pointer-events-none opacity-50' : ''}
        `}
      >
        <input
          ref={fileInputRef}
          type="file"
          onChange={handleFileInputChange}
          accept={ALLOWED_EXTENSIONS.join(',')}
          className="hidden"
          disabled={uploading}
        />
        
        <Upload className={`w-12 h-12 mx-auto mb-4 ${
          isDragging ? 'text-blue-400' : 'text-slate-500'
        }`} />
        
        <p className="text-white font-medium mb-2">
          {isDragging ? 'Drop file here' : 'Drag and drop a file here'}
        </p>
        <p className="text-sm text-slate-400">
          or <span className="text-blue-400 hover:text-blue-300">browse</span> to choose a file
        </p>
        <p className="text-xs text-slate-500 mt-2">
          Supported formats: {ALLOWED_EXTENSIONS.join(', ')} (max {MAX_FILE_SIZE / 1024 / 1024}MB)
        </p>
      </div>
      
      {/* Selected File */}
      {selectedFile && (
        <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
          <div className="flex items-start justify-between">
            <div className="flex items-start space-x-3">
              <File className="w-5 h-5 text-slate-400 mt-0.5" />
              <div>
                <p className="text-white font-medium">{selectedFile.name}</p>
                <p className="text-sm text-slate-400">
                  {formatFileSize(selectedFile.size)}
                </p>
              </div>
            </div>
            {!uploading && (
              <button
                onClick={handleCancel}
                className="text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            )}
          </div>
          
          {/* Progress Bar */}
          {uploading && (
            <div className="mt-4">
              <div className="flex items-center justify-between text-sm mb-2">
                <span className="text-slate-400">Uploading...</span>
                <span className="text-white">{uploadProgress}%</span>
              </div>
              <div className="w-full h-2 bg-slate-700 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-blue-500 transition-all duration-300"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
            </div>
          )}
          
          {/* Upload Button */}
          {!uploading && uploadProgress === 0 && (
            <button
              onClick={handleUpload}
              className="mt-4 w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors flex items-center justify-center"
            >
              <Upload className="w-4 h-4 mr-2" />
              Start Analysis
            </button>
          )}
          
          {/* Success Message */}
          {uploadProgress === 100 && (
            <div className="mt-4 flex items-center text-green-400">
              <CheckCircle className="w-5 h-5 mr-2" />
              <span className="text-sm">Upload complete! Analysis started.</span>
            </div>
          )}
        </div>
      )}
      
      {/* Info Box */}
      <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4 flex items-start">
        <AlertCircle className="w-5 h-5 text-blue-400 mr-3 flex-shrink-0 mt-0.5" />
        <div className="text-sm">
          <p className="text-blue-400 font-medium mb-1">
            Automated Analysis
          </p>
          <p className="text-slate-400">
            Files are automatically analyzed upon upload. You'll receive real-time updates as the analysis progresses.
          </p>
        </div>
      </div>
    </div>
  )
}