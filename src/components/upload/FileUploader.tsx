import React, { useState, useCallback, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';
import { motion } from 'framer-motion';
import { Upload as UploadIcon, X } from 'lucide-react';
import { uploadService } from '../../services/uploadService';
import { analysisService } from '../../services/analysisService';
import { formatFileSize } from '../../utils/formatters';
import FileItem from './FileItem';
import toast from 'react-hot-toast';

export interface UploadedFile {
  id: string;
  file: File;
  status: 'uploading' | 'uploaded' | 'parsing' | 'analyzing' | 'completed' | 'error';
  progress: number;
  uploadResult?: any;
  analysisId?: string;
  error?: string;
}

interface FileUploaderProps {
  onFileUploaded?: (file: UploadedFile) => void;
  onAnalysisStarted?: (analysisId: string, fileId: string) => void;
  autoAnalyze?: boolean;
  maxFiles?: number;
  maxSize?: number;
  acceptedFileTypes?: string[];
}

const FileUploader: React.FC<FileUploaderProps> = ({
  onFileUploaded,
  onAnalysisStarted,
  autoAnalyze = true,
  maxFiles = 10,
  maxSize = 1073741824, // 1GB
  acceptedFileTypes
}) => {
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([]);
  const [dragActive, setDragActive] = useState(false);
  const [supportedTypes, setSupportedTypes] = useState<string[]>([]);

  useEffect(() => {
    // Load supported file types from backend
    const loadSupportedTypes = async () => {
      try {
        const response = await uploadService.getSupportedFileTypes();
        if (response?.extensions) {
          setSupportedTypes(response.extensions);
        }
      } catch (error) {
        console.error('Failed to load supported file types:', error);
      }
    };
    
    loadSupportedTypes();
  }, []);

  const uploadAndAnalyzeFile = async (fileId: string) => {
    const fileIndex = uploadedFiles.findIndex(f => f.id === fileId);
    if (fileIndex === -1) return;

    const uploadedFile = uploadedFiles[fileIndex];
    
    try {
      // Upload file
      setUploadedFiles(prev => prev.map(f => 
        f.id === fileId 
          ? { ...f, status: 'uploading', progress: 0 }
          : f
      ));

      const uploadResult = await uploadService.uploadFile(uploadedFile.file, {
        autoAnalyze: false,
        tags: ['frontend-upload'],
        onProgress: (progress) => {
          setUploadedFiles(prev => prev.map(f => 
            f.id === fileId 
              ? { ...f, progress }
              : f
          ));
        }
      });

      // Update with upload result
      const updatedFile = {
        ...uploadedFile,
        status: 'uploaded',
        progress: 100,
        uploadResult
      };
      
      setUploadedFiles(prev => prev.map(f => 
        f.id === fileId ? updatedFile : f
      ));
      
      if (onFileUploaded) {
        onFileUploaded(updatedFile);
      }

      // Start analysis if autoAnalyze is true
      if (autoAnalyze) {
        setUploadedFiles(prev => prev.map(f => 
          f.id === fileId 
            ? { ...f, status: 'analyzing' }
            : f
        ));

        const analysisResult = await analysisService.startAnalysis(uploadResult.id, {
          analyzers: ['yara', 'sigma', 'mitre', 'ai', 'patterns'],
          deepScan: true,
          extractIocs: true,
          checkVirusTotal: true
        });

        const finalFile = {
          ...updatedFile,
          status: 'completed',
          analysisId: analysisResult.analysis_id
        };
        
        setUploadedFiles(prev => prev.map(f => 
          f.id === fileId ? finalFile : f
        ));
        
        if (onAnalysisStarted) {
          onAnalysisStarted(analysisResult.analysis_id, fileId);
        }

        toast.success('File uploaded and analysis started!');
      } else {
        toast.success('File uploaded successfully!');
      }

    } catch (error: any) {
      console.error('Upload/Analysis error:', error);
      setUploadedFiles(prev => prev.map(f => 
        f.id === fileId 
          ? { ...f, status: 'error', error: error.message }
          : f
      ));
      toast.error(error.message || 'Upload failed');
    }
  };

  const onDrop = useCallback((acceptedFiles: File[]) => {
    // Check if adding these files would exceed maxFiles
    if (uploadedFiles.length + acceptedFiles.length > maxFiles) {
      toast.error(`You can only upload a maximum of ${maxFiles} files at once.`);
      return;
    }

    const newFiles: UploadedFile[] = acceptedFiles.map(file => ({
      id: `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      file,
      status: 'uploading',
      progress: 0
    }));

    setUploadedFiles(prev => [...prev, ...newFiles]);
    
    // Start upload and analysis for each file
    newFiles.forEach(file => {
      uploadAndAnalyzeFile(file.id);
    });

    toast.success(`${acceptedFiles.length} file(s) queued for upload${autoAnalyze ? ' and analysis' : ''}!`);
  }, [uploadedFiles.length, maxFiles, autoAnalyze, onFileUploaded, onAnalysisStarted]);

  const { getRootProps, getInputProps, isDragActive, fileRejections } = useDropzone({
    onDrop,
    multiple: true,
    maxSize,
    accept: acceptedFileTypes ? acceptedFileTypes.reduce((acc, type) => {
      acc[type] = [];
      return acc;
    }, {} as Record<string, string[]>) : undefined,
    onDragEnter: () => setDragActive(true),
    onDragLeave: () => setDragActive(false),
  });

  const removeFile = (fileId: string) => {
    setUploadedFiles(prev => prev.filter(f => f.id !== fileId));
    toast.success('File removed');
  };

  // Show file rejection errors
  React.useEffect(() => {
    fileRejections.forEach(({ file, errors }) => {
      const errorMessages = errors.map(e => e.message).join(', ');
      toast.error(`${file.name}: ${errorMessages}`);
    });
  }, [fileRejections]);

  return (
    <div className="space-y-6">
      {/* Upload Area */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className={`bg-slate-900/50 rounded-lg border-2 border-dashed p-12 text-center transition-colors ${
          dragActive ? 'border-blue-500 bg-blue-900/10' : 'border-slate-700 hover:border-blue-500'
        }`}
        {...getRootProps()}
      >
        <input {...getInputProps()} />
        <motion.div
          animate={{ scale: isDragActive ? 1.1 : 1 }}
          transition={{ type: "spring", stiffness: 300, damping: 30 }}
        >
          <UploadIcon className="w-16 h-16 text-blue-400 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-white mb-2">
            {isDragActive ? 'Drop files here' : 'Drag & drop files here'}
          </h3>
          <p className="text-slate-400 mb-4">
            or click to browse and select files for analysis
          </p>
          <div className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
            <UploadIcon className="w-4 h-4 mr-2" />
            Choose Files
          </div>
        </motion.div>
      </motion.div>

      {/* Uploaded Files */}
      {uploadedFiles.length > 0 && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-white">
              Uploaded Files ({uploadedFiles.length})
            </h3>
            {uploadedFiles.length > 0 && (
              <button
                onClick={() => setUploadedFiles([])}
                className="text-sm text-slate-400 hover:text-white transition-colors"
              >
                Clear All
              </button>
            )}
          </div>
          
          <div className="space-y-4">
            {uploadedFiles.map((file) => (
              <FileItem
                key={file.id}
                file={file}
                onRemove={() => removeFile(file.id)}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default FileUploader;