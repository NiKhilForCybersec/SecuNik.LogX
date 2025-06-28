import React from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { 
  X, 
  Play, 
  FileText, 
  Database, 
  Code, 
  CheckCircle, 
  AlertCircle, 
  Clock, 
  Zap
} from 'lucide-react';
import { formatFileSize } from '../../utils/formatters';
import { UploadedFile } from './FileUploader';

interface FileItemProps {
  file: UploadedFile;
  onRemove: () => void;
}

const FileItem: React.FC<FileItemProps> = ({ file, onRemove }) => {
  const navigate = useNavigate();

  const getFileIcon = (fileName: string) => {
    const extension = fileName.split('.').pop()?.toLowerCase();
    
    switch (extension) {
      case 'evtx':
      case 'evt':
        return <Database className="w-8 h-8 text-blue-400" />;
      case 'log':
      case 'txt':
        return <FileText className="w-8 h-8 text-green-400" />;
      case 'json':
      case 'xml':
        return <Code className="w-8 h-8 text-yellow-400" />;
      case 'csv':
        return <FileText className="w-8 h-8 text-purple-400" />;
      default:
        return <FileText className="w-8 h-8 text-slate-400" />;
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'uploading':
        return <Clock className="w-5 h-5 text-blue-400 animate-spin" />;
      case 'uploaded':
        return <CheckCircle className="w-5 h-5 text-green-400" />;
      case 'parsing':
        return <Clock className="w-5 h-5 text-yellow-400 animate-spin" />;
      case 'analyzing':
        return <Zap className="w-5 h-5 text-purple-400 animate-pulse" />;
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-400" />;
      case 'error':
        return <AlertCircle className="w-5 h-5 text-red-400" />;
      default:
        return <Clock className="w-5 h-5 text-slate-400" />;
    }
  };

  const getStatusText = (status: string) => {
    switch (status) {
      case 'uploading': return 'Uploading...';
      case 'uploaded': return 'Upload Complete';
      case 'parsing': return 'Parsing Data...';
      case 'analyzing': return 'Running Analysis...';
      case 'completed': return 'Analysis Complete';
      case 'error': return 'Error';
      default: return 'Unknown';
    }
  };

  const viewAnalysis = () => {
    if (file.analysisId) {
      navigate(`/analysis/${file.analysisId}`);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      className="flex items-center space-x-4 p-4 bg-slate-800/50 rounded-lg"
    >
      {getFileIcon(file.file.name)}
      
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between">
          <h4 className="text-sm font-medium text-white truncate">
            {file.file.name}
          </h4>
          <div className="flex items-center space-x-2">
            {file.analysisId && file.status === 'completed' && (
              <button
                onClick={viewAnalysis}
                className="flex items-center space-x-1 px-2 py-1 bg-blue-600 text-white text-xs rounded hover:bg-blue-700 transition-colors"
              >
                <Play className="w-3 h-3" />
                <span>View Analysis</span>
              </button>
            )}
            <button
              onClick={onRemove}
              className="text-slate-400 hover:text-red-400 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
        
        <div className="flex items-center space-x-4 mt-1">
          <span className="text-xs text-slate-400">{formatFileSize(file.file.size)}</span>
          {file.uploadResult?.parser_detected && (
            <span className="text-xs text-blue-400">Parser: {file.uploadResult.parser_detected}</span>
          )}
        </div>
        
        <div className="flex items-center space-x-3 mt-2">
          {getStatusIcon(file.status)}
          <span className="text-xs text-slate-400">
            {getStatusText(file.status)}
          </span>
          
          {file.status === 'uploading' && (
            <div className="flex-1 bg-slate-700 rounded-full h-2">
              <motion.div
                className="bg-blue-500 h-2 rounded-full"
                initial={{ width: 0 }}
                animate={{ width: `${file.progress}%` }}
                transition={{ duration: 0.3 }}
              />
            </div>
          )}
          
          {file.error && (
            <span className="text-xs text-red-400">{file.error}</span>
          )}
        </div>
      </div>
    </motion.div>
  );
};

export default FileItem;