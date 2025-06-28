import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Download, Share } from 'lucide-react';
import { formatFileSize, formatDate } from '../../utils/formatters';

interface AnalysisHeaderProps {
  analysisId: string;
  fileName?: string;
  fileSize?: number;
  fileType?: string;
  analysisDate?: string;
  severity?: string;
  onExport?: (format: string) => void;
}

const AnalysisHeader: React.FC<AnalysisHeaderProps> = ({
  analysisId,
  fileName,
  fileSize,
  fileType,
  analysisDate,
  severity,
  onExport
}) => {
  const navigate = useNavigate();

  const getThreatLevelColor = (level?: string) => {
    switch (level?.toLowerCase()) {
      case 'critical':
        return 'text-red-400 bg-red-900/30';
      case 'high':
        return 'text-orange-400 bg-orange-900/30';
      case 'medium':
        return 'text-yellow-400 bg-yellow-900/30';
      case 'low':
        return 'text-green-400 bg-green-900/30';
      default:
        return 'text-slate-400 bg-slate-900/30';
    }
  };

  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center space-x-4">
        <button
          onClick={() => navigate('/history')}
          className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
        >
          <ArrowLeft className="w-5 h-5" />
        </button>
        <div>
          <h1 className="text-3xl font-bold text-white">Analysis Results</h1>
          <div className="flex items-center space-x-4 mt-2 text-sm text-slate-400">
            <span>File: {fileName || 'Unknown'}</span>
            {fileSize && (
              <>
                <span>•</span>
                <span>Size: {formatFileSize(fileSize)}</span>
              </>
            )}
            {fileType && (
              <>
                <span>•</span>
                <span>Type: {fileType}</span>
              </>
            )}
            {analysisDate && (
              <>
                <span>•</span>
                <span>Analyzed: {formatDate(analysisDate)}</span>
              </>
            )}
          </div>
        </div>
      </div>
      <div className="flex items-center space-x-3">
        {severity && (
          <div className={`px-3 py-1 rounded-lg text-sm font-medium ${getThreatLevelColor(severity)}`}>
            Threat Level: {severity.toUpperCase()}
          </div>
        )}
        <button 
          onClick={() => onExport && onExport('json')}
          className="flex items-center space-x-2 px-4 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors"
        >
          <Download className="w-4 h-4" />
          <span>Export</span>
        </button>
        <button className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
          <Share className="w-4 h-4" />
          <span>Share</span>
        </button>
      </div>
    </div>
  );
};

export default AnalysisHeader;