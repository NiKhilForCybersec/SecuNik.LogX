import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import FileUploader, { UploadedFile } from '../components/upload/FileUploader';
import UploadOptions from '../components/upload/UploadOptions';
import ParserSelector from '../components/upload/ParserSelector';
import { uploadService } from '../services/uploadService';
import toast from 'react-hot-toast';

const UploadAnalyze: React.FC = () => {
  const navigate = useNavigate();
  const [selectedParserId, setSelectedParserId] = useState('auto');
  const [analysisOptions, setAnalysisOptions] = useState({
    enableYara: true,
    enableSigma: true,
    enableAI: false,
    deepScan: false,
    extractIOCs: true
  });
  const [supportedFormats, setSupportedFormats] = useState<any>(null);

  useEffect(() => {
    loadSupportedFormats();
  }, []);

  const loadSupportedFormats = async () => {
    try {
      const formats = await uploadService.getSupportedFileTypes();
      setSupportedFormats(formats);
    } catch (error) {
      console.error('Failed to load supported formats:', error);
    }
  };

  const handleOptionChange = (key: string, value: boolean) => {
    setAnalysisOptions(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const handleAnalysisStarted = (analysisId: string) => {
    toast.success('Analysis started successfully!');
    // Optionally navigate to analysis page
    // navigate(`/analysis/${analysisId}`);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white">Upload & Analyze</h1>
        <p className="text-slate-400 mt-2">
          Upload files for comprehensive cybersecurity analysis using SecuNik LogX
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Upload Area */}
        <div className="lg:col-span-2 space-y-6">
          <FileUploader
            onAnalysisStarted={handleAnalysisStarted}
            autoAnalyze={true}
            maxFiles={5}
            maxSize={1073741824} // 1GB
          />

          {/* Supported Formats */}
          {supportedFormats && (
            <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-800">
              <h3 className="text-lg font-semibold text-white mb-4">Supported File Formats</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {Object.entries(supportedFormats.categories || {}).map(([category, formats]: [string, any]) => (
                  <div key={category} className="space-y-2">
                    <h4 className="text-sm font-medium text-blue-400">{category}</h4>
                    <div className="flex flex-wrap gap-1">
                      {formats.map((format: string) => (
                        <span
                          key={format}
                          className="px-2 py-1 bg-slate-800 text-slate-300 text-xs rounded"
                        >
                          {format}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Configuration Panel */}
        <div className="space-y-6">
          {/* Parser Selection */}
          <ParserSelector
            selectedParserId={selectedParserId}
            onParserChange={setSelectedParserId}
          />

          {/* Analysis Options */}
          <UploadOptions
            options={analysisOptions}
            onChange={handleOptionChange}
          />

          {/* Upload Guidelines */}
          <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-800">
            <h3 className="text-lg font-semibold text-white mb-4">Upload Guidelines</h3>
            <div className="space-y-4">
              <div>
                <h4 className="text-sm font-medium text-blue-400 mb-2">File Requirements</h4>
                <ul className="text-sm text-slate-400 space-y-1">
                  <li>• Maximum file size: 1GB</li>
                  <li>• Multiple files supported</li>
                  <li>• Compressed archives will be extracted</li>
                  <li>• Binary files will be analyzed for malware</li>
                </ul>
              </div>
              <div>
                <h4 className="text-sm font-medium text-blue-400 mb-2">Analysis Features</h4>
                <ul className="text-sm text-slate-400 space-y-1">
                  <li>• YARA rule matching</li>
                  <li>• Sigma rule detection</li>
                  <li>• MITRE ATT&CK mapping</li>
                  <li>• AI-powered analysis</li>
                  <li>• IOC extraction</li>
                  <li>• VirusTotal integration</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UploadAnalyze;