import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { FileText, AlertTriangle } from 'lucide-react';
import { analysisService } from '../services/analysisService';
import { useAnalysisById } from '../hooks/useAnalysis';
import toast from 'react-hot-toast';

// Analysis components
import AnalysisHeader from '../components/analysis/AnalysisHeader';
import AnalysisSummary from '../components/analysis/AnalysisSummary';
import AnalysisTabs from '../components/analysis/AnalysisTabs';
import OverviewTab from '../components/analysis/OverviewTab';
import IOCsTab from '../components/analysis/IOCsTab';
import YaraTab from '../components/analysis/YaraTab';
import SigmaTab from '../components/analysis/SigmaTab';
import MitreTab from '../components/analysis/MitreTab';
import TimelineTab from '../components/analysis/TimelineTab';
import AIInsightsTab from '../components/analysis/AIInsightsTab';

const AnalysisResults: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('overview');
  const { analysis, loading } = useAnalysisById(id);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (id && !analysis && !loading) {
      loadAnalysisData(id);
    }
  }, [id, analysis, loading]);

  const loadAnalysisData = async (analysisId: string) => {
    try {
      await analysisService.getAnalysisResults(analysisId);
    } catch (error: any) {
      console.error('Failed to load analysis data:', error);
      setError(error.message || 'Failed to load analysis data');
      toast.error('Failed to load analysis data');
    }
  };

  const exportAnalysis = async (format: string) => {
    if (!id) return;
    
    try {
      const data = await analysisService.exportAnalysis(id, format);
      
      // Create download link
      const blob = new Blob([JSON.stringify(data, null, 2)], { 
        type: format === 'json' ? 'application/json' : 'text/csv' 
      });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `analysis_${id}.${format}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      
      toast.success(`Analysis exported as ${format.toUpperCase()}`);
    } catch (error: any) {
      console.error('Export failed:', error);
      toast.error('Failed to export analysis');
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-slate-300 mb-2">Analysis Error</h3>
        <p className="text-slate-400 mb-4">{error}</p>
        <button
          onClick={() => navigate('/history')}
          className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors mx-auto"
        >
          <span>Back to History</span>
        </button>
      </div>
    );
  }

  if (!analysis) {
    return (
      <div className="text-center py-12">
        <FileText className="w-12 h-12 text-slate-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-slate-300 mb-2">Analysis not found</h3>
        <p className="text-slate-400">The requested analysis could not be found.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <AnalysisHeader
        analysisId={analysis.id}
        fileName={analysis.fileName}
        fileSize={analysis.fileSize}
        fileType={analysis.fileType}
        analysisDate={analysis.startTime}
        severity={analysis.severity}
        onExport={exportAnalysis}
      />

      {/* Summary Cards */}
      <AnalysisSummary
        threatScore={analysis.threatScore}
        iocsCount={analysis.iocs?.length || 0}
        yaraMatchesCount={analysis.ruleMatches?.filter(m => m.ruleType === 'yara')?.length || 0}
        sigmaMatchesCount={analysis.ruleMatches?.filter(m => m.ruleType === 'sigma')?.length || 0}
        mitreCount={analysis.mitreResults?.techniques?.length || 0}
      />

      {/* Tabs */}
      <div className="bg-slate-900/50 rounded-lg border border-slate-800">
        <AnalysisTabs activeTab={activeTab} onTabChange={setActiveTab} />

        <div className="p-6">
          {/* Overview Tab */}
          {activeTab === 'overview' && (
            <OverviewTab 
              summary={analysis.results?.summary} 
              aiInsights={analysis.results?.ai_insights} 
            />
          )}

          {/* IOCs Tab */}
          {activeTab === 'iocs' && (
            <IOCsTab iocs={analysis.results?.iocs || []} />
          )}

          {/* YARA Results Tab */}
          {activeTab === 'yara' && (
            <YaraTab matches={analysis.results?.yara_results || []} />
          )}

          {/* Sigma Results Tab */}
          {activeTab === 'sigma' && (
            <SigmaTab matches={analysis.results?.sigma_results || []} />
          )}

          {/* MITRE ATT&CK Tab */}
          {activeTab === 'mitre' && (
            <MitreTab techniques={analysis.results?.mitre_results?.techniques || []} />
          )}

          {/* Timeline Tab */}
          {activeTab === 'timeline' && (
            <TimelineTab events={analysis.results?.timeline || []} />
          )}

          {/* AI Insights Tab */}
          {activeTab === 'ai' && (
            <AIInsightsTab insights={analysis.results?.ai_insights} />
          )}
        </div>
      </div>
    </div>
  );
};

export default AnalysisResults;