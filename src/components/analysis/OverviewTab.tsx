import React from 'react';
import { CheckCircle, AlertTriangle } from 'lucide-react';

interface OverviewTabProps {
  summary?: string;
  aiInsights?: {
    analysis?: string;
    key_findings?: string[];
    recommendations?: string[];
  };
}

const OverviewTab: React.FC<OverviewTabProps> = ({ summary, aiInsights }) => {
  return (
    <div className="space-y-6">
      {/* Summary */}
      {summary && (
        <div className="bg-slate-800/50 rounded-lg p-4">
          <h3 className="text-lg font-semibold text-white mb-2">Analysis Summary</h3>
          <p className="text-slate-300">{summary}</p>
        </div>
      )}

      {/* AI Insights */}
      {aiInsights && (
        <div className="bg-slate-800/50 rounded-lg p-4">
          <h3 className="text-lg font-semibold text-white mb-4">AI Insights</h3>
          <div className="space-y-4">
            {aiInsights.analysis && (
              <div>
                <h4 className="text-sm font-medium text-blue-400 mb-2">Analysis</h4>
                <p className="text-slate-300 text-sm">{aiInsights.analysis}</p>
              </div>
            )}
            
            {aiInsights.key_findings && aiInsights.key_findings.length > 0 && (
              <div>
                <h4 className="text-sm font-medium text-blue-400 mb-2">Key Findings</h4>
                <ul className="list-disc list-inside space-y-1">
                  {aiInsights.key_findings.map((finding, index) => (
                    <li key={index} className="text-slate-300 text-sm">{finding}</li>
                  ))}
                </ul>
              </div>
            )}
            
            {aiInsights.recommendations && aiInsights.recommendations.length > 0 && (
              <div>
                <h4 className="text-sm font-medium text-blue-400 mb-2">Recommendations</h4>
                <ul className="list-disc list-inside space-y-1">
                  {aiInsights.recommendations.map((rec, index) => (
                    <li key={index} className="text-slate-300 text-sm">{rec}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Key Findings & Recommendations */}
      {aiInsights && (aiInsights.key_findings?.length || aiInsights.recommendations?.length) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {aiInsights.key_findings && aiInsights.key_findings.length > 0 && (
            <div className="bg-slate-800/50 rounded-lg p-4">
              <h4 className="text-md font-semibold text-white mb-3">Key Findings</h4>
              <ul className="space-y-2">
                {aiInsights.key_findings.map((finding, index) => (
                  <li key={index} className="flex items-start space-x-2">
                    <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                    <span className="text-sm text-slate-300">{finding}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {aiInsights.recommendations && aiInsights.recommendations.length > 0 && (
            <div className="bg-slate-800/50 rounded-lg p-4">
              <h4 className="text-md font-semibold text-white mb-3">Recommendations</h4>
              <ul className="space-y-2">
                {aiInsights.recommendations.map((rec, index) => (
                  <li key={index} className="flex items-start space-x-2">
                    <AlertTriangle className="w-4 h-4 text-yellow-400 mt-0.5 flex-shrink-0" />
                    <span className="text-sm text-slate-300">{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default OverviewTab;