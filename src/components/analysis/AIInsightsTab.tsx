import React from 'react';
import { Zap } from 'lucide-react';

interface AIInsights {
  analysis?: string;
  key_findings?: string[];
  recommendations?: string[];
  threat_assessment?: {
    score: number;
    reasoning: string;
    confidence: number;
  };
  ioc_analysis?: {
    total_found: number;
    malicious_count: number;
    analysis: string;
  };
  mitre_analysis?: {
    techniques_identified: number;
    tactics_identified: number;
    analysis: string;
  };
}

interface AIInsightsTabProps {
  insights?: AIInsights;
}

const AIInsightsTab: React.FC<AIInsightsTabProps> = ({ insights }) => {
  if (!insights) {
    return (
      <div className="text-center py-8">
        <Zap className="w-12 h-12 text-slate-400 mx-auto mb-4" />
        <p className="text-slate-400">No AI insights available for this analysis</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h3 className="text-lg font-semibold text-white">AI-Powered Analysis</h3>
      
      {/* Main Analysis */}
      {insights.analysis && (
        <div className="bg-slate-800/50 rounded-lg p-6">
          <h4 className="text-md font-semibold text-white mb-4">Detailed Analysis</h4>
          <p className="text-slate-300 leading-relaxed">{insights.analysis}</p>
        </div>
      )}
      
      {/* Threat Assessment */}
      {insights.threat_assessment && (
        <div className="bg-slate-800/50 rounded-lg p-6">
          <h4 className="text-md font-semibold text-white mb-4">Threat Assessment</h4>
          <div className="flex items-center space-x-4 mb-4">
            <div className="w-20 h-20 rounded-full flex items-center justify-center border-4 border-blue-500">
              <span className="text-2xl font-bold text-white">{insights.threat_assessment.score}</span>
            </div>
            <div>
              <p className="text-sm text-slate-300">{insights.threat_assessment.reasoning}</p>
              <p className="text-xs text-slate-400 mt-2">
                Confidence: {Math.round(insights.threat_assessment.confidence * 100)}%
              </p>
            </div>
          </div>
        </div>
      )}
      
      {/* Key Findings & Recommendations */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {insights.key_findings && insights.key_findings.length > 0 && (
          <div className="bg-slate-800/50 rounded-lg p-6">
            <h4 className="text-md font-semibold text-white mb-4">Key Findings</h4>
            <ul className="space-y-2">
              {insights.key_findings.map((finding, index) => (
                <li key={index} className="flex items-start space-x-2">
                  <span className="text-blue-400 font-bold">•</span>
                  <span className="text-sm text-slate-300">{finding}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {insights.recommendations && insights.recommendations.length > 0 && (
          <div className="bg-slate-800/50 rounded-lg p-6">
            <h4 className="text-md font-semibold text-white mb-4">Recommendations</h4>
            <ul className="space-y-2">
              {insights.recommendations.map((rec, index) => (
                <li key={index} className="flex items-start space-x-2">
                  <span className="text-blue-400 font-bold">•</span>
                  <span className="text-sm text-slate-300">{rec}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
      
      {/* IOC Analysis */}
      {insights.ioc_analysis && (
        <div className="bg-slate-800/50 rounded-lg p-6">
          <h4 className="text-md font-semibold text-white mb-4">IOC Analysis</h4>
          <div className="flex items-center space-x-6 mb-4">
            <div className="text-center">
              <p className="text-2xl font-bold text-white">{insights.ioc_analysis.total_found}</p>
              <p className="text-xs text-slate-400">Total IOCs</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-red-400">{insights.ioc_analysis.malicious_count}</p>
              <p className="text-xs text-slate-400">Malicious</p>
            </div>
          </div>
          <p className="text-sm text-slate-300">{insights.ioc_analysis.analysis}</p>
        </div>
      )}
      
      {/* MITRE Analysis */}
      {insights.mitre_analysis && (
        <div className="bg-slate-800/50 rounded-lg p-6">
          <h4 className="text-md font-semibold text-white mb-4">MITRE ATT&CK Analysis</h4>
          <div className="flex items-center space-x-6 mb-4">
            <div className="text-center">
              <p className="text-2xl font-bold text-white">{insights.mitre_analysis.techniques_identified}</p>
              <p className="text-xs text-slate-400">Techniques</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-blue-400">{insights.mitre_analysis.tactics_identified}</p>
              <p className="text-xs text-slate-400">Tactics</p>
            </div>
          </div>
          <p className="text-sm text-slate-300">{insights.mitre_analysis.analysis}</p>
        </div>
      )}
    </div>
  );
};

export default AIInsightsTab;