import React from 'react';
import { Activity, Clock, AlertTriangle, Shield, Bug, Network, Zap } from 'lucide-react';

interface AnalysisTabsProps {
  activeTab: string;
  onTabChange: (tabId: string) => void;
}

const AnalysisTabs: React.FC<AnalysisTabsProps> = ({ activeTab, onTabChange }) => {
  const tabs = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'timeline', label: 'Timeline', icon: Clock },
    { id: 'iocs', label: 'IOCs & Threats', icon: AlertTriangle },
    { id: 'yara', label: 'YARA Results', icon: Shield },
    { id: 'sigma', label: 'Sigma Results', icon: Bug },
    { id: 'mitre', label: 'MITRE ATT&CK', icon: Network },
    { id: 'ai', label: 'AI Insights', icon: Zap },
  ];

  return (
    <div className="border-b border-slate-700">
      <nav className="flex space-x-8 px-6 overflow-x-auto">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              className={`flex items-center space-x-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors whitespace-nowrap ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-slate-400 hover:text-slate-300'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </nav>
    </div>
  );
};

export default AnalysisTabs;