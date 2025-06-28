import React from 'react';
import { Shield, Search, Zap, Settings, AlertTriangle } from 'lucide-react';

interface UploadOptionsProps {
  options: {
    enableYara: boolean;
    enableSigma: boolean;
    enableAI: boolean;
    deepScan: boolean;
    extractIOCs: boolean;
  };
  onChange: (key: string, value: boolean) => void;
}

const UploadOptions: React.FC<UploadOptionsProps> = ({ options, onChange }) => {
  return (
    <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-800">
      <h3 className="text-lg font-semibold text-white mb-4">Analysis Options</h3>
      <div className="space-y-4">
        {[
          { key: 'enableYara', label: 'YARA Rules', description: 'Malware detection patterns', icon: Shield },
          { key: 'enableSigma', label: 'Sigma Rules', description: 'Log analysis rules', icon: Search },
          { key: 'enableAI', label: 'AI Analysis', description: 'Machine learning insights', icon: Zap },
          { key: 'deepScan', label: 'Deep Scan', description: 'Comprehensive analysis', icon: Settings },
          { key: 'extractIOCs', label: 'Extract IOCs', description: 'Find indicators of compromise', icon: AlertTriangle },
        ].map((option) => {
          const Icon = option.icon;
          return (
            <div key={option.key} className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <Icon className="w-4 h-4 text-slate-400" />
                <div>
                  <p className="text-sm font-medium text-white">{option.label}</p>
                  <p className="text-xs text-slate-400">{option.description}</p>
                </div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={options[option.key as keyof typeof options]}
                  onChange={(e) => onChange(option.key, e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-slate-600 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
              </label>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default UploadOptions;