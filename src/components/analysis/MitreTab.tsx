import React, { useState } from 'react';
import { Network, Search, Filter } from 'lucide-react';

interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  confidence: number;
  description?: string;
  evidence?: string[];
  sub_techniques?: {
    id: string;
    name: string;
    confidence: number;
  }[];
}

interface MitreTabProps {
  techniques: MitreTechnique[];
}

const MitreTab: React.FC<MitreTabProps> = ({ techniques = [] }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [tacticFilter, setTacticFilter] = useState<string>('all');

  const filteredTechniques = techniques.filter(technique => {
    const matchesSearch = searchTerm === '' || 
      technique.technique_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      technique.technique_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (technique.description && technique.description.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesTactic = tacticFilter === 'all' || technique.tactic.toLowerCase() === tacticFilter.toLowerCase();
    
    return matchesSearch && matchesTactic;
  });

  // Get unique tactics for filter
  const tactics = ['all', ...Array.from(new Set(techniques.map(t => t.tactic.toLowerCase())))];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">MITRE ATT&CK Techniques</h3>
        
        <div className="flex items-center space-x-2">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search techniques..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          
          <select
            value={tacticFilter}
            onChange={(e) => setTacticFilter(e.target.value)}
            className="px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="all">All Tactics</option>
            {tactics.filter(t => t !== 'all').map(tactic => (
              <option key={tactic} value={tactic}>
                {tactic.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}
              </option>
            ))}
          </select>
        </div>
      </div>
      
      {filteredTechniques.length > 0 ? (
        <div className="space-y-4">
          {filteredTechniques.map((technique, index) => (
            <div key={index} className="bg-slate-800/50 rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-sm font-medium text-white">
                  {technique.technique_id}: {technique.technique_name}
                </h4>
                <div className="flex items-center space-x-2">
                  <span className="text-xs text-slate-400">
                    Confidence: {Math.round(technique.confidence * 100)}%
                  </span>
                  <span className="px-2 py-1 bg-blue-900/30 text-blue-300 text-xs rounded">
                    {technique.tactic.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}
                  </span>
                </div>
              </div>
              
              {technique.description && (
                <p className="text-sm text-slate-300 mb-2">{technique.description}</p>
              )}
              
              {technique.evidence && technique.evidence.length > 0 && (
                <div className="mt-2">
                  <h5 className="text-xs font-medium text-slate-400 mb-1">Evidence:</h5>
                  <ul className="list-disc list-inside text-xs text-slate-300 space-y-1">
                    {technique.evidence.map((item, i) => (
                      <li key={i}>{item}</li>
                    ))}
                  </ul>
                </div>
              )}
              
              {technique.sub_techniques && technique.sub_techniques.length > 0 && (
                <div className="mt-3 pl-4 border-l border-slate-700">
                  <h5 className="text-xs font-medium text-slate-400 mb-2">Sub-techniques:</h5>
                  <div className="space-y-2">
                    {technique.sub_techniques.map((sub, i) => (
                      <div key={i} className="flex items-center justify-between">
                        <span className="text-xs text-slate-300">{sub.id}: {sub.name}</span>
                        <span className="text-xs text-slate-400">
                          Confidence: {Math.round(sub.confidence * 100)}%
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <div className="text-center py-8">
          <Network className="w-12 h-12 text-slate-400 mx-auto mb-4" />
          <p className="text-slate-400">No MITRE ATT&CK techniques identified</p>
        </div>
      )}
    </div>
  );
};

export default MitreTab;