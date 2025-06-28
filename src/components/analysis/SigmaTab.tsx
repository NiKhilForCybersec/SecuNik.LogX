import React, { useState } from 'react';
import { Bug, Search, Filter } from 'lucide-react';

interface SigmaMatch {
  rule: string;
  title?: string;
  level: string;
  matches: number;
  description?: string;
  author?: string;
  tags?: string[];
  logsource?: {
    product?: string;
    service?: string;
    category?: string;
  };
}

interface SigmaTabProps {
  matches: SigmaMatch[];
}

const SigmaTab: React.FC<SigmaTabProps> = ({ matches = [] }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [levelFilter, setLevelFilter] = useState<string>('all');

  const getLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical':
        return 'text-red-400 bg-red-900/30';
      case 'high':
        return 'text-orange-400 bg-orange-900/30';
      case 'medium':
        return 'text-yellow-400 bg-yellow-900/30';
      case 'low':
        return 'text-green-400 bg-green-900/30';
      case 'informational':
        return 'text-blue-400 bg-blue-900/30';
      default:
        return 'text-slate-400 bg-slate-900/30';
    }
  };

  const filteredMatches = matches.filter(match => {
    const matchesSearch = searchTerm === '' || 
      match.rule.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (match.title && match.title.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (match.description && match.description.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesLevel = levelFilter === 'all' || match.level.toLowerCase() === levelFilter.toLowerCase();
    
    return matchesSearch && matchesLevel;
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Sigma Rule Matches</h3>
        
        <div className="flex items-center space-x-2">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search rules..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          
          <select
            value={levelFilter}
            onChange={(e) => setLevelFilter(e.target.value)}
            className="px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="all">All Levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="informational">Informational</option>
          </select>
        </div>
      </div>
      
      {filteredMatches.length > 0 ? (
        <div className="space-y-4">
          {filteredMatches.map((match, index) => (
            <div key={index} className="bg-slate-800/50 rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-sm font-medium text-white">{match.title || match.rule}</h4>
                <span className={`px-2 py-1 text-xs rounded ${getLevelColor(match.level || 'medium')}`}>
                  {match.level?.toUpperCase() || 'MEDIUM'}
                </span>
              </div>
              {match.description && (
                <p className="text-sm text-slate-300 mb-2">{match.description}</p>
              )}
              <div className="flex items-center space-x-4 text-xs text-slate-400">
                <span>Matches: {match.matches || 1}</span>
                {match.author && <span>Author: {match.author}</span>}
                {match.logsource && (
                  <span>
                    Source: {match.logsource.product || match.logsource.service || match.logsource.category || 'Unknown'}
                  </span>
                )}
                {match.tags && match.tags.length > 0 && (
                  <div className="flex space-x-1">
                    {match.tags.slice(0, 3).map((tag, tagIndex) => (
                      <span key={tagIndex} className="px-1 py-0.5 bg-slate-700 rounded text-xs">
                        {tag}
                      </span>
                    ))}
                    {match.tags.length > 3 && (
                      <span className="px-1 py-0.5 bg-slate-700 rounded text-xs">
                        +{match.tags.length - 3}
                      </span>
                    )}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-center py-8">
          <Bug className="w-12 h-12 text-slate-400 mx-auto mb-4" />
          <p className="text-slate-400">No Sigma rule matches found</p>
        </div>
      )}
    </div>
  );
};

export default SigmaTab;