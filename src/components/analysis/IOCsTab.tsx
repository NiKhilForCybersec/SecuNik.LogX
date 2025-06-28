import React, { useState } from 'react';
import { Eye, Globe, Hash, FileText, Mail, Database, Search } from 'lucide-react';

interface IOC {
  type: string;
  value: string;
  context?: string;
  confidence?: number;
  source?: string;
  isMalicious?: boolean;
  threatScore?: number;
  firstSeen?: string;
  lastSeen?: string;
}

interface IOCsTabProps {
  iocs: IOC[];
}

const IOCsTab: React.FC<IOCsTabProps> = ({ iocs = [] }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');

  const getIOCIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'ip':
      case 'ip_address':
        return <Globe className="w-4 h-4" />;
      case 'hash':
      case 'file_hash':
        return <Hash className="w-4 h-4" />;
      case 'domain':
      case 'url':
        return <Globe className="w-4 h-4" />;
      case 'email':
        return <Mail className="w-4 h-4" />;
      case 'file_path':
      case 'registry_key':
        return <FileText className="w-4 h-4" />;
      case 'mutex':
        return <Database className="w-4 h-4" />;
      default:
        return <Eye className="w-4 h-4" />;
    }
  };

  const filteredIOCs = iocs.filter(ioc => {
    const matchesSearch = searchTerm === '' || 
      ioc.value.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (ioc.context && ioc.context.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesType = typeFilter === 'all' || ioc.type.toLowerCase() === typeFilter.toLowerCase();
    
    return matchesSearch && matchesType;
  });

  // Get unique IOC types for filter
  const iocTypes = ['all', ...Array.from(new Set(iocs.map(ioc => ioc.type.toLowerCase())))];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Indicators of Compromise (IOCs)</h3>
        
        <div className="flex items-center space-x-2">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search IOCs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            {iocTypes.map(type => (
              <option key={type} value={type}>
                {type === 'all' ? 'All Types' : type.charAt(0).toUpperCase() + type.slice(1)}
              </option>
            ))}
          </select>
        </div>
      </div>

      {filteredIOCs.length > 0 ? (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-700">
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                  Type
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                  Value
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                  Context
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                  Confidence
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                  Status
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {filteredIOCs.map((ioc, index) => (
                <tr key={index} className="hover:bg-slate-800/50 transition-colors">
                  <td className="px-4 py-4">
                    <span className="px-2 py-1 bg-blue-900/30 text-blue-300 text-xs rounded flex items-center space-x-1">
                      {getIOCIcon(ioc.type)}
                      <span>{ioc.type.toUpperCase()}</span>
                    </span>
                  </td>
                  <td className="px-4 py-4">
                    <span className="text-sm text-white font-mono">{ioc.value}</span>
                  </td>
                  <td className="px-4 py-4">
                    <span className="text-sm text-slate-300">{ioc.context || 'N/A'}</span>
                  </td>
                  <td className="px-4 py-4">
                    <span className="text-sm text-slate-300">{ioc.confidence ? `${ioc.confidence}%` : 'N/A'}</span>
                  </td>
                  <td className="px-4 py-4">
                    {ioc.isMalicious ? (
                      <span className="px-2 py-1 bg-red-900/30 text-red-300 text-xs rounded">Malicious</span>
                    ) : (
                      <span className="px-2 py-1 bg-slate-800 text-slate-300 text-xs rounded">Unknown</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="text-center py-8">
          <Eye className="w-12 h-12 text-slate-400 mx-auto mb-4" />
          <p className="text-slate-400">No IOCs found in this analysis</p>
        </div>
      )}
    </div>
  );
};

export default IOCsTab;