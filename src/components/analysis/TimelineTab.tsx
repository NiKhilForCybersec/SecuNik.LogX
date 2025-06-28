import React, { useState } from 'react';
import { Clock, Search, Filter, Calendar } from 'lucide-react';
import { formatDate } from '../../utils/formatters';

interface TimelineEvent {
  timestamp: string;
  event: string;
  severity: string;
  source?: string;
  details?: Record<string, any>;
  lineNumber?: number;
}

interface TimelineTabProps {
  events: TimelineEvent[];
}

const TimelineTab: React.FC<TimelineTabProps> = ({ events = [] }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [sourceFilter, setSourceFilter] = useState<string>('all');

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-red-400';
      case 'high':
        return 'bg-orange-400';
      case 'medium':
        return 'bg-yellow-400';
      case 'low':
        return 'bg-green-400';
      default:
        return 'bg-slate-400';
    }
  };

  const filteredEvents = events.filter(event => {
    const matchesSearch = searchTerm === '' || 
      event.event.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (event.details && JSON.stringify(event.details).toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesSeverity = severityFilter === 'all' || event.severity.toLowerCase() === severityFilter.toLowerCase();
    const matchesSource = sourceFilter === 'all' || event.source === sourceFilter;
    
    return matchesSearch && matchesSeverity && matchesSource;
  });

  // Get unique sources for filter
  const sources = ['all', ...Array.from(new Set(events.filter(e => e.source).map(e => e.source as string)))];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Event Timeline</h3>
        
        <div className="flex items-center space-x-2">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search events..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          
          {sources.length > 1 && (
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Sources</option>
              {sources.filter(s => s !== 'all').map(source => (
                <option key={source} value={source}>{source}</option>
              ))}
            </select>
          )}
        </div>
      </div>
      
      {filteredEvents.length > 0 ? (
        <div className="space-y-4">
          {filteredEvents.map((event, index) => (
            <div key={index} className="flex items-start space-x-4 p-4 bg-slate-800/50 rounded-lg">
              <div className={`w-3 h-3 rounded-full mt-2 ${getSeverityColor(event.severity)}`}></div>
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-medium text-white">{event.event}</p>
                  <span className={`px-2 py-1 text-xs rounded ${
                    event.severity === 'critical' ? 'text-red-400 bg-red-900/30' :
                    event.severity === 'high' ? 'text-orange-400 bg-orange-900/30' :
                    event.severity === 'medium' ? 'text-yellow-400 bg-yellow-900/30' : 
                    'text-green-400 bg-green-900/30'
                  }`}>
                    {event.severity.toUpperCase()}
                  </span>
                </div>
                <div className="flex items-center space-x-4 mt-1">
                  <p className="text-xs text-slate-400 flex items-center">
                    <Calendar className="w-3 h-3 mr-1" />
                    {formatDate(event.timestamp)}
                  </p>
                  {event.source && (
                    <p className="text-xs text-slate-400">
                      Source: {event.source}
                    </p>
                  )}
                  {event.lineNumber && (
                    <p className="text-xs text-slate-400">
                      Line: {event.lineNumber}
                    </p>
                  )}
                </div>
                
                {event.details && Object.keys(event.details).length > 0 && (
                  <div className="mt-2 text-xs text-slate-400">
                    <details className="cursor-pointer">
                      <summary className="text-blue-400 hover:text-blue-300">Show Details</summary>
                      <div className="mt-2 p-2 bg-slate-900 rounded-md overflow-x-auto">
                        <pre className="text-slate-300">
                          {JSON.stringify(event.details, null, 2)}
                        </pre>
                      </div>
                    </details>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-center py-8">
          <Clock className="w-12 h-12 text-slate-400 mx-auto mb-4" />
          <p className="text-slate-400">No timeline events found</p>
        </div>
      )}
    </div>
  );
};

export default TimelineTab;