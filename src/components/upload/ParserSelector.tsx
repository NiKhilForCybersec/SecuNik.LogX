import React, { useState, useEffect } from 'react';
import { parserService } from '../../services/parserService';
import toast from 'react-hot-toast';

interface Parser {
  id: string;
  name: string;
  description: string;
  type: string;
  supportedExtensions: string[];
}

interface ParserSelectorProps {
  selectedParserId: string;
  onParserChange: (parserId: string) => void;
}

const ParserSelector: React.FC<ParserSelectorProps> = ({ selectedParserId, onParserChange }) => {
  const [parsers, setParsers] = useState<Parser[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadParsers();
  }, []);

  const loadParsers = async () => {
    try {
      setLoading(true);
      const response = await parserService.getParsers({ enabled: true });
      
      // Add auto-detect option
      const parsersWithAuto = [
        {
          id: 'auto',
          name: 'Auto-detect',
          description: 'Automatically select best parser',
          type: 'system',
          supportedExtensions: []
        },
        ...response
      ];
      
      setParsers(parsersWithAuto);
    } catch (error: any) {
      console.error('Failed to load parsers:', error);
      toast.error('Failed to load parsers');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-800">
        <h3 className="text-lg font-semibold text-white mb-4">Parser Selection</h3>
        <div className="flex items-center justify-center py-4">
          <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-800">
      <h3 className="text-lg font-semibold text-white mb-4">Parser Selection</h3>
      <div className="space-y-3">
        {parsers.map((parser) => (
          <label key={parser.id} className="flex items-start space-x-3 cursor-pointer">
            <input
              type="radio"
              name="parser"
              value={parser.id}
              checked={selectedParserId === parser.id}
              onChange={() => onParserChange(parser.id)}
              className="mt-1 text-blue-600 focus:ring-blue-500"
            />
            <div>
              <p className="text-sm font-medium text-white">{parser.name}</p>
              <p className="text-xs text-slate-400">{parser.description}</p>
              {parser.supportedExtensions.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-1">
                  {parser.supportedExtensions.slice(0, 3).map((ext) => (
                    <span key={ext} className="text-xs px-1.5 py-0.5 bg-slate-800 rounded text-slate-400">
                      {ext}
                    </span>
                  ))}
                  {parser.supportedExtensions.length > 3 && (
                    <span className="text-xs px-1.5 py-0.5 bg-slate-800 rounded text-slate-400">
                      +{parser.supportedExtensions.length - 3}
                    </span>
                  )}
                </div>
              )}
            </div>
          </label>
        ))}
      </div>
    </div>
  );
};

export default ParserSelector;