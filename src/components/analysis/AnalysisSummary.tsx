import React from 'react';
import { motion } from 'framer-motion';
import { Activity, Eye, Shield, Bug, Network } from 'lucide-react';

interface AnalysisSummaryProps {
  threatScore?: number;
  iocsCount?: number;
  yaraMatchesCount?: number;
  sigmaMatchesCount?: number;
  mitreCount?: number;
}

const AnalysisSummary: React.FC<AnalysisSummaryProps> = ({
  threatScore = 0,
  iocsCount = 0,
  yaraMatchesCount = 0,
  sigmaMatchesCount = 0,
  mitreCount = 0
}) => {
  const summaryItems = [
    { 
      title: 'Threat Score', 
      value: threatScore.toString(), 
      icon: Activity, 
      color: 'text-blue-400' 
    },
    { 
      title: 'IOCs Found', 
      value: iocsCount.toString(), 
      icon: Eye, 
      color: 'text-yellow-400' 
    },
    { 
      title: 'YARA Matches', 
      value: yaraMatchesCount.toString(), 
      icon: Shield, 
      color: 'text-green-400' 
    },
    { 
      title: 'Sigma Matches', 
      value: sigmaMatchesCount.toString(), 
      icon: Bug, 
      color: 'text-purple-400' 
    },
    { 
      title: 'MITRE Techniques', 
      value: mitreCount.toString(), 
      icon: Network, 
      color: 'text-red-400' 
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
      {summaryItems.map((stat, index) => {
        const Icon = stat.icon;
        return (
          <motion.div
            key={stat.title}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
            className="bg-slate-900/50 rounded-lg p-4 border border-slate-800"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-slate-400">{stat.title}</p>
                <p className="text-xl font-bold text-white mt-1">{stat.value}</p>
              </div>
              <Icon className={`w-6 h-6 ${stat.color}`} />
            </div>
          </motion.div>
        );
      })}
    </div>
  );
};

export default AnalysisSummary;