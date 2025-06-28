import { useState, useCallback, useEffect } from 'react';
import { analysisService } from '../services/analysisService';
import { useWebSocket } from './useWebSocket';
import toast from 'react-hot-toast';

export interface Analysis {
  id: string;
  status: string;
  progress: number;
  fileName: string;
  fileHash: string;
  fileSize?: number;
  fileType?: string;
  threatScore?: number;
  severity?: string;
  startTime?: string;
  completionTime?: string;
  duration?: string;
  results?: any;
  error?: string;
  iocs?: any[];
  ruleMatches?: any[];
  timeline?: any[];
  mitreResults?: any;
  aiInsights?: any;
  tags?: string[];
  notes?: string;
}

export const useAnalysis = () => {
  const [analyses, setAnalyses] = useState<Map<string, Analysis>>(new Map());
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<Error | null>(null);
  const { subscribe, unsubscribe } = useWebSocket();

  const startAnalysis = useCallback(async (uploadId: string, options = {}) => {
    setLoading(true);
    setError(null);

    try {
      const result = await analysisService.startAnalysis(uploadId, options);
      
      setAnalyses(prev => {
        const newMap = new Map(prev);
        newMap.set(result.analysis_id, {
          id: result.analysis_id,
          status: 'started',
          progress: 0,
          fileName: result.file_name || '',
          fileHash: result.file_hash || '',
          fileSize: result.file_size,
          fileType: result.file_type,
          results: null
        });
        return newMap;
      });

      toast.success('Analysis started successfully');
      return result;
    } catch (error: any) {
      setError(error);
      toast.error(error.message || 'Failed to start analysis');
      throw error;
    } finally {
      setLoading(false);
    }
  }, []);

  const getAnalysisStatus = useCallback(async (analysisId: string) => {
    try {
      const status = await analysisService.getAnalysisStatus(analysisId);
      
      setAnalyses(prev => {
        const newMap = new Map(prev);
        const existing = newMap.get(analysisId);
        if (existing) {
          newMap.set(analysisId, { 
            ...existing, 
            status: status.status,
            progress: status.progress || existing.progress,
            threatScore: status.threat_score,
            severity: status.severity,
            startTime: status.start_time,
            completionTime: status.completion_time,
            error: status.error_message
          });
        }
        return newMap;
      });

      return status;
    } catch (error) {
      console.error('Failed to get analysis status:', error);
      throw error;
    }
  }, []);

  const getAnalysisResults = useCallback(async (analysisId: string) => {
    try {
      const results = await analysisService.getAnalysisResults(analysisId);
      
      setAnalyses(prev => {
        const newMap = new Map(prev);
        const existing = newMap.get(analysisId);
        if (existing) {
          newMap.set(analysisId, { 
            ...existing, 
            results,
            status: 'completed',
            progress: 100,
            threatScore: results.threat_score,
            severity: results.severity,
            iocs: results.iocs,
            ruleMatches: results.rule_matches,
            timeline: results.timeline,
            mitreResults: results.mitre_results,
            aiInsights: results.ai_insights,
            tags: results.tags,
            notes: results.notes
          });
        } else {
          // If analysis doesn't exist in state yet, create it
          newMap.set(analysisId, {
            id: analysisId,
            status: 'completed',
            progress: 100,
            fileName: results.file_name || '',
            fileHash: results.file_hash || '',
            fileSize: results.file_size,
            fileType: results.file_type,
            threatScore: results.threat_score,
            severity: results.severity,
            startTime: results.start_time,
            completionTime: results.completion_time,
            results,
            iocs: results.iocs,
            ruleMatches: results.rule_matches,
            timeline: results.timeline,
            mitreResults: results.mitre_results,
            aiInsights: results.ai_insights,
            tags: results.tags,
            notes: results.notes
          });
        }
        return newMap;
      });

      return results;
    } catch (error) {
      console.error('Failed to get analysis results:', error);
      throw error;
    }
  }, []);

  const cancelAnalysis = useCallback(async (analysisId: string) => {
    try {
      await analysisService.cancelAnalysis(analysisId);
      
      setAnalyses(prev => {
        const newMap = new Map(prev);
        const existing = newMap.get(analysisId);
        if (existing) {
          newMap.set(analysisId, { ...existing, status: 'cancelled' });
        }
        return newMap;
      });

      toast.success('Analysis cancelled');
    } catch (error: any) {
      toast.error(error.message || 'Failed to cancel analysis');
      throw error;
    }
  }, []);

  const updateAnalysisFromWebSocket = useCallback((data: any) => {
    const analysisId = data.AnalysisId || data.analysisId;
    if (!analysisId) return;

    setAnalyses(prev => {
      const newMap = new Map(prev);
      const existing = newMap.get(analysisId);
      
      if (existing) {
        const updatedAnalysis = { ...existing };
        
        // Handle different message types
        if (data.type === 'AnalysisProgress') {
          updatedAnalysis.status = 'analyzing';
          updatedAnalysis.progress = data.Progress || data.progress || existing.progress;
        } 
        else if (data.type === 'AnalysisCompleted') {
          updatedAnalysis.status = 'completed';
          updatedAnalysis.progress = 100;
          updatedAnalysis.results = data.Results || data.results;
          updatedAnalysis.completionTime = new Date().toISOString();
          toast.success('Analysis completed successfully');
        } 
        else if (data.type === 'AnalysisError') {
          updatedAnalysis.status = 'failed';
          updatedAnalysis.error = data.Error || data.error;
          toast.error(`Analysis failed: ${data.Error || data.error || 'Unknown error'}`);
        }
        else if (data.type === 'ThreatAlert') {
          if (!updatedAnalysis.ruleMatches) {
            updatedAnalysis.ruleMatches = [];
          }
          updatedAnalysis.ruleMatches.push(data.Threat || data.threat);
          toast.warning(`Threat detected: ${(data.Threat || data.threat)?.ruleName || 'Unknown threat'}`);
        }
        else if (data.type === 'IOCFound') {
          if (!updatedAnalysis.iocs) {
            updatedAnalysis.iocs = [];
          }
          updatedAnalysis.iocs.push(data.IOC || data.ioc);
        }
        
        newMap.set(analysisId, updatedAnalysis);
      } else {
        // If we get an update for an analysis not in state, fetch it
        getAnalysisStatus(analysisId).catch(err => 
          console.error(`Failed to get status for analysis ${analysisId}:`, err)
        );
      }
      
      return newMap;
    });
  }, [getAnalysisStatus]);

  return {
    analyses,
    loading,
    error,
    startAnalysis,
    getAnalysisStatus,
    getAnalysisResults,
    cancelAnalysis,
    updateAnalysisFromWebSocket
  };
};

export const useAnalysisById = (analysisId?: string) => {
  const { analyses, updateAnalysisFromWebSocket, getAnalysisResults } = useAnalysis();
  const { subscribe, unsubscribe } = useWebSocket();
  const [subscriptionId, setSubscriptionId] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  
  useEffect(() => {
    if (!analysisId) return;
    
    // Load analysis results if not already loaded
    const analysis = analyses.get(analysisId);
    if (!analysis || (!analysis.results && analysis.status === 'completed')) {
      setLoading(true);
      getAnalysisResults(analysisId)
        .catch(error => console.error('Failed to load analysis results:', error))
        .finally(() => setLoading(false));
    }
    
    // Subscribe to real-time updates
    const subId = subscribe(analysisId, updateAnalysisFromWebSocket);
    setSubscriptionId(subId);
    
    return () => {
      if (subId) {
        unsubscribe(subId);
      }
    };
  }, [analysisId, analyses, getAnalysisResults, subscribe, unsubscribe, updateAnalysisFromWebSocket]);
  
  return { 
    analysis: analysisId ? analyses.get(analysisId) : null,
    loading
  };
};