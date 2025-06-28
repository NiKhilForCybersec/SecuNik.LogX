import { useEffect, useRef, useCallback, useState } from 'react';
import websocketService from '../services/websocketService';

export const useWebSocket = () => {
  const [status, setStatus] = useState<string>('disconnected');
  const statusCheckInterval = useRef<number | null>(null);

  useEffect(() => {
    // Connect to WebSocket
    websocketService.connect().catch(error => {
      console.error('Failed to connect to WebSocket:', error);
    });

    // Set up status check interval
    statusCheckInterval.current = window.setInterval(() => {
      setStatus(websocketService.getStatus());
    }, 5000);

    // Check status immediately
    setStatus(websocketService.getStatus());

    return () => {
      // Clean up on unmount
      if (statusCheckInterval.current) {
        clearInterval(statusCheckInterval.current);
      }
    };
  }, []);

  const subscribe = useCallback((analysisId: string, callback: (data: any) => void) => {
    return websocketService.subscribeToAnalysis(analysisId, callback);
  }, []);

  const unsubscribe = useCallback((subscriptionId: string) => {
    websocketService.unsubscribe(subscriptionId);
  }, []);

  const send = useCallback((message: any) => {
    return websocketService.send(message);
  }, []);

  const getStatus = useCallback(() => {
    return websocketService.getStatus();
  }, []);

  return {
    status,
    subscribe,
    unsubscribe,
    send,
    getStatus
  };
};

export const useAnalysisUpdates = (analysisId: string | undefined, onUpdate: (data: any) => void) => {
  const { subscribe, unsubscribe } = useWebSocket();
  const subscriptionIdRef = useRef<string | null>(null);

  useEffect(() => {
    if (!analysisId || !onUpdate) return;

    // Clean up previous subscription if exists
    if (subscriptionIdRef.current) {
      unsubscribe(subscriptionIdRef.current);
      subscriptionIdRef.current = null;
    }

    // Create new subscription
    subscriptionIdRef.current = subscribe(analysisId, onUpdate);

    return () => {
      if (subscriptionIdRef.current) {
        unsubscribe(subscriptionIdRef.current);
        subscriptionIdRef.current = null;
      }
    };
  }, [analysisId, onUpdate, subscribe, unsubscribe]);
};

export const useConnectionStatus = () => {
  const { status } = useWebSocket();
  return status;
};