import { useEffect, useRef, useCallback } from 'react'
import * as signalR from '@microsoft/signalr'
import { useAppStore } from '../store/useAppStore'
import { useAnalysisStore } from '../store/useAnalysisStore'

const SIGNALR_URL = import.meta.env.VITE_SIGNALR_URL || 'http://localhost:5000/analysishub'

export function useSignalR() {
  const connectionRef = useRef<signalR.HubConnection | null>(null)
  const { setConnected, setSystemStatus } = useAppStore()
  const { updateAnalysis } = useAnalysisStore()

  // Initialize connection
  const connect = useCallback(async () => {
    if (connectionRef.current?.state === signalR.HubConnectionState.Connected) {
      return
    }

    const connection = new signalR.HubConnectionBuilder()
      .withUrl(SIGNALR_URL)
      .withAutomaticReconnect()
      .configureLogging(signalR.LogLevel.Information)
      .build()

    // Set up event handlers
    connection.on('ReceiveAnalysisProgress', (analysisId: string, progress: number, status: string) => {
      console.log('Progress update:', analysisId, progress, status)
      updateAnalysis(analysisId, { progress, status: status as any })
    })

    connection.on('ReceiveIOCDetected', (analysisId: string, ioc: any) => {
      console.log('IOC detected:', analysisId, ioc)
      // Update analysis IOC count
      const analysis = useAnalysisStore.getState().analyses.find(a => a.id === analysisId)
      if (analysis) {
        updateAnalysis(analysisId, { iocCount: analysis.iocCount + 1 })
      }
    })

    connection.on('ReceiveMITREMapped', (analysisId: string, mitre: any) => {
      console.log('MITRE mapped:', analysisId, mitre)
      // Update analysis MITRE count
      const analysis = useAnalysisStore.getState().analyses.find(a => a.id === analysisId)
      if (analysis) {
        updateAnalysis(analysisId, { mitreCount: analysis.mitreCount + 1 })
      }
    })

    connection.on('ReceiveAnalysisComplete', (analysisId: string, result: any) => {
      console.log('Analysis complete:', analysisId, result)
      updateAnalysis(analysisId, { 
        status: 'completed', 
        progress: 100,
        threatLevel: result.threatLevel 
      })
    })

    connection.on('ReceiveError', (message: string, errorCode: string) => {
      console.error('SignalR error:', message, errorCode)
      useAnalysisStore.getState().setError(message)
    })

    // Connection lifecycle events
    connection.onreconnecting(() => {
      console.log('SignalR reconnecting...')
      setConnected(false)
      setSystemStatus('degraded')
    })

    connection.onreconnected(() => {
      console.log('SignalR reconnected')
      setConnected(true)
      setSystemStatus('online')
    })

    connection.onclose(() => {
      console.log('SignalR disconnected')
      setConnected(false)
      setSystemStatus('offline')
    })

    try {
      await connection.start()
      console.log('SignalR connected')
      connectionRef.current = connection
      setConnected(true)
      setSystemStatus('online')
    } catch (error) {
      console.error('SignalR connection failed:', error)
      setConnected(false)
      setSystemStatus('offline')
    }
  }, [setConnected, setSystemStatus, updateAnalysis])

  // Join analysis group
  const joinAnalysisGroup = useCallback(async (analysisId: string) => {
    if (connectionRef.current?.state === signalR.HubConnectionState.Connected) {
      try {
        await connectionRef.current.invoke('JoinAnalysisGroup', analysisId)
        console.log('Joined analysis group:', analysisId)
      } catch (error) {
        console.error('Failed to join analysis group:', error)
      }
    }
  }, [])

  // Leave analysis group
  const leaveAnalysisGroup = useCallback(async (analysisId: string) => {
    if (connectionRef.current?.state === signalR.HubConnectionState.Connected) {
      try {
        await connectionRef.current.invoke('LeaveAnalysisGroup', analysisId)
        console.log('Left analysis group:', analysisId)
      } catch (error) {
        console.error('Failed to leave analysis group:', error)
      }
    }
  }, [])

  // Cleanup on unmount
  useEffect(() => {
    connect()

    return () => {
      if (connectionRef.current) {
        connectionRef.current.stop()
      }
    }
  }, [connect])

  return {
    isConnected: connectionRef.current?.state === signalR.HubConnectionState.Connected,
    joinAnalysisGroup,
    leaveAnalysisGroup,
  }
}