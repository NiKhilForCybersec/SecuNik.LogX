const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';

interface Subscription {
  analysisId: string;
  callback: (data: any) => void;
}

class WebSocketService {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectInterval = 1000;
  private subscribers = new Map<string, Subscription>();
  private isConnecting = false;
  private messageQueue: any[] = [];
  private pingInterval: number | null = null;

  connect(): Promise<void> {
    if (this.isConnecting || (this.ws && this.ws.readyState === WebSocket.OPEN)) {
      return Promise.resolve();
    }

    this.isConnecting = true;

    return new Promise((resolve, reject) => {
      try {
        // Connect to analysis hub
        this.ws = new WebSocket(`${WS_URL}/hubs/analysis`);

        this.ws.onopen = () => {
          console.log('WebSocket connected to SecuNik LogX backend');
          this.isConnecting = false;
          this.reconnectAttempts = 0;
          
          // Send queued messages
          while (this.messageQueue.length > 0) {
            const message = this.messageQueue.shift();
            this.ws?.send(JSON.stringify(message));
          }
          
          // Start ping interval to keep connection alive
          this.startPingInterval();
          
          resolve();
        };

        this.ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            this.handleMessage(data);
          } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
          }
        };

        this.ws.onclose = (event) => {
          console.log('WebSocket disconnected:', event.code, event.reason);
          this.isConnecting = false;
          this.stopPingInterval();
          this.reconnect();
        };

        this.ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          this.isConnecting = false;
          reject(error);
        };
      } catch (error) {
        this.isConnecting = false;
        reject(error);
      }
    });
  }

  disconnect(): void {
    this.stopPingInterval();
    
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.subscribers.clear();
    this.messageQueue = [];
  }

  private reconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached');
      return;
    }

    const delay = this.reconnectInterval * Math.pow(2, this.reconnectAttempts);
    this.reconnectAttempts++;

    setTimeout(() => {
      console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
      this.connect().catch(error => {
        console.error('Reconnection failed:', error);
      });
    }, delay);
  }

  send(message: any): boolean {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
      return true;
    } else {
      // Queue message for when connection is restored
      this.messageQueue.push(message);
      
      // Try to connect if not already connecting
      if (!this.isConnecting && (!this.ws || this.ws.readyState !== WebSocket.CONNECTING)) {
        this.connect().catch(error => {
          console.error('Connection failed:', error);
        });
      }
      
      return false;
    }
  }

  // Subscribe to analysis updates
  subscribeToAnalysis(analysisId: string, callback: (data: any) => void): string {
    const subscriptionId = `analysis_${analysisId}_${Date.now()}_${Math.random()}`;
    
    this.subscribers.set(subscriptionId, {
      analysisId,
      callback
    });

    // Send subscription message if connected
    this.send({
      action: 'SubscribeToAnalysis',
      analysisId
    });

    return subscriptionId;
  }

  unsubscribe(subscriptionId: string): void {
    const subscription = this.subscribers.get(subscriptionId);
    if (subscription) {
      this.subscribers.delete(subscriptionId);
      
      // Send unsubscribe message if connected
      this.send({
        action: 'UnsubscribeFromAnalysis',
        analysisId: subscription.analysisId
      });
    }
  }

  private handleMessage(data: any): void {
    // Handle different message types
    if (data.AnalysisId) {
      this.notifyAnalysisSubscribers(data.AnalysisId, data);
    } else if (data.analysisId) {
      this.notifyAnalysisSubscribers(data.analysisId, data);
    }
    
    // Handle specific message types
    switch (data.type) {
      case 'SubscriptionConfirmed':
        console.log('Subscription confirmed:', data);
        break;
        
      case 'UnsubscriptionConfirmed':
        console.log('Unsubscription confirmed:', data);
        break;
        
      case 'Pong':
        // Handle ping/pong for connection health
        break;
        
      case 'Error':
        console.error('WebSocket error:', data);
        break;
        
      default:
        // Other message types are handled by subscribers
        break;
    }
  }

  private notifyAnalysisSubscribers(analysisId: string, data: any): void {
    this.subscribers.forEach((subscription) => {
      if (subscription.analysisId === analysisId) {
        try {
          subscription.callback(data);
        } catch (error) {
          console.error('Error in WebSocket callback:', error);
        }
      }
    });
  }

  private startPingInterval(): void {
    this.stopPingInterval();
    
    // Send ping every 30 seconds to keep connection alive
    this.pingInterval = window.setInterval(() => {
      this.ping();
    }, 30000);
  }

  private stopPingInterval(): void {
    if (this.pingInterval !== null) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }

  // Health check
  ping(): boolean {
    return this.send({ action: 'Ping' });
  }

  // Get connection status
  getStatus(): string {
    if (!this.ws) return 'disconnected';
    
    switch (this.ws.readyState) {
      case WebSocket.CONNECTING:
        return 'connecting';
      case WebSocket.OPEN:
        return 'connected';
      case WebSocket.CLOSING:
        return 'closing';
      case WebSocket.CLOSED:
        return 'disconnected';
      default:
        return 'unknown';
    }
  }
}

// Create singleton instance
const websocketService = new WebSocketService();

export default websocketService;