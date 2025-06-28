using Microsoft.AspNetCore.SignalR;
using System.Collections.Concurrent;

namespace SecuNik.LogX.Api.Hubs
{
    public class AnalysisHub : Hub
    {
        private static readonly ConcurrentDictionary<string, HashSet<string>> _analysisSubscriptions = new();
        private static readonly ConcurrentDictionary<string, string> _connectionAnalysis = new();
        private readonly ILogger<AnalysisHub> _logger;
        
        public AnalysisHub(ILogger<AnalysisHub> logger)
        {
            _logger = logger;
        }
        
        /// <summary>
        /// Subscribe to analysis updates for a specific analysis ID
        /// </summary>
        /// <param name="analysisId">The analysis ID to subscribe to</param>
        public async Task SubscribeToAnalysis(string analysisId)
        {
            try
            {
                if (string.IsNullOrEmpty(analysisId))
                {
                    await Clients.Caller.SendAsync("Error", "Analysis ID is required");
                    return;
                }
                
                var connectionId = Context.ConnectionId;
                
                // Add to analysis group
                await Groups.AddToGroupAsync(connectionId, $"analysis_{analysisId}");
                
                // Track subscription
                _analysisSubscriptions.AddOrUpdate(
                    analysisId,
                    new HashSet<string> { connectionId },
                    (key, existing) =>
                    {
                        existing.Add(connectionId);
                        return existing;
                    });
                
                // Track connection to analysis mapping
                _connectionAnalysis[connectionId] = analysisId;
                
                _logger.LogInformation("Connection {ConnectionId} subscribed to analysis {AnalysisId}", 
                    connectionId, analysisId);
                
                await Clients.Caller.SendAsync("SubscriptionConfirmed", new
                {
                    AnalysisId = analysisId,
                    Message = "Successfully subscribed to analysis updates"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error subscribing to analysis {AnalysisId}", analysisId);
                await Clients.Caller.SendAsync("Error", "Failed to subscribe to analysis updates");
            }
        }
        
        /// <summary>
        /// Unsubscribe from analysis updates
        /// </summary>
        /// <param name="analysisId">The analysis ID to unsubscribe from</param>
        public async Task UnsubscribeFromAnalysis(string analysisId)
        {
            try
            {
                if (string.IsNullOrEmpty(analysisId))
                {
                    await Clients.Caller.SendAsync("Error", "Analysis ID is required");
                    return;
                }
                
                var connectionId = Context.ConnectionId;
                
                // Remove from analysis group
                await Groups.RemoveFromGroupAsync(connectionId, $"analysis_{analysisId}");
                
                // Remove from subscription tracking
                if (_analysisSubscriptions.TryGetValue(analysisId, out var connections))
                {
                    connections.Remove(connectionId);
                    if (connections.Count == 0)
                    {
                        _analysisSubscriptions.TryRemove(analysisId, out _);
                    }
                }
                
                // Remove connection mapping
                _connectionAnalysis.TryRemove(connectionId, out _);
                
                _logger.LogInformation("Connection {ConnectionId} unsubscribed from analysis {AnalysisId}", 
                    connectionId, analysisId);
                
                await Clients.Caller.SendAsync("UnsubscriptionConfirmed", new
                {
                    AnalysisId = analysisId,
                    Message = "Successfully unsubscribed from analysis updates"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error unsubscribing from analysis {AnalysisId}", analysisId);
                await Clients.Caller.SendAsync("Error", "Failed to unsubscribe from analysis updates");
            }
        }
        
        /// <summary>
        /// Get current analysis status
        /// </summary>
        /// <param name="analysisId">The analysis ID to get status for</param>
        public async Task GetAnalysisStatus(string analysisId)
        {
            try
            {
                if (string.IsNullOrEmpty(analysisId))
                {
                    await Clients.Caller.SendAsync("Error", "Analysis ID is required");
                    return;
                }
                
                // This would typically fetch from database or cache
                // For now, return a placeholder response
                await Clients.Caller.SendAsync("AnalysisStatus", new
                {
                    AnalysisId = analysisId,
                    Status = "processing",
                    Progress = 50,
                    Message = "Analysis in progress"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting analysis status for {AnalysisId}", analysisId);
                await Clients.Caller.SendAsync("Error", "Failed to get analysis status");
            }
        }
        
        /// <summary>
        /// Ping to keep connection alive
        /// </summary>
        public async Task Ping()
        {
            await Clients.Caller.SendAsync("Pong", new
            {
                Timestamp = DateTime.UtcNow,
                ConnectionId = Context.ConnectionId
            });
        }
        
        public override async Task OnConnectedAsync()
        {
            var connectionId = Context.ConnectionId;
            _logger.LogInformation("Client connected: {ConnectionId}", connectionId);
            
            await Clients.Caller.SendAsync("Connected", new
            {
                ConnectionId = connectionId,
                Message = "Successfully connected to SecuNik LogX analysis hub",
                Timestamp = DateTime.UtcNow
            });
            
            await base.OnConnectedAsync();
        }
        
        public override async Task OnDisconnectedAsync(Exception? exception)
        {
            var connectionId = Context.ConnectionId;
            
            // Clean up subscriptions
            if (_connectionAnalysis.TryRemove(connectionId, out var analysisId))
            {
                if (_analysisSubscriptions.TryGetValue(analysisId, out var connections))
                {
                    connections.Remove(connectionId);
                    if (connections.Count == 0)
                    {
                        _analysisSubscriptions.TryRemove(analysisId, out _);
                    }
                }
            }
            
            if (exception != null)
            {
                _logger.LogWarning(exception, "Client disconnected with error: {ConnectionId}", connectionId);
            }
            else
            {
                _logger.LogInformation("Client disconnected: {ConnectionId}", connectionId);
            }
            
            await base.OnDisconnectedAsync(exception);
        }
        
        // Static methods for sending updates from services
        public static async Task SendAnalysisUpdate(IHubContext<AnalysisHub> hubContext, string analysisId, object update)
        {
            await hubContext.Clients.Group($"analysis_{analysisId}").SendAsync("AnalysisUpdate", update);
        }
        
        public static async Task SendAnalysisProgress(IHubContext<AnalysisHub> hubContext, string analysisId, int progress, string? message = null)
        {
            await hubContext.Clients.Group($"analysis_{analysisId}").SendAsync("AnalysisProgress", new
            {
                AnalysisId = analysisId,
                Progress = progress,
                Message = message,
                Timestamp = DateTime.UtcNow
            });
        }
        
        public static async Task SendAnalysisCompleted(IHubContext<AnalysisHub> hubContext, string analysisId, object? results = null)
        {
            await hubContext.Clients.Group($"analysis_{analysisId}").SendAsync("AnalysisCompleted", new
            {
                AnalysisId = analysisId,
                Results = results,
                Timestamp = DateTime.UtcNow
            });
        }
        
        public static async Task SendAnalysisError(IHubContext<AnalysisHub> hubContext, string analysisId, string error)
        {
            await hubContext.Clients.Group($"analysis_{analysisId}").SendAsync("AnalysisError", new
            {
                AnalysisId = analysisId,
                Error = error,
                Timestamp = DateTime.UtcNow
            });
        }
        
        public static async Task SendThreatAlert(IHubContext<AnalysisHub> hubContext, string analysisId, object threat)
        {
            await hubContext.Clients.Group($"analysis_{analysisId}").SendAsync("ThreatAlert", new
            {
                AnalysisId = analysisId,
                Threat = threat,
                Timestamp = DateTime.UtcNow
            });
        }
        
        public static async Task SendIOCFound(IHubContext<AnalysisHub> hubContext, string analysisId, object ioc)
        {
            await hubContext.Clients.Group($"analysis_{analysisId}").SendAsync("IOCFound", new
            {
                AnalysisId = analysisId,
                IOC = ioc,
                Timestamp = DateTime.UtcNow
            });
        }
        
        public static async Task SendRuleMatch(IHubContext<AnalysisHub> hubContext, string analysisId, object ruleMatch)
        {
            await hubContext.Clients.Group($"analysis_{analysisId}").SendAsync("RuleMatch", new
            {
                AnalysisId = analysisId,
                RuleMatch = ruleMatch,
                Timestamp = DateTime.UtcNow
            });
        }
    }
}