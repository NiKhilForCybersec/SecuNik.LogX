using Microsoft.AspNetCore.SignalR;
using SecuNikLogX.API.Models;
using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SecuNikLogX.API.Hubs
{
    public interface IAnalysisHubClient
    {
        Task ReceiveAnalysisProgress(string analysisId, int percentage, string status);
        Task ReceiveIOCDetected(string analysisId, IOCNotification ioc);
        Task ReceiveMITREMapped(string analysisId, MITRENotification mitre);
        Task ReceiveAnalysisComplete(string analysisId, AnalysisCompleteNotification result);
        Task ReceiveError(string message, string errorCode);
    }

    public class AnalysisHub : Hub<IAnalysisHubClient>
    {
        private static readonly ConcurrentDictionary<string, ConnectionInfo> _connections = new();
        private readonly ILogger<AnalysisHub> _logger;

        public AnalysisHub(ILogger<AnalysisHub> logger)
        {
            _logger = logger;
        }

        public override async Task OnConnectedAsync()
        {
            var connectionId = Context.ConnectionId;
            var userAgent = Context.GetHttpContext()?.Request.Headers["User-Agent"].ToString() ?? "Unknown";
            var ipAddress = Context.GetHttpContext()?.Connection.RemoteIpAddress?.ToString() ?? "Unknown";

            var connectionInfo = new ConnectionInfo
            {
                ConnectionId = connectionId,
                ConnectedAt = DateTime.UtcNow,
                UserAgent = userAgent,
                IpAddress = ipAddress
            };

            _connections.TryAdd(connectionId, connectionInfo);
            _logger.LogInformation("Client connected: {ConnectionId} from {IpAddress}", connectionId, ipAddress);

            await base.OnConnectedAsync();
        }

        public override async Task OnDisconnectedAsync(Exception exception)
        {
            var connectionId = Context.ConnectionId;
            _connections.TryRemove(connectionId, out _);

            if (exception != null)
            {
                _logger.LogError(exception, "Client disconnected with error: {ConnectionId}", connectionId);
            }
            else
            {
                _logger.LogInformation("Client disconnected: {ConnectionId}", connectionId);
            }

            await base.OnDisconnectedAsync(exception);
        }

        public async Task JoinAnalysisGroup(string analysisId)
        {
            if (string.IsNullOrEmpty(analysisId))
            {
                await Clients.Caller.ReceiveError("Invalid analysis ID", "INVALID_ANALYSIS_ID");
                return;
            }

            var groupName = GetAnalysisGroupName(analysisId);
            await Groups.AddToGroupAsync(Context.ConnectionId, groupName);

            _logger.LogInformation("Client {ConnectionId} joined analysis group: {AnalysisId}", 
                Context.ConnectionId, analysisId);

            await Clients.Caller.ReceiveAnalysisProgress(analysisId, 0, "Joined analysis session");
        }

        public async Task LeaveAnalysisGroup(string analysisId)
        {
            if (string.IsNullOrEmpty(analysisId))
            {
                await Clients.Caller.ReceiveError("Invalid analysis ID", "INVALID_ANALYSIS_ID");
                return;
            }

            var groupName = GetAnalysisGroupName(analysisId);
            await Groups.RemoveFromGroupAsync(Context.ConnectionId, groupName);

            _logger.LogInformation("Client {ConnectionId} left analysis group: {AnalysisId}", 
                Context.ConnectionId, analysisId);
        }

        public async Task SendProgress(string analysisId, int percentage, string status)
        {
            if (string.IsNullOrEmpty(analysisId))
            {
                await Clients.Caller.ReceiveError("Invalid analysis ID", "INVALID_ANALYSIS_ID");
                return;
            }

            if (percentage < 0 || percentage > 100)
            {
                await Clients.Caller.ReceiveError("Invalid progress percentage", "INVALID_PROGRESS");
                return;
            }

            var groupName = GetAnalysisGroupName(analysisId);
            await Clients.Group(groupName).ReceiveAnalysisProgress(analysisId, percentage, status);

            _logger.LogInformation("Progress update for analysis {AnalysisId}: {Percentage}% - {Status}", 
                analysisId, percentage, status);
        }

        public async Task NotifyIOCDetected(string analysisId, IOCNotification ioc)
        {
            if (string.IsNullOrEmpty(analysisId))
            {
                await Clients.Caller.ReceiveError("Invalid analysis ID", "INVALID_ANALYSIS_ID");
                return;
            }

            if (ioc == null)
            {
                await Clients.Caller.ReceiveError("Invalid IOC notification", "INVALID_IOC");
                return;
            }

            var groupName = GetAnalysisGroupName(analysisId);
            await Clients.Group(groupName).ReceiveIOCDetected(analysisId, ioc);

            _logger.LogInformation("IOC detected for analysis {AnalysisId}: Type={Type}, Value={Value}", 
                analysisId, ioc.Type, ioc.Value);
        }

        public async Task NotifyMITREMapped(string analysisId, MITRENotification mitre)
        {
            if (string.IsNullOrEmpty(analysisId))
            {
                await Clients.Caller.ReceiveError("Invalid analysis ID", "INVALID_ANALYSIS_ID");
                return;
            }

            if (mitre == null)
            {
                await Clients.Caller.ReceiveError("Invalid MITRE notification", "INVALID_MITRE");
                return;
            }

            var groupName = GetAnalysisGroupName(analysisId);
            await Clients.Group(groupName).ReceiveMITREMapped(analysisId, mitre);

            _logger.LogInformation("MITRE technique mapped for analysis {AnalysisId}: {TechniqueId} - {Name}", 
                analysisId, mitre.TechniqueId, mitre.Name);
        }

        private string GetAnalysisGroupName(string analysisId)
        {
            return $"analysis-{analysisId}";
        }
    }

    public class ConnectionInfo
    {
        public string ConnectionId { get; set; }
        public DateTime ConnectedAt { get; set; }
        public string UserAgent { get; set; }
        public string IpAddress { get; set; }
        public DateTime LastActivity { get; set; } = DateTime.UtcNow;
    }

    public class IOCNotification
    {
        public string Id { get; set; }
        public string Type { get; set; }
        public string Value { get; set; }
        public string Context { get; set; }
        public double Confidence { get; set; }
        public DateTime DetectedAt { get; set; }
        public string Severity { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
    }

    public class MITRENotification
    {
        public string TechniqueId { get; set; }
        public string Name { get; set; }
        public string Tactic { get; set; }
        public double Confidence { get; set; }
        public string Description { get; set; }
        public List<string> RelatedIOCs { get; set; }
        public DateTime MappedAt { get; set; }
    }

    public class AnalysisCompleteNotification
    {
        public string AnalysisId { get; set; }
        public string Status { get; set; }
        public DateTime CompletedAt { get; set; }
        public int TotalIOCs { get; set; }
        public int TotalMITRETechniques { get; set; }
        public double ThreatLevel { get; set; }
        public string Summary { get; set; }
        public Dictionary<string, object> Statistics { get; set; }
    }
}