using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Core.Configuration;
using Microsoft.Extensions.Options;
using System.Text.Json;

namespace SecuNik.LogX.Api.Services.External
{
    public class VirusTotalService : IThreatIntelligenceService
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<VirusTotalService> _logger;
        private readonly VirusTotalOptions _options;
        
        private readonly SemaphoreSlim _requestThrottle;
        private DateTime _lastRequestTime = DateTime.MinValue;
        
        public VirusTotalService(
            HttpClient httpClient,
            IOptions<VirusTotalOptions> options,
            ILogger<VirusTotalService> logger)
        {
            _httpClient = httpClient;
            _logger = logger;
            _options = options.Value;
            
            // Configure HTTP client
            _httpClient.BaseAddress = new Uri(_options.BaseUrl);
            _httpClient.DefaultRequestHeaders.Add("x-apikey", _options.ApiKey);
            
            // Create request throttle
            _requestThrottle = new SemaphoreSlim(_options.MaxRequestsPerMinute);
        }
        
        public async Task<ThreatIntelligenceResult> AnalyzeIOCAsync(
            string iocValue, 
            IOCType iocType, 
            CancellationToken cancellationToken = default)
        {
            if (!_options.EnableIntegration || string.IsNullOrEmpty(_options.ApiKey))
            {
                _logger.LogWarning("VirusTotal integration is disabled or API key is missing");
                return new ThreatIntelligenceResult
                {
                    IOCValue = iocValue,
                    IOCType = iocType,
                    IsMalicious = false,
                    ThreatScore = 0,
                    Source = "virustotal",
                    LastSeen = DateTime.UtcNow
                };
            }
            
            try
            {
                // Throttle requests
                await ThrottleRequestsAsync();
                
                // Determine endpoint based on IOC type
                string endpoint = iocType switch
                {
                    IOCType.FileHash => $"/files/{iocValue}",
                    IOCType.IPAddress => $"/ip_addresses/{iocValue}",
                    IOCType.Domain => $"/domains/{iocValue}",
                    IOCType.URL => $"/urls/{Uri.EscapeDataString(iocValue)}",
                    _ => throw new NotSupportedException($"IOC type {iocType} is not supported by VirusTotal")
                };
                
                // Make request
                var response = await _httpClient.GetAsync(endpoint, cancellationToken);
                
                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("VirusTotal API returned {StatusCode} for {IOCValue}", 
                        response.StatusCode, iocValue);
                    
                    return new ThreatIntelligenceResult
                    {
                        IOCValue = iocValue,
                        IOCType = iocType,
                        IsMalicious = false,
                        ThreatScore = 0,
                        Source = "virustotal",
                        LastSeen = DateTime.UtcNow
                    };
                }
                
                // Parse response
                var content = await response.Content.ReadAsStringAsync(cancellationToken);
                var data = JsonSerializer.Deserialize<JsonElement>(content);
                
                // Extract results
                var attributes = data.GetProperty("data").GetProperty("attributes");
                
                int malicious = 0;
                int total = 0;
                
                if (attributes.TryGetProperty("last_analysis_stats", out var stats))
                {
                    malicious = stats.GetProperty("malicious").GetInt32();
                    total = stats.GetProperty("malicious").GetInt32() + 
                            stats.GetProperty("suspicious").GetInt32() + 
                            stats.GetProperty("undetected").GetInt32() + 
                            stats.GetProperty("harmless").GetInt32();
                }
                
                // Calculate threat score (0-100)
                int threatScore = total > 0 ? (int)Math.Round((double)malicious / total * 100) : 0;
                
                // Extract additional metadata
                var threatTypes = new List<string>();
                var malwareFamilies = new List<string>();
                
                if (attributes.TryGetProperty("popular_threat_classification", out var classification))
                {
                    if (classification.TryGetProperty("suggested_threat_label", out var threatLabel))
                    {
                        threatTypes.Add(threatLabel.GetString());
                    }
                    
                    if (classification.TryGetProperty("popular_threat_category", out var categories))
                    {
                        foreach (var category in categories.EnumerateArray())
                        {
                            threatTypes.Add(category.GetProperty("value").GetString());
                        }
                    }
                    
                    if (classification.TryGetProperty("popular_threat_name", out var names))
                    {
                        foreach (var name in names.EnumerateArray())
                        {
                            malwareFamilies.Add(name.GetProperty("value").GetString());
                        }
                    }
                }
                
                // Create result
                var result = new ThreatIntelligenceResult
                {
                    IOCValue = iocValue,
                    IOCType = iocType,
                    IsMalicious = malicious > 0,
                    ThreatScore = threatScore,
                    Source = "virustotal",
                    ThreatTypes = threatTypes,
                    AssociatedMalware = malwareFamilies,
                    LastSeen = DateTime.UtcNow,
                    Details = new Dictionary<string, object>
                    {
                        ["malicious_detections"] = malicious,
                        ["total_scans"] = total,
                        ["detection_ratio"] = total > 0 ? (double)malicious / total : 0
                    }
                };
                
                _logger.LogInformation("VirusTotal analysis for {IOCValue}: Score {ThreatScore}, Malicious: {IsMalicious}",
                    iocValue, threatScore, result.IsMalicious);
                
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing IOC {IOCValue} with VirusTotal", iocValue);
                
                return new ThreatIntelligenceResult
                {
                    IOCValue = iocValue,
                    IOCType = iocType,
                    IsMalicious = false,
                    ThreatScore = 0,
                    Source = "virustotal",
                    LastSeen = DateTime.UtcNow,
                    Details = new Dictionary<string, object>
                    {
                        ["error"] = ex.Message
                    }
                };
            }
        }
        
        public async Task<List<ThreatIntelligenceResult>> AnalyzeIOCsAsync(
            List<IOC> iocs, 
            CancellationToken cancellationToken = default)
        {
            var results = new List<ThreatIntelligenceResult>();
            
            foreach (var ioc in iocs)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                var result = await AnalyzeIOCAsync(ioc.Value, ioc.Type, cancellationToken);
                results.Add(result);
            }
            
            return results;
        }
        
        public async Task<ReputationResult> CheckReputationAsync(
            string value, 
            IOCType type, 
            CancellationToken cancellationToken = default)
        {
            try
            {
                var threatResult = await AnalyzeIOCAsync(value, type, cancellationToken);
                
                var status = threatResult.IsMalicious ? "malicious" : 
                             threatResult.ThreatScore > 20 ? "suspicious" : "clean";
                
                return new ReputationResult
                {
                    Value = value,
                    Type = type,
                    Status = MapToReputationStatus(status),
                    Score = threatResult.ThreatScore,
                    Provider = "virustotal",
                    CheckedAt = DateTime.UtcNow,
                    Metadata = threatResult.Details
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking reputation for {Value}", value);
                
                return new ReputationResult
                {
                    Value = value,
                    Type = type,
                    Status = ReputationStatus.Error,
                    Score = 0,
                    Provider = "virustotal",
                    CheckedAt = DateTime.UtcNow,
                    Metadata = new Dictionary<string, object>
                    {
                        ["error"] = ex.Message
                    }
                };
            }
        }
        
        public async Task<List<IOC>> ExtractIOCsAsync(
            string content, 
            CancellationToken cancellationToken = default)
        {
            // This is a placeholder implementation
            // In a real implementation, we would use VirusTotal Intelligence to extract IOCs
            
            _logger.LogInformation("VirusTotal IOC extraction is not implemented");
            return new List<IOC>();
        }
        
        public async Task<ThreatContextResult> GetThreatContextAsync(
            List<IOC> iocs, 
            CancellationToken cancellationToken = default)
        {
            // This is a placeholder implementation
            // In a real implementation, we would use VirusTotal Intelligence to get threat context
            
            _logger.LogInformation("VirusTotal threat context is not implemented");
            return new ThreatContextResult();
        }
        
        private async Task ThrottleRequestsAsync()
        {
            // Respect rate limits
            await _requestThrottle.WaitAsync();
            
            try
            {
                var timeSinceLastRequest = DateTime.UtcNow - _lastRequestTime;
                var minimumInterval = TimeSpan.FromMilliseconds(_options.RequestDelayMs);
                
                if (timeSinceLastRequest < minimumInterval)
                {
                    await Task.Delay(minimumInterval - timeSinceLastRequest);
                }
                
                _lastRequestTime = DateTime.UtcNow;
            }
            finally
            {
                // Release after delay
                _ = Task.Run(async () =>
                {
                    await Task.Delay(TimeSpan.FromMinutes(1) / _options.MaxRequestsPerMinute);
                    _requestThrottle.Release();
                });
            }
        }
        
        private ReputationStatus MapToReputationStatus(string status)
        {
            return status.ToLowerInvariant() switch
            {
                "clean" => ReputationStatus.Clean,
                "suspicious" => ReputationStatus.Suspicious,
                "malicious" => ReputationStatus.Malicious,
                _ => ReputationStatus.Unknown
            };
        }
    }
    
    public class VirusTotalOptions
    {
        public const string SectionName = "VirusTotal";
        
        public string ApiKey { get; set; } = string.Empty;
        public string BaseUrl { get; set; } = "https://www.virustotal.com/api/v3";
        public bool EnableIntegration { get; set; } = false;
        public int RequestDelayMs { get; set; } = 15000;
        public int MaxRequestsPerMinute { get; set; } = 4;
        public int CacheExpirationHours { get; set; } = 24;
    }
}