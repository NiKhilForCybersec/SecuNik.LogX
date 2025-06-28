using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Core.Entities;
using SecuNik.LogX.Core.DTOs; // Add this for IOCDto
using SecuNik.LogX.Api.Data;
using SecuNik.LogX.Api.Services.Parsers; // Add this for ParserFactory
using Microsoft.EntityFrameworkCore;

// IMPORTANT: Add this alias to avoid namespace collision
using AnalysisEntity = SecuNik.LogX.Core.Entities.Analysis;
using SecuNik.LogX.Core.Configuration;
using Microsoft.Extensions.Options;
using System.Text;
using System.Text.Json;

namespace SecuNik.LogX.Api.Services.Analysis
{
    public class AIAnalyzerService
    {
        private readonly OpenAIOptions _options;
        private readonly ILogger<AIAnalyzerService> _logger;
        private readonly HttpClient _httpClient;
        
        public AIAnalyzerService(
            IOptions<OpenAIOptions> options,
            ILogger<AIAnalyzerService> logger)
        {
            _options = options.Value;
            _logger = logger;
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_options.ApiKey}");
            _httpClient.Timeout = TimeSpan.FromSeconds(_options.TimeoutSeconds);
        }
        
        public async Task<object> AnalyzeAsync(
            List<LogEvent> events,
            List<RuleMatchResult> ruleMatches,
            List<IOC> iocs,
            CancellationToken cancellationToken = default)
        {
            if (!_options.EnableAIAnalysis || string.IsNullOrEmpty(_options.ApiKey))
            {
                _logger.LogWarning("AI analysis is disabled or API key is missing");
                return new { message = "AI analysis is disabled" };
            }
            
            try
            {
                _logger.LogInformation("Starting AI analysis of {EventCount} events, {MatchCount} rule matches, and {IocCount} IOCs",
                    events.Count, ruleMatches.Count, iocs?.Count ?? 0);
                
                // Prepare data for analysis
                var analysisData = PrepareAnalysisData(events, ruleMatches, iocs);
                
                // Generate analysis
                var analysis = await GenerateAnalysisAsync(analysisData, cancellationToken);
                
                // Extract IOCs if enabled
                object iocAnalysis = null;
                if (_options.EnableAIIOCExtraction)
                {
                    iocAnalysis = await ExtractIOCsAsync(analysisData, cancellationToken);
                }
                
                // Generate threat assessment if enabled
                object threatAssessment = null;
                if (_options.EnableAIThreatAssessment)
                {
                    threatAssessment = await GenerateThreatAssessmentAsync(analysisData, ruleMatches, iocs, cancellationToken);
                }
                
                // Generate summary if enabled
                object summary = null;
                if (_options.EnableAISummary)
                {
                    summary = await GenerateSummaryAsync(analysisData, cancellationToken);
                }
                
                // Combine results
                var result = new
                {
                    analysis = analysis,
                    ioc_analysis = iocAnalysis,
                    threat_assessment = threatAssessment,
                    summary = summary,
                    generated_at = DateTime.UtcNow
                };
                
                _logger.LogInformation("AI analysis completed successfully");
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during AI analysis");
                return new { error = ex.Message };
            }
        }
        
        private string PrepareAnalysisData(
            List<LogEvent> events,
            List<RuleMatchResult> ruleMatches,
            List<IOC> iocs)
        {
            var sb = new StringBuilder();
            
            // Add summary of data
            sb.AppendLine("=== ANALYSIS DATA ===");
            sb.AppendLine($"Total Events: {events.Count}");
            sb.AppendLine($"Rule Matches: {ruleMatches.Count}");
            sb.AppendLine($"IOCs Found: {iocs?.Count ?? 0}");
            sb.AppendLine();
            
            // Add rule matches
            if (ruleMatches.Count > 0)
            {
                sb.AppendLine("=== RULE MATCHES ===");
                foreach (var match in ruleMatches.Take(10)) // Limit to avoid token limits
                {
                    sb.AppendLine($"Rule: {match.RuleName}");
                    sb.AppendLine($"Type: {match.RuleType}");
                    sb.AppendLine($"Severity: {match.Severity}");
                    sb.AppendLine($"Match Count: {match.MatchCount}");
                    
                    if (match.Matches.Count > 0)
                    {
                        sb.AppendLine("Sample Matches:");
                        foreach (var detail in match.Matches.Take(3)) // Limit samples
                        {
                            sb.AppendLine($"- {detail.MatchedContent}");
                        }
                    }
                    
                    if (match.MitreAttackIds.Count > 0)
                    {
                        sb.AppendLine($"MITRE ATT&CK: {string.Join(", ", match.MitreAttackIds)}");
                    }
                    
                    sb.AppendLine();
                }
                
                if (ruleMatches.Count > 10)
                {
                    sb.AppendLine($"... and {ruleMatches.Count - 10} more rule matches");
                }
                
                sb.AppendLine();
            }
            
            // Add IOCs
            if (iocs != null && iocs.Count > 0)
            {
                sb.AppendLine("=== INDICATORS OF COMPROMISE ===");
                foreach (var ioc in iocs.Take(20)) // Limit to avoid token limits
                {
                    sb.AppendLine($"Type: {ioc.Type}");
                    sb.AppendLine($"Value: {ioc.Value}");
                    sb.AppendLine($"Context: {ioc.Context}");
                    sb.AppendLine();
                }
                
                if (iocs.Count > 20)
                {
                    sb.AppendLine($"... and {iocs.Count - 20} more IOCs");
                }
                
                sb.AppendLine();
            }
            
            // Add sample events
            sb.AppendLine("=== SAMPLE EVENTS ===");
            foreach (var evt in events.Take(20)) // Limit to avoid token limits
            {
                sb.AppendLine($"Timestamp: {evt.Timestamp}");
                sb.AppendLine($"Level: {evt.Level}");
                sb.AppendLine($"Source: {evt.Source}");
                sb.AppendLine($"Message: {evt.Message}");
                sb.AppendLine();
            }
            
            if (events.Count > 20)
            {
                sb.AppendLine($"... and {events.Count - 20} more events");
            }
            
            return sb.ToString();
        }
        
        private async Task<string> GenerateAnalysisAsync(string data, CancellationToken cancellationToken)
        {
            var prompt = $"{_options.AnalysisPrompt}\n\nData to analyze:\n{data}";
            var response = await CallOpenAIAsync(prompt, cancellationToken);
            return response;
        }
        
        private async Task<object> ExtractIOCsAsync(string data, CancellationToken cancellationToken)
        {
            var prompt = $"{_options.IOCExtractionPrompt}\n\nData to analyze:\n{data}";
            var response = await CallOpenAIAsync(prompt, cancellationToken);
            
            // In a real implementation, we would parse the response to extract structured IOCs
            return new
            {
                analysis = response,
                total_found = 0,
                malicious_count = 0
            };
        }
        
        private async Task<object> GenerateThreatAssessmentAsync(
            string data, 
            List<RuleMatchResult> ruleMatches,
            List<IOC> iocs,
            CancellationToken cancellationToken)
        {
            var prompt = $"{_options.ThreatAssessmentPrompt}\n\nData to assess:\n{data}";
            var response = await CallOpenAIAsync(prompt, cancellationToken);
            
            // In a real implementation, we would parse the response to extract the threat score
            // For now, calculate a simple score based on rule matches
            int score = 0;
            if (ruleMatches.Count > 0)
            {
                var criticalCount = ruleMatches.Count(r => r.Severity == ThreatLevel.Critical);
                var highCount = ruleMatches.Count(r => r.Severity == ThreatLevel.High);
                var mediumCount = ruleMatches.Count(r => r.Severity == ThreatLevel.Medium);
                
                score = (criticalCount * 100 + highCount * 75 + mediumCount * 50) / Math.Max(1, ruleMatches.Count);
                score = Math.Min(100, score);
            }
            
            return new
            {
                score = score,
                reasoning = response,
                confidence = 0.85
            };
        }
        
        private async Task<object> GenerateSummaryAsync(string data, CancellationToken cancellationToken)
        {
            var prompt = "Provide a concise summary of the security analysis findings. " +
                         "Include key findings, recommendations, and potential threats.\n\n" +
                         $"Data to summarize:\n{data}";
                         
            var response = await CallOpenAIAsync(prompt, cancellationToken);
            
            // In a real implementation, we would parse the response to extract structured data
            return new
            {
                summary = response,
                key_points = new[] { "Sample key point 1", "Sample key point 2" }
            };
        }
        
        private async Task<string> CallOpenAIAsync(string prompt, CancellationToken cancellationToken)
        {
            try
            {
                var requestBody = new
                {
                    model = _options.DefaultModel,
                    messages = new[]
                    {
                        new { role = "system", content = "You are a cybersecurity analyst assistant." },
                        new { role = "user", content = prompt }
                    },
                    max_tokens = _options.MaxTokens,
                    temperature = _options.Temperature
                };
                
                var content = new StringContent(
                    JsonSerializer.Serialize(requestBody),
                    Encoding.UTF8,
                    "application/json");
                
                var response = await _httpClient.PostAsync($"{_options.BaseUrl}/chat/completions", content, cancellationToken);
                
                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
                    _logger.LogError("OpenAI API error: {StatusCode} - {ErrorContent}", 
                        response.StatusCode, errorContent);
                    return $"Error: {response.StatusCode}";
                }
                
                var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);
                var responseObject = JsonSerializer.Deserialize<JsonElement>(responseContent);
                
                return responseObject
                    .GetProperty("choices")[0]
                    .GetProperty("message")
                    .GetProperty("content")
                    .GetString() ?? "No response generated";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calling OpenAI API");
                return $"Error: {ex.Message}";
            }
        }
    }
}