using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using Polly;
using Polly.Extensions.Http;
using SecuNik.LogX.Domain.Entities;
using SecuNik.LogX.Domain.Enums;
using SecuNik.LogX.API.Services;

namespace SecuNik.LogX.API.Services
{
    public class AIService
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<AIService> _logger;
        private readonly IConfiguration _configuration;
        private readonly IMemoryCache _cache;
        private readonly SemaphoreSlim _rateLimiter;
        private readonly string _apiKey;
        private readonly string _apiEndpoint;
        private readonly int _maxTokens;
        private readonly double _temperature;
        private readonly IAsyncPolicy<HttpResponseMessage> _retryPolicy;
        private long _totalTokensUsed = 0;
        private readonly object _tokenLock = new object();

        public AIService(
            HttpClient httpClient,
            ILogger<AIService> logger,
            IConfiguration configuration,
            IMemoryCache cache)
        {
            _httpClient = httpClient;
            _logger = logger;
            _configuration = configuration;
            _cache = cache;
            
            _apiKey = configuration["OpenAI:ApiKey"] ?? throw new InvalidOperationException("OpenAI API key not configured");
            _apiEndpoint = configuration["OpenAI:Endpoint"] ?? "https://api.openai.com/v1";
            _maxTokens = configuration.GetValue<int>("OpenAI:MaxTokens", 4000);
            _temperature = configuration.GetValue<double>("OpenAI:Temperature", 0.7);
            
            _rateLimiter = new SemaphoreSlim(
                configuration.GetValue<int>("OpenAI:RateLimitPerMinute", 20),
                configuration.GetValue<int>("OpenAI:RateLimitPerMinute", 20)
            );

            // Configure HTTP client
            _httpClient.BaseAddress = new Uri(_apiEndpoint);
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _apiKey);
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "SecuNik-LogX-Forensics/1.0");
            _httpClient.Timeout = TimeSpan.FromMinutes(2);

            // Configure retry policy with exponential backoff
            _retryPolicy = HttpPolicyExtensions
                .HandleTransientHttpError()
                .OrResult(msg => msg.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                .WaitAndRetryAsync(
                    3,
                    retryAttempt => TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)),
                    onRetry: (outcome, timespan, retryCount, context) =>
                    {
                        _logger.LogWarning("OpenAI API retry attempt {RetryCount} after {Delay}s", retryCount, timespan.TotalSeconds);
                    });
        }

        public async Task<string> AnalyzeFileContentAsync(string filePath, CancellationToken cancellationToken = default)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException($"File not found: {filePath}");

            var fileContent = await File.ReadAllTextAsync(filePath, cancellationToken);
            var fileInfo = new FileInfo(filePath);

            // Truncate content if too large
            if (fileContent.Length > 50000)
            {
                fileContent = fileContent.Substring(0, 50000) + "... [truncated]";
            }

            var prompt = $@"Analyze the following forensics evidence file for security threats, indicators of compromise, and suspicious patterns.

File: {fileInfo.Name}
Size: {fileInfo.Length} bytes
Modified: {fileInfo.LastWriteTimeUtc:yyyy-MM-dd HH:mm:ss} UTC

Content:
{fileContent}

Provide a comprehensive forensics analysis including:
1. Identified threats and security issues
2. Indicators of Compromise (IOCs) found
3. Suspicious patterns or anomalies
4. Attack techniques potentially used
5. Risk assessment and severity
6. Recommended actions

Format the response as a structured forensics report.";

            return await SendCompletionRequestAsync(prompt, cancellationToken);
        }

        public async Task<ThreatAssessment> GenerateThreatAssessmentAsync(Analysis analysis, CancellationToken cancellationToken = default)
        {
            var cacheKey = $"threat_assessment_{analysis.Id}";
            if (_cache.TryGetValue<ThreatAssessment>(cacheKey, out var cached))
                return cached;

            var prompt = $@"Based on the following forensics analysis results, provide a comprehensive threat assessment:

Analysis ID: {analysis.Id}
File: {Path.GetFileName(analysis.SourceFile)}
Current Threat Level: {analysis.ThreatLevel}
IOCs Found: {analysis.IOCs?.Count ?? 0}
MITRE Techniques: {analysis.MITRE?.Count ?? 0}

Findings:
{analysis.Findings ?? "No findings available"}

Provide:
1. Overall threat severity (Critical/High/Medium/Low)
2. Confidence level (percentage)
3. Attack sophistication assessment
4. Potential threat actor profile
5. Business impact analysis
6. Recommended immediate actions
7. Long-term security recommendations";

            var response = await SendCompletionRequestAsync(prompt, cancellationToken);
            
            var assessment = ParseThreatAssessment(response, analysis.Id);
            
            _cache.Set(cacheKey, assessment, TimeSpan.FromHours(1));
            return assessment;
        }

        public async Task<List<IOC>> ExtractIOCsAsync(string content, CancellationToken cancellationToken = default)
        {
            var prompt = $@"Extract all Indicators of Compromise (IOCs) from the following content. Return a structured list with IOC type, value, and confidence level.

Content:
{content.Length > 10000 ? content.Substring(0, 10000) + "... [truncated]" : content}

Extract and categorize:
- IP addresses (IPv4 and IPv6)
- Domain names and URLs
- File hashes (MD5, SHA1, SHA256, SHA512)
- Email addresses
- File paths and names
- Registry keys
- Cryptocurrency addresses
- Network ports and protocols
- Malware signatures

Format each IOC as: Type|Value|Confidence(0-100)|Context";

            var response = await SendCompletionRequestAsync(prompt, cancellationToken);
            return ParseIOCResponse(response);
        }

        public async Task<string> AnalyzeLogContentAsync(string logContent, string logType, CancellationToken cancellationToken = default)
        {
            var prompt = $@"Analyze the following {logType} log content for security incidents, anomalies, and forensics artifacts:

Log Type: {logType}
Content Sample:
{logContent.Length > 20000 ? logContent.Substring(0, 20000) + "... [truncated]" : logContent}

Identify:
1. Security events and incidents
2. Authentication failures and successes
3. Privilege escalation attempts
4. Data exfiltration indicators
5. Command and control traffic
6. System compromises
7. Timeline of events
8. User behavior anomalies

Provide a forensics-focused analysis with specific evidence citations.";

            return await SendCompletionRequestAsync(prompt, cancellationToken);
        }

        public async Task<List<Anomaly>> DetectAnomaliesAsync(string content, string contentType, CancellationToken cancellationToken = default)
        {
            var prompt = $@"Detect anomalies and suspicious patterns in the following {contentType} content:

{content.Length > 15000 ? content.Substring(0, 15000) + "... [truncated]" : content}

Focus on:
1. Statistical anomalies (unusual frequencies, outliers)
2. Behavioral anomalies (deviations from normal patterns)
3. Structural anomalies (malformed data, encoding issues)
4. Temporal anomalies (unusual timing, sequences)
5. Security anomalies (suspicious commands, paths, users)

For each anomaly provide:
- Type of anomaly
- Severity (Critical/High/Medium/Low)
- Confidence level (0-100)
- Location/context in the data
- Potential security implications";

            var response = await SendCompletionRequestAsync(prompt, cancellationToken);
            return ParseAnomalyResponse(response);
        }

        public async Task<ThreatLevel> ClassifyThreatLevelAsync(AnalysisResult analysisResult, CancellationToken cancellationToken = default)
        {
            var prompt = $@"Classify the threat level based on the following forensics analysis results:

IOCs detected: {analysisResult.IOCCount}
- High confidence IOCs: {analysisResult.IOCs?.Count(i => i.Confidence >= 80) ?? 0}
- Medium confidence IOCs: {analysisResult.IOCs?.Count(i => i.Confidence >= 50 && i.Confidence < 80) ?? 0}
- Low confidence IOCs: {analysisResult.IOCs?.Count(i => i.Confidence < 50) ?? 0}

MITRE ATT&amp;CK Techniques: {analysisResult.MITRETechniques}
Matched Rules: {analysisResult.RuleMatches}

Current findings summary:
{analysisResult.Findings ?? "No findings available"}

Based on industry standards and threat intelligence, classify as:
- Critical: Active compromise with ongoing data exfiltration or system control
- High: Confirmed malicious activity with significant impact potential
- Medium: Suspicious activity requiring investigation
- Low: Minor security issues or false positives

Respond with only the classification: Critical, High, Medium, or Low";

            var response = await SendCompletionRequestAsync(prompt, cancellationToken, maxTokens: 10);
            
            return Enum.TryParse<ThreatLevel>(response.Trim(), true, out var threatLevel) 
                ? threatLevel 
                : ThreatLevel.Medium;
        }

        public async Task<string> GenerateAnalysisReportAsync(AnalysisResult result, ReportFormat format, CancellationToken cancellationToken = default)
        {
            var prompt = format switch
            {
                ReportFormat.Executive => $@"Generate an executive summary report for the following forensics analysis:

Analysis ID: {result.AnalysisId}
Threat Level: {result.ThreatLevel}
Duration: {result.Duration}
IOCs Found: {result.IOCCount}
MITRE Techniques: {result.MITRETechniques}

Key Findings:
{result.Findings ?? "No specific findings"}

Create a concise executive report focusing on:
1. Business impact and risk assessment
2. Key security findings in non-technical terms
3. Immediate actions required
4. Resource requirements for remediation
5. Timeline and priorities

Keep it under 500 words, suitable for C-level executives.",

                ReportFormat.Technical => $@"Generate a detailed technical report for the following forensics analysis:

Analysis ID: {result.AnalysisId}
Threat Level: {result.ThreatLevel}
IOCs: {string.Join(", ", result.IOCs?.Take(10).Select(i => i.Type + ":" + i.Value) ?? new List<string>())}
MITRE Techniques: {string.Join(", ", result.MITREMappings?.Take(10).Select(m => m.TechniqueId) ?? new List<string>())}

Findings:
{result.Findings ?? "No findings"}

Create a comprehensive technical report including:
1. Detailed attack chain analysis
2. Technical indicators and artifacts
3. Network and system compromise details
4. Persistence mechanisms identified
5. Data accessed or exfiltrated
6. Technical remediation steps
7. Detection and monitoring recommendations",

                ReportFormat.Forensics => $@"Generate a formal digital forensics report for the following analysis:

Case ID: {result.AnalysisId}
Evidence Examined: Digital artifacts and system logs
Examination Date: {DateTime.UtcNow:yyyy-MM-dd}

Initial Findings:
{result.Findings ?? "No findings documented"}

Create a forensics report following legal standards:
1. Executive Summary
2. Evidence Identification and Chain of Custody
3. Examination Process and Methodology
4. Detailed Findings with Evidence Citations
5. Timeline Reconstruction
6. Artifact Analysis and Interpretation
7. Conclusions Based on Evidence
8. Recommendations for Further Investigation

Maintain objectivity and use precise forensics terminology.",

                _ => throw new ArgumentException($"Unsupported report format: {format}")
            };

            return await SendCompletionRequestAsync(prompt, cancellationToken, maxTokens: 2000);
        }

        public async Task<string> SummarizeAnalysisAsync(AnalysisResult result, CancellationToken cancellationToken = default)
        {
            var prompt = $@"Provide a concise summary of this forensics analysis:

Threat Level: {result.ThreatLevel}
IOCs: {result.IOCCount} indicators found
MITRE Techniques: {result.MITRETechniques} techniques identified
Duration: {result.Duration}

Top IOCs:
{string.Join("\n", result.IOCs?.Take(5).Select(i => "- " + i.Type + ": " + i.Value + " (Confidence: " + i.Confidence + "%)") ?? new List<string>())}

Key Findings:
{result.Findings ?? "No findings available"}

Summarize in 3-4 sentences focusing on:
1. Primary threat identified
2. Severity and impact
3. Most important action to take";

            return await SendCompletionRequestAsync(prompt, cancellationToken, maxTokens: 200);
        }

        public async Task<List<string>> GenerateRecommendationsAsync(Analysis analysis, CancellationToken cancellationToken = default)
        {
            var prompt = $@"Based on this forensics analysis, provide specific security recommendations:

Threat Level: {analysis.ThreatLevel}
File Analyzed: {Path.GetFileName(analysis.SourceFile)}
Key Findings: {analysis.Findings ?? "No specific findings"}
IOCs Found: {analysis.IOCs?.Count ?? 0}
MITRE Techniques: {analysis.MITRE?.Count ?? 0}

Provide 5-7 actionable recommendations:
1. Immediate containment actions
2. Investigation next steps
3. System hardening measures
4. Monitoring and detection improvements
5. Policy and process updates

Format each as a brief, actionable statement.";

            var response = await SendCompletionRequestAsync(prompt, cancellationToken);
            return ParseRecommendations(response);
        }

        public async Task<IOC> EnrichIOCWithAIAsync(IOC ioc, CancellationToken cancellationToken = default)
        {
            var cacheKey = $"ioc_enrichment_{ioc.Type}_{ioc.Value}";
            if (_cache.TryGetValue<IOC>(cacheKey, out var cached))
                return cached;

            var prompt = $@"Enrich the following IOC with threat intelligence context:

Type: {ioc.Type}
Value: {ioc.Value}
Current Context: {ioc.Context ?? "No context"}

Provide:
1. Threat classification (malicious/suspicious/benign)
2. Known associations with threat actors or campaigns
3. Common attack patterns using this IOC
4. First seen / last seen estimates
5. Geographic associations
6. Recommended blocking priority
7. Additional context for forensics investigation

Be specific and base on known threat intelligence patterns.";

            var response = await SendCompletionRequestAsync(prompt, cancellationToken, maxTokens: 500);
            
            ioc.Context = response;
            ioc.Enriched = true;
            ioc.EnrichedAt = DateTime.UtcNow;
            
            _cache.Set(cacheKey, ioc, TimeSpan.FromHours(24));
            return ioc;
        }

        public async Task<string> AnalyzeThreatContextAsync(List<IOC> iocs, List<MITRE> mitreTechniques, CancellationToken cancellationToken = default)
        {
            var iocSummary = string.Join("\n", iocs.Take(20).Select(i => $"- {i.Type}: {i.Value}"));
            var mitreSummary = string.Join("\n", mitreTechniques.Take(10).Select(m => $"- {m.TechniqueId}: {m.Name}"));

            var prompt = $@"Analyze the threat context based on these indicators and techniques:

Indicators of Compromise:
{iocSummary}

MITRE ATT&CK Techniques:
{mitreSummary}

Provide comprehensive threat context:
1. Likely threat actor profile or group
2. Campaign characteristics and objectives
3. Attack sophistication level
4. Target profile (industry, size, geography)
5. Estimated dwell time
6. Data exfiltration risk
7. Business impact assessment
8. Similar historical incidents

Connect the IOCs and techniques to paint a complete picture.";

            return await SendCompletionRequestAsync(prompt, cancellationToken);
        }

        public async Task<List<string>> GenerateYaraRulesAsync(List<IOC> iocs, string ruleName, CancellationToken cancellationToken = default)
        {
            var relevantIocs = iocs.Where(i => i.Confidence >= 70).Take(20).ToList();
            var iocDetails = string.Join("\n", relevantIocs.Select(i => $"{i.Type}: {i.Value} (Context: {i.Context})"));

            var prompt = $@"Generate YARA rules based on these high-confidence IOCs:

Rule Name: {ruleName}
IOCs:
{iocDetails}

Create 1-3 YARA rules that:
1. Detect files or network traffic containing these indicators
2. Use appropriate string matching and conditions
3. Include meaningful metadata
4. Follow YARA best practices
5. Optimize for low false positive rate

Format as valid YARA syntax with proper indentation.";

            var response = await SendCompletionRequestAsync(prompt, cancellationToken);
            return ParseYaraRules(response);
        }

        public async Task<long> GetTokenUsageAsync()
        {
            lock (_tokenLock)
            {
                return _totalTokensUsed;
            }
        }

        public async Task<double> EstimateCostAsync()
        {
            var tokens = await GetTokenUsageAsync();
            var costPer1kTokens = _configuration.GetValue<double>("OpenAI:CostPer1kTokens", 0.002);
            return (tokens / 1000.0) * costPer1kTokens;
        }

        // Private helper methods
        private async Task<string> SendCompletionRequestAsync(string prompt, CancellationToken cancellationToken, int? maxTokens = null)
        {
            await _rateLimiter.WaitAsync(cancellationToken);
            try
            {
                var requestBody = new
                {
                    model = _configuration["OpenAI:Model"] ?? "gpt-4",
                    messages = new[]
                    {
                        new { role = "system", content = "You are a senior digital forensics analyst specializing in cybersecurity incident response and threat analysis. Provide detailed, accurate, and actionable forensics insights." },
                        new { role = "user", content = prompt }
                    },
                    max_tokens = maxTokens ?? _maxTokens,
                    temperature = _temperature,
                    top_p = 0.9,
                    frequency_penalty = 0.0,
                    presence_penalty = 0.0
                };

                var json = JsonSerializer.Serialize(requestBody);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _retryPolicy.ExecuteAsync(async () =>
                    await _httpClient.PostAsync("/chat/completions", content, cancellationToken)
                );

                if (!response.IsSuccessStatusCode)
                {
                    var error = await response.Content.ReadAsStringAsync(cancellationToken);
                    _logger.LogError("OpenAI API error: {StatusCode} - {Error}", response.StatusCode, error);
                    throw new HttpRequestException($"OpenAI API request failed: {response.StatusCode}");
                }

                var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
                using var doc = JsonDocument.Parse(responseJson);
                
                var usage = doc.RootElement.GetProperty("usage");
                var tokensUsed = usage.GetProperty("total_tokens").GetInt32();
                
                lock (_tokenLock)
                {
                    _totalTokensUsed += tokensUsed;
                }

                var choices = doc.RootElement.GetProperty("choices");
                return choices[0].GetProperty("message").GetProperty("content").GetString();
            }
            finally
            {
                // Release rate limiter after a delay to respect rate limits
                _ = Task.Delay(TimeSpan.FromSeconds(3)).ContinueWith(_ => _rateLimiter.Release());
            }
        }

        private ThreatAssessment ParseThreatAssessment(string response, Guid analysisId)
        {
            var assessment = new ThreatAssessment
            {
                AnalysisId = analysisId,
                AssessmentDate = DateTime.UtcNow,
                RawAssessment = response
            };

            // Parse threat level
            if (response.Contains("Critical", StringComparison.OrdinalIgnoreCase))
                assessment.ThreatLevel = ThreatLevel.Critical;
            else if (response.Contains("High", StringComparison.OrdinalIgnoreCase))
                assessment.ThreatLevel = ThreatLevel.High;
            else if (response.Contains("Medium", StringComparison.OrdinalIgnoreCase))
                assessment.ThreatLevel = ThreatLevel.Medium;
            else
                assessment.ThreatLevel = ThreatLevel.Low;

            // Extract confidence level
            var confidenceMatch = System.Text.RegularExpressions.Regex.Match(response, @"(\d+)%?\s*confidence", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (confidenceMatch.Success && int.TryParse(confidenceMatch.Groups[1].Value, out var confidence))
            {
                assessment.ConfidenceLevel = confidence;
            }
            else
            {
                assessment.ConfidenceLevel = 75; // Default confidence
            }

            // Extract key sections
            assessment.ThreatActorProfile = ExtractSection(response, "threat actor profile", "Potential threat actor characteristics");
            assessment.BusinessImpact = ExtractSection(response, "business impact", "Potential business impact");
            assessment.RecommendedActions = ExtractSection(response, "recommended", "Immediate actions recommended");

            return assessment;
        }

        private List<IOC> ParseIOCResponse(string response)
        {
            var iocs = new List<IOC>();
            var lines = response.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            foreach (var line in lines)
            {
                var parts = line.Split('|');
                if (parts.Length >= 3)
                {
                    var ioc = new IOC
                    {
                        Id = Guid.NewGuid(),
                        Type = parts[0].Trim(),
                        Value = parts[1].Trim(),
                        Confidence = int.TryParse(parts[2].Trim(), out var conf) ? conf : 50,
                        Context = parts.Length > 3 ? parts[3].Trim() : null,
                        FirstSeen = DateTime.UtcNow,
                        LastSeen = DateTime.UtcNow,
                        CreatedAt = DateTime.UtcNow
                    };

                    if (!string.IsNullOrWhiteSpace(ioc.Value))
                    {
                        iocs.Add(ioc);
                    }
                }
            }

            return iocs;
        }

        private List<Anomaly> ParseAnomalyResponse(string response)
        {
            var anomalies = new List<Anomaly>();
            var sections = response.Split(new[] { "Type:", "Anomaly:" }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var section in sections.Skip(1))
            {
                var anomaly = new Anomaly
                {
                    Id = Guid.NewGuid(),
                    Description = section.Trim(),
                    DetectedAt = DateTime.UtcNow
                };

                // Extract severity
                if (section.Contains("Critical", StringComparison.OrdinalIgnoreCase))
                    anomaly.Severity = "Critical";
                else if (section.Contains("High", StringComparison.OrdinalIgnoreCase))
                    anomaly.Severity = "High";
                else if (section.Contains("Medium", StringComparison.OrdinalIgnoreCase))
                    anomaly.Severity = "Medium";
                else
                    anomaly.Severity = "Low";

                // Extract confidence
                var confMatch = System.Text.RegularExpressions.Regex.Match(section, @"(\d+)%?\s*confidence", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (confMatch.Success && int.TryParse(confMatch.Groups[1].Value, out var conf))
                {
                    anomaly.Confidence = conf;
                }
                else
                {
                    anomaly.Confidence = 70;
                }

                anomalies.Add(anomaly);
            }

            return anomalies;
        }

        private List<string> ParseRecommendations(string response)
        {
            var recommendations = new List<string>();
            var lines = response.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            foreach (var line in lines)
            {
                var cleaned = line.TrimStart('-', '*', '•', ' ', '\t');
                cleaned = System.Text.RegularExpressions.Regex.Replace(cleaned, @"^\d+\.\s*", "");
                
                if (!string.IsNullOrWhiteSpace(cleaned) && cleaned.Length > 10)
                {
                    recommendations.Add(cleaned);
                }
            }

            return recommendations.Take(7).ToList();
        }

        private List<string> ParseYaraRules(string response)
        {
            var rules = new List<string>();
            var rulePattern = @"rule\s+\w+\s*{[\s\S]*?}";
            var matches = System.Text.RegularExpressions.Regex.Matches(response, rulePattern);

            foreach (System.Text.RegularExpressions.Match match in matches)
            {
                rules.Add(match.Value);
            }

            return rules;
        }

        private string ExtractSection(string text, string sectionKeyword, string defaultContent)
        {
            var lines = text.Split('\n');
            var capturing = false;
            var content = new StringBuilder();

            foreach (var line in lines)
            {
                if (line.Contains(sectionKeyword, StringComparison.OrdinalIgnoreCase))
                {
                    capturing = true;
                    continue;
                }

                if (capturing && (line.Trim().EndsWith(":") || string.IsNullOrWhiteSpace(line)))
                {
                    break;
                }

                if (capturing)
                {
                    content.AppendLine(line);
                }
            }

            return content.Length > 0 ? content.ToString().Trim() : defaultContent;
        }
    }

    // Supporting classes
    public class ThreatAssessment
    {
        public Guid AnalysisId { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
        public int ConfidenceLevel { get; set; }
        public string ThreatActorProfile { get; set; }
        public string BusinessImpact { get; set; }
        public string RecommendedActions { get; set; }
        public string RawAssessment { get; set; }
        public DateTime AssessmentDate { get; set; }
    }

    public class Anomaly
    {
        public Guid Id { get; set; }
        public string Type { get; set; }
        public string Description { get; set; }
        public string Severity { get; set; }
        public int Confidence { get; set; }
        public string Location { get; set; }
        public DateTime DetectedAt { get; set; }
    }
}