using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Core.Entities;
using SecuNik.LogX.Core.DTOs; // Add this for IOCDto
using SecuNik.LogX.Api.Data;
using SecuNik.LogX.Api.Services.Parsers; // Add this for ParserFactory
using Microsoft.EntityFrameworkCore;

// IMPORTANT: Add this alias to avoid namespace collision
using AnalysisEntity = SecuNik.LogX.Core.Entities.Analysis;
using SecuNik.LogX.Api.Hubs;
using Microsoft.AspNetCore.SignalR;
using System.Text.Json;

namespace SecuNik.LogX.Api.Services.Analysis
{
    public class AnalysisOrchestrator
    {
        private readonly LogXDbContext _dbContext;
        private readonly IStorageService _storageService;
        private readonly ParserFactory _parserFactory;
        private readonly IRuleEngine _ruleEngine;
        private readonly TimelineBuilder _timelineBuilder;
        private readonly IOCExtractor _iocExtractor;
        private readonly ThreatScoringService _threatScoringService;
        private readonly MitreMapperService _mitreMapperService;
        private readonly AIAnalyzerService _aiAnalyzerService;
        private readonly IHubContext<AnalysisHub> _hubContext;
        private readonly ILogger<AnalysisOrchestrator> _logger;
        
        public AnalysisOrchestrator(
            LogXDbContext dbContext,
            IStorageService storageService,
            ParserFactory parserFactory,
            IRuleEngine ruleEngine,
            TimelineBuilder timelineBuilder,
            IOCExtractor iocExtractor,
            ThreatScoringService threatScoringService,
            MitreMapperService mitreMapperService,
            AIAnalyzerService aiAnalyzerService,
            IHubContext<AnalysisHub> hubContext,
            ILogger<AnalysisOrchestrator> logger)
        {
            _dbContext = dbContext;
            _storageService = storageService;
            _parserFactory = parserFactory;
            _ruleEngine = ruleEngine;
            _timelineBuilder = timelineBuilder;
            _iocExtractor = iocExtractor;
            _threatScoringService = threatScoringService;
            _mitreMapperService = mitreMapperService;
            _aiAnalyzerService = aiAnalyzerService;
            _hubContext = hubContext;
            _logger = logger;
        }
        
        public async Task<AnalysisEntity> StartAnalysisAsync(
            Guid uploadId, 
            AnalysisOptions options, 
            CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Starting analysis for upload {UploadId}", uploadId);
            
            // Create analysis record
            var analysis = new AnalysisEntity
            {
                Id = Guid.NewGuid(),
                UploadTime = DateTime.UtcNow,
                StartTime = DateTime.UtcNow,
                Status = "processing",
                Progress = 0
            };
            
            try
            {
                // Get upload files
                var files = await _storageService.ListAnalysisFilesAsync(uploadId, cancellationToken);
                if (files.Count == 0)
                {
                    throw new InvalidOperationException($"No files found for upload {uploadId}");
                }
                
                // Use the first file for now (in a real implementation, we'd handle multiple files)
                var fileName = files[0];
                
                // Update analysis with file info
                analysis.FileName = fileName;
                
                // Save initial analysis record
                _dbContext.Analyses.Add(analysis);
                await _dbContext.SaveChangesAsync(cancellationToken);
                
                // Start analysis in background
                _ = Task.Run(() => ProcessAnalysisAsync(analysis.Id, uploadId, fileName, options), CancellationToken.None);
                
                return analysis;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error starting analysis for upload {UploadId}", uploadId);
                
                // Update analysis status
                analysis.Status = "failed";
                analysis.ErrorMessage = ex.Message;
                analysis.CompletionTime = DateTime.UtcNow;
                
                if (_dbContext.Entry(analysis).State == Microsoft.EntityFrameworkCore.EntityState.Detached)
                {
                    _dbContext.Analyses.Add(analysis);
                }
                
                await _dbContext.SaveChangesAsync(cancellationToken);
                
                throw;
            }
        }
        
        private async Task ProcessAnalysisAsync(
            Guid analysisId, 
            Guid uploadId, 
            string fileName, 
            AnalysisOptions options)
        {
            using var scope = new CancellationTokenSource(TimeSpan.FromMinutes(options.TimeoutMinutes));
            var cancellationToken = scope.Token;
            
            try
            {
                _logger.LogInformation("Processing analysis {AnalysisId} for file {FileName}", analysisId, fileName);
                
                // Get analysis from database
                var analysis = await _dbContext.Analyses.FindAsync(new object[] { analysisId }, cancellationToken);
                if (analysis == null)
                {
                    _logger.LogError("Analysis {AnalysisId} not found in database", analysisId);
                    return;
                }
                
                // Send progress update
                await SendProgressUpdateAsync(analysisId, 5, "Starting analysis");
                
                // Get file content
                using var fileStream = await _storageService.GetFileAsync(uploadId, fileName, cancellationToken);
                using var reader = new StreamReader(fileStream);
                var content = await reader.ReadToEndAsync(cancellationToken);
                
                // Update file info
                analysis.FileSize = content.Length;
                analysis.FileType = Path.GetExtension(fileName).TrimStart('.').ToUpper();
                
                // Calculate file hash
                using (var ms = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(content)))
                {
                    using var sha256 = System.Security.Cryptography.SHA256.Create();
                    var hashBytes = await sha256.ComputeHashAsync(ms, cancellationToken);
                    analysis.FileHash = Convert.ToHexString(hashBytes).ToLowerInvariant();
                }
                
                await _dbContext.SaveChangesAsync(cancellationToken);
                
                // Send progress update
                await SendProgressUpdateAsync(analysisId, 10, "File loaded");
                
                // Find suitable parser
                var parser = await _parserFactory.GetParserAsync(fileName, content, options.PreferredParserId);
                if (parser == null)
                {
                    throw new InvalidOperationException("No suitable parser found for this file type");
                }
                
                // Update parser info
                analysis.ParserId = parser.GetType().GUID;
                await _dbContext.SaveChangesAsync(cancellationToken);
                
                // Send progress update
                await SendProgressUpdateAsync(analysisId, 15, "Parser selected");
                
                // Parse file
                var parseResult = await parser.ParseAsync(fileName, content, cancellationToken);
                if (!parseResult.Success)
                {
                    throw new InvalidOperationException($"Parsing failed: {parseResult.ErrorMessage}");
                }
                
                // Limit events if needed
                var events = parseResult.Events;
                if (options.MaxEvents > 0 && events.Count > options.MaxEvents)
                {
                    _logger.LogWarning("Limiting events from {TotalEvents} to {MaxEvents}", 
                        events.Count, options.MaxEvents);
                    events = events.Take(options.MaxEvents).ToList();
                }
                
                // Store parsed data
                analysis.ParsedDataJson = JsonSerializer.Serialize(events);
                await _dbContext.SaveChangesAsync(cancellationToken);
                
                // Send progress update
                await SendProgressUpdateAsync(analysisId, 30, "File parsed successfully");
                
                // Run rules against parsed data
                var ruleMatches = await _ruleEngine.ProcessAsync(analysisId, events, content, cancellationToken);
                
                // Store rule matches
                foreach (var match in ruleMatches)
                {
                    var ruleMatch = new RuleMatch
                    {
                        AnalysisId = analysisId,
                        RuleId = match.RuleId,
                        RuleName = match.RuleName,
                        RuleType = match.RuleType,
                        Severity = match.Severity,
                        MatchCount = match.MatchCount,
                        Confidence = match.Confidence,
                        MatchedAt = DateTime.UtcNow
                    };
                    
                    if (match.Matches.Count > 0)
                    {
                        var firstMatch = match.Matches[0];
                        ruleMatch.MatchedContent = firstMatch.MatchedContent;
                        ruleMatch.FileOffset = firstMatch.FileOffset;
                        ruleMatch.LineNumber = firstMatch.LineNumber;
                        ruleMatch.Context = firstMatch.Context;
                    }
                    
                    if (match.MitreAttackIds.Count > 0)
                    {
                        ruleMatch.SetMitreAttackIds(match.MitreAttackIds);
                    }
                    
                    analysis.RuleMatches.Add(ruleMatch);
                    
                    // Send rule match notification
                    await SendRuleMatchAsync(analysisId, match);
                }
                
                await _dbContext.SaveChangesAsync(cancellationToken);
                
                // Send progress update
                await SendProgressUpdateAsync(analysisId, 50, "Rule analysis completed");
                
                // Extract IOCs
                List<IOCDto> iocs = new List<IOCDto>();
                if (options.ExtractIOCs)
                {
                    iocs = await _iocExtractor.ExtractIOCsAsync(events, content, cancellationToken);
                    analysis.IOCsJson = JsonSerializer.Serialize(iocs);
                    await _dbContext.SaveChangesAsync(cancellationToken);
                    
                    // Send progress update
                    await SendProgressUpdateAsync(analysisId, 60, "IOCs extracted");
                    
                    // Send IOC notifications
                    foreach (var ioc in iocs)
                    {
                        await SendIOCFoundAsync(analysisId, ioc);
                    }
                }
                
                // Build timeline
                var timeline = await _timelineBuilder.BuildTimelineAsync(events, ruleMatches, cancellationToken);
                analysis.TimelineJson = JsonSerializer.Serialize(timeline);
                await _dbContext.SaveChangesAsync(cancellationToken);
                
                // Send progress update
                await SendProgressUpdateAsync(analysisId, 70, "Timeline built");
                
                // Map to MITRE ATT&CK
                if (options.MapToMitre)
                {
                    var mitreResults = await _mitreMapperService.MapToMitreAsync(ruleMatches, cancellationToken);
                    analysis.MitreResultsJson = JsonSerializer.Serialize(mitreResults);
                    await _dbContext.SaveChangesAsync(cancellationToken);
                    
                    // Send progress update
                    await SendProgressUpdateAsync(analysisId, 80, "MITRE ATT&CK mapping completed");
                }
                
                // Run AI analysis
                if (options.EnableAI)
                {
                    var aiInsights = await _aiAnalyzerService.AnalyzeAsync(
                        events, 
                        ruleMatches, 
                        iocs.Select(i => new IOC 
                        { 
                            Value = i.Value, 
                            Type = MapIOCType(i.Type),
                            Context = i.Context
                        }).ToList(),
                        cancellationToken);
                    
                    analysis.AISummary = JsonSerializer.Serialize(aiInsights);
                    await _dbContext.SaveChangesAsync(cancellationToken);
                    
                    // Send progress update
                    await SendProgressUpdateAsync(analysisId, 90, "AI analysis completed");
                }
                
                // Calculate threat score
                analysis.ThreatScore = _threatScoringService.CalculateThreatScore(
                    ruleMatches,
                    iocs.Select(i => new IOC 
                    { 
                        Value = i.Value, 
                        Type = MapIOCType(i.Type),
                        IsMalicious = i.IsMalicious
                    }).ToList());
                
                analysis.Severity = _threatScoringService.GetSeverityFromScore(analysis.ThreatScore);
                
                // Generate summary
                analysis.Summary = GenerateSummary(analysis, events, ruleMatches, iocs);
                
                // Complete analysis
                analysis.Status = "completed";
                analysis.Progress = 100;
                analysis.CompletionTime = DateTime.UtcNow;
                
                await _dbContext.SaveChangesAsync(cancellationToken);
                
                // Send completion notification
                await SendAnalysisCompletedAsync(analysis);
                
                _logger.LogInformation("Analysis {AnalysisId} completed successfully", analysisId);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Analysis {AnalysisId} was cancelled or timed out", analysisId);
                
                // Update analysis status
                var analysis = await _dbContext.Analyses.FindAsync(new object[] { analysisId });
                if (analysis != null)
                {
                    analysis.Status = "failed";
                    analysis.ErrorMessage = "Analysis was cancelled or timed out";
                    analysis.CompletionTime = DateTime.UtcNow;
                    await _dbContext.SaveChangesAsync();
                    
                    // Send error notification
                    await SendAnalysisErrorAsync(analysisId, "Analysis was cancelled or timed out");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing analysis {AnalysisId}", analysisId);
                
                // Update analysis status
                var analysis = await _dbContext.Analyses.FindAsync(new object[] { analysisId });
                if (analysis != null)
                {
                    analysis.Status = "failed";
                    analysis.ErrorMessage = ex.Message;
                    analysis.CompletionTime = DateTime.UtcNow;
                    await _dbContext.SaveChangesAsync();
                    
                    // Send error notification
                    await SendAnalysisErrorAsync(analysisId, ex.Message);
                }
            }
        }
        
        private async Task SendProgressUpdateAsync(Guid analysisId, int progress, string message)
        {
            await AnalysisHub.SendAnalysisProgress(_hubContext, analysisId.ToString(), progress, message);
            
            // Also update in database
            var analysis = await _dbContext.Analyses.FindAsync(new object[] { analysisId });
            if (analysis != null)
            {
                analysis.Progress = progress;
                await _dbContext.SaveChangesAsync();
            }
        }
        
        private async Task SendAnalysisCompletedAsync(AnalysisEntity analysis)
        {
            var result = new
            {
                analysis_id = analysis.Id,
                file_name = analysis.FileName,
                file_hash = analysis.FileHash,
                status = analysis.Status,
                threat_score = analysis.ThreatScore,
                severity = analysis.Severity,
                completion_time = analysis.CompletionTime,
                rule_matches = analysis.RuleMatches.Count
            };
            
            await AnalysisHub.SendAnalysisCompleted(_hubContext, analysis.Id.ToString(), result);
        }
        
        private async Task SendAnalysisErrorAsync(Guid analysisId, string errorMessage)
        {
            await AnalysisHub.SendAnalysisError(_hubContext, analysisId.ToString(), errorMessage);
        }
        
        private async Task SendRuleMatchAsync(Guid analysisId, RuleMatchResult match)
        {
            await AnalysisHub.SendRuleMatch(_hubContext, analysisId.ToString(), new
            {
                rule_id = match.RuleId,
                rule_name = match.RuleName,
                rule_type = match.RuleType.ToString(),
                severity = match.Severity.ToString(),
                match_count = match.MatchCount,
                confidence = match.Confidence,
                mitre_attack_ids = match.MitreAttackIds
            });
        }
        
        private async Task SendIOCFoundAsync(Guid analysisId, IOCDto ioc)
        {
            await AnalysisHub.SendIOCFound(_hubContext, analysisId.ToString(), ioc);
        }
        
        private string GenerateSummary(
            AnalysisEntity analysis, 
            List<LogEvent> events, 
            List<RuleMatchResult> ruleMatches,
            List<IOCDto> iocs)
        {
            var summary = new System.Text.StringBuilder();
            
            summary.AppendLine($"Analysis of {analysis.FileName} completed.");
            summary.AppendLine($"File size: {analysis.FileSize} bytes");
            summary.AppendLine($"File hash: {analysis.FileHash}");
            summary.AppendLine();
            
            summary.AppendLine($"Parsed {events.Count} events.");
            
            if (ruleMatches.Count > 0)
            {
                summary.AppendLine($"Found {ruleMatches.Count} rule matches:");
                
                var criticalMatches = ruleMatches.Where(m => m.Severity == ThreatLevel.Critical).ToList();
                var highMatches = ruleMatches.Where(m => m.Severity == ThreatLevel.High).ToList();
                var mediumMatches = ruleMatches.Where(m => m.Severity == ThreatLevel.Medium).ToList();
                
                if (criticalMatches.Count > 0)
                {
                    summary.AppendLine($"- {criticalMatches.Count} critical severity matches");
                }
                
                if (highMatches.Count > 0)
                {
                    summary.AppendLine($"- {highMatches.Count} high severity matches");
                }
                
                if (mediumMatches.Count > 0)
                {
                    summary.AppendLine($"- {mediumMatches.Count} medium severity matches");
                }
            }
            else
            {
                summary.AppendLine("No rule matches found.");
            }
            
            if (iocs.Count > 0)
            {
                summary.AppendLine($"Extracted {iocs.Count} indicators of compromise (IOCs).");
                
                var ipCount = iocs.Count(i => i.Type == "ip");
                var domainCount = iocs.Count(i => i.Type == "domain");
                var hashCount = iocs.Count(i => i.Type == "hash");
                var urlCount = iocs.Count(i => i.Type == "url");
                
                if (ipCount > 0) summary.AppendLine($"- {ipCount} IP addresses");
                if (domainCount > 0) summary.AppendLine($"- {domainCount} domains");
                if (hashCount > 0) summary.AppendLine($"- {hashCount} file hashes");
                if (urlCount > 0) summary.AppendLine($"- {urlCount} URLs");
            }
            else
            {
                summary.AppendLine("No indicators of compromise found.");
            }
            
            summary.AppendLine();
            summary.AppendLine($"Threat score: {analysis.ThreatScore}/100");
            summary.AppendLine($"Severity: {analysis.Severity.ToUpperInvariant()}");
            
            return summary.ToString();
        }
        
        private IOCType MapIOCType(string type)
        {
            return type.ToLowerInvariant() switch
            {
                "ip" => IOCType.IPAddress,
                "domain" => IOCType.Domain,
                "url" => IOCType.URL,
                "hash" => IOCType.FileHash,
                "email" => IOCType.Email,
                "file_path" => IOCType.FilePath,
                "registry_key" => IOCType.RegistryKey,
                "mutex" => IOCType.Mutex,
                _ => IOCType.Other
            };
        }
    }
    
    public class AnalysisOptions
    {
        public Guid? PreferredParserId { get; set; }
        public bool DeepScan { get; set; } = true;
        public bool ExtractIOCs { get; set; } = true;
        public bool CheckVirusTotal { get; set; } = false;
        public bool EnableAI { get; set; } = false;
        public bool MapToMitre { get; set; } = true;
        public int MaxEvents { get; set; } = 100000;
        public int TimeoutMinutes { get; set; } = 30;
        public List<string>? IncludeRuleTypes { get; set; }
        public List<string>? ExcludeRuleCategories { get; set; }
        public Dictionary<string, object>? CustomOptions { get; set; }
    }
}