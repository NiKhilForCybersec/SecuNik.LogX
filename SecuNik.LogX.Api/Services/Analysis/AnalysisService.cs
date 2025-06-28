using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Core.Entities;
using SecuNik.LogX.Core.DTOs;
using SecuNik.LogX.Api.Data;
using SecuNik.LogX.Api.Hubs;
using SecuNik.LogX.Api.Services.Parsers;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.SignalR;
using System.Text;
using AnalysisEntity = SecuNik.LogX.Core.Entities.Analysis;

namespace SecuNik.LogX.Api.Services.Analysis
{
    public class AnalysisService : IAnalysisService
    {
        private readonly LogXDbContext _dbContext;
        private readonly IStorageService _storageService;
        private readonly IRuleEngine _ruleEngine;
        private readonly ParserFactory _parserFactory;
        private readonly IHubContext<AnalysisHub> _hubContext;
        private readonly ILogger<AnalysisService> _logger;

        public AnalysisService(
            LogXDbContext dbContext,
            IStorageService storageService,
            IRuleEngine ruleEngine,
            ParserFactory parserFactory,
            IHubContext<AnalysisHub> hubContext,
            ILogger<AnalysisService> logger)
        {
            _dbContext = dbContext;
            _storageService = storageService;
            _ruleEngine = ruleEngine;
            _parserFactory = parserFactory;
            _hubContext = hubContext;
            _logger = logger;
        }

       public async Task<SecuNik.LogX.Core.Entities.Analysis> StartAnalysisAsync(Guid uploadId, AnalysisOptions options, CancellationToken cancellationToken = default)
        {
            try
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

                // Get upload files
                var files = await _storageService.ListAnalysisFilesAsync(uploadId, cancellationToken);
                if (files.Count == 0)
                {
                    throw new InvalidOperationException($"No files found for upload {uploadId}");
                }

                // Use the first file for now (in a real implementation, we'd handle multiple files)
                var fileName = files[0];
                var filePath = Path.Combine(_storageService.GetAnalysisPath(uploadId), fileName);

                // Update analysis with file info
                analysis.FileName = fileName;
                analysis.FileSize = new FileInfo(filePath).Length;
                analysis.FileType = Path.GetExtension(fileName).TrimStart('.').ToUpper();

                // Calculate file hash
                using (var stream = await _storageService.GetFileAsync(uploadId, fileName, cancellationToken))
                {
                    using (var ms = new MemoryStream())
                    {
                        await stream.CopyToAsync(ms, cancellationToken);
                        ms.Position = 0;
                        using (var sha256 = System.Security.Cryptography.SHA256.Create())
                        {
                            var hashBytes = await sha256.ComputeHashAsync(ms, cancellationToken);
                            analysis.FileHash = Convert.ToHexString(hashBytes).ToLowerInvariant();
                        }

                        // Read file content for parsing
                        ms.Position = 0;
                        using (var reader = new StreamReader(ms))
                        {
                            var content = await reader.ReadToEndAsync(cancellationToken);

                            // Find suitable parser
                            var parser = await _parserFactory.GetParserAsync(fileName, content, options.PreferredParserId);
                            if (parser != null)
                            {
                                analysis.ParserId = parser.GetType().GUID;
                                
                                // Send progress update
                                await SendProgressUpdateAsync(analysis.Id, 10, "Parser selected");

                                // Parse file
                                var parseResult = await parser.ParseAsync(fileName, content, cancellationToken);
                                if (parseResult.Success)
                                {
                                    // Store parsed data
                                    analysis.ParsedDataJson = System.Text.Json.JsonSerializer.Serialize(parseResult.Events);
                                    
                                    // Send progress update
                                    await SendProgressUpdateAsync(analysis.Id, 30, "File parsed successfully");

                                    // Run rules against parsed data
                                    var ruleMatches = await _ruleEngine.ProcessAsync(
                                        analysis.Id, 
                                        parseResult.Events, 
                                        content, 
                                        cancellationToken);

                                    // Store rule matches
                                    foreach (var match in ruleMatches)
                                    {
                                        var ruleMatch = new RuleMatch
                                        {
                                            AnalysisId = analysis.Id,
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
                                    }

                                    // Send progress update
                                    await SendProgressUpdateAsync(analysis.Id, 70, "Rule analysis completed");

                                    // Calculate threat score based on rule matches
                                    analysis.ThreatScore = CalculateThreatScore(analysis.RuleMatches);
                                    analysis.Severity = GetSeverityFromScore(analysis.ThreatScore);

                                    // Generate summary
                                    analysis.Summary = GenerateSummary(analysis, parseResult.Events, ruleMatches);
                                }
                                else
                                {
                                    analysis.Status = "failed";
                                    analysis.ErrorMessage = parseResult.ErrorMessage;
                                    _logger.LogError("Parsing failed for {FileName}: {ErrorMessage}", 
                                        fileName, parseResult.ErrorMessage);
                                }
                            }
                            else
                            {
                                analysis.Status = "failed";
                                analysis.ErrorMessage = "No suitable parser found for this file type";
                                _logger.LogError("No suitable parser found for {FileName}", fileName);
                            }
                        }
                    }
                }

                // Complete analysis
                if (analysis.Status != "failed")
                {
                    analysis.Status = "completed";
                    analysis.Progress = 100;
                    analysis.CompletionTime = DateTime.UtcNow;
                }

                // Save to database
                _dbContext.Analyses.Add(analysis);
                await _dbContext.SaveChangesAsync(cancellationToken);

                // Send completion notification
                await SendAnalysisCompletedAsync(analysis);

                return analysis;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during analysis for upload {UploadId}", uploadId);
                throw;
            }
        }

        public async Task<SecuNik.LogX.Core.Entities.Analysis?> GetAnalysisAsync(Guid analysisId, CancellationToken cancellationToken = default)
        {
            return await _dbContext.Analyses
                .Include(a => a.RuleMatches)
                .Include(a => a.Parser)
                .FirstOrDefaultAsync(a => a.Id == analysisId, cancellationToken);
        }

        public async Task<List<SecuNik.LogX.Core.Entities.Analysis>> GetRecentAnalysesAsync(int limit = 10, CancellationToken cancellationToken = default)
        {
            return await _dbContext.Analyses
                .OrderByDescending(a => a.UploadTime)
                .Take(limit)
                .ToListAsync(cancellationToken);
        }

        public async Task<bool> CancelAnalysisAsync(Guid analysisId, CancellationToken cancellationToken = default)
        {
            var analysis = await _dbContext.Analyses.FindAsync(new object[] { analysisId }, cancellationToken);
            if (analysis == null)
            {
                return false;
            }

            if (analysis.Status == "processing" || analysis.Status == "queued")
            {
                analysis.Status = "cancelled";
                analysis.CompletionTime = DateTime.UtcNow;
                await _dbContext.SaveChangesAsync(cancellationToken);
                
                await SendProgressUpdateAsync(analysisId, analysis.Progress, "Analysis cancelled");
                
                return true;
            }

            return false;
        }

        public async Task<bool> DeleteAnalysisAsync(Guid analysisId, CancellationToken cancellationToken = default)
        {
            var analysis = await _dbContext.Analyses.FindAsync(new object[] { analysisId }, cancellationToken);
            if (analysis == null)
            {
                return false;
            }

            _dbContext.Analyses.Remove(analysis);
            await _dbContext.SaveChangesAsync(cancellationToken);

            // Delete associated files
            await _storageService.DeleteAnalysisDirectoryAsync(analysisId, cancellationToken);

            return true;
        }

        private async Task SendProgressUpdateAsync(Guid analysisId, int progress, string message)
        {
            await AnalysisHub.SendAnalysisProgress(_hubContext, analysisId.ToString(), progress, message);
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

        private int CalculateThreatScore(ICollection<RuleMatch> ruleMatches)
        {
            if (ruleMatches.Count == 0)
            {
                return 0;
            }

            // Calculate based on severity and match count
            int score = 0;
            int totalMatches = 0;

            foreach (var match in ruleMatches)
            {
                int severityScore = match.Severity switch
                {
                    ThreatLevel.Critical => 100,
                    ThreatLevel.High => 75,
                    ThreatLevel.Medium => 50,
                    ThreatLevel.Low => 25,
                    _ => 10
                };

                // Weight by match count and confidence
                score += (int)(severityScore * match.MatchCount * match.Confidence);
                totalMatches += match.MatchCount;
            }

            // Normalize to 0-100 scale
            return Math.Min(100, score / Math.Max(1, totalMatches));
        }

        private string GetSeverityFromScore(int score)
        {
            if (score >= 80) return "critical";
            if (score >= 60) return "high";
            if (score >= 30) return "medium";
            return "low";
        }

        private string GenerateSummary(AnalysisEntity analysis, List<LogEvent> events, List<RuleMatchResult> ruleMatches)
        {
            var summary = new StringBuilder();

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

            return summary.ToString();
        }
    }
}



