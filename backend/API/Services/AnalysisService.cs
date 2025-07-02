using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.SignalR;
using SecuNik.LogX.Domain.Entities;
using SecuNik.LogX.Domain.Services;
using SecuNik.LogX.Domain.Enums;
using SecuNik.LogX.Infrastructure.Data;
using SecuNik.LogX.API.Hubs;

namespace SecuNik.LogX.API.Services
{
    public class AnalysisService : IAnalysisService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<AnalysisService> _logger;
        private readonly IConfiguration _configuration;
        private readonly IMemoryCache _cache;
        private readonly IHubContext<AnalysisHub> _hubContext;
        private readonly IOCExtractor _iocExtractor;
        private readonly MITREMapper _mitreMapper;
        private readonly AIService _aiService;
        private readonly ConcurrentDictionary<Guid, AnalysisProgress> _progressTracking;
        private readonly SemaphoreSlim _analysisLock;

        public AnalysisService(
            ApplicationDbContext context,
            ILogger<AnalysisService> logger,
            IConfiguration configuration,
            IMemoryCache cache,
            IHubContext<AnalysisHub> hubContext,
            IOCExtractor iocExtractor,
            MITREMapper mitreMapper,
            AIService aiService)
        {
            _context = context;
            _logger = logger;
            _configuration = configuration;
            _cache = cache;
            _hubContext = hubContext;
            _iocExtractor = iocExtractor;
            _mitreMapper = mitreMapper;
            _aiService = aiService;
            _progressTracking = new ConcurrentDictionary<Guid, AnalysisProgress>();
            _analysisLock = new SemaphoreSlim(5); // Limit concurrent analyses
        }

        public async Task<Analysis> AnalyzeFileAsync(string filePath, Guid parserId, CancellationToken cancellationToken = default)
        {
            await _analysisLock.WaitAsync(cancellationToken);
            try
            {
                _logger.LogInformation("Starting file analysis for: {FilePath}", filePath);

                if (!File.Exists(filePath))
                    throw new FileNotFoundException($"File not found: {filePath}");

                var fileInfo = new FileInfo(filePath);
                var analysis = new Analysis
                {
                    Id = Guid.NewGuid(),
                    Name = $"Analysis_{fileInfo.Name}_{DateTime.UtcNow:yyyyMMddHHmmss}",
                    Description = $"Automated analysis of {fileInfo.Name}",
                    SourceFile = filePath,
                    FileSize = fileInfo.Length,
                    FileHash = await CalculateFileHashAsync(filePath),
                    Status = AnalysisStatus.Queued,
                    StartTime = DateTime.UtcNow,
                    ParserId = parserId,
                    CreatedAt = DateTime.UtcNow,
                    CreatedBy = "System",
                    UpdatedAt = DateTime.UtcNow,
                    UpdatedBy = "System"
                };

                _context.Analyses.Add(analysis);
                await _context.SaveChangesAsync(cancellationToken);

                _progressTracking.TryAdd(analysis.Id, new AnalysisProgress
                {
                    AnalysisId = analysis.Id,
                    Progress = 0,
                    Status = AnalysisStatus.Queued,
                    CurrentPhase = "Initialization"
                });

                // Start analysis in background
                _ = Task.Run(async () => await ExecuteAnalysisAsync(analysis.Id, cancellationToken), cancellationToken);

                return analysis;
            }
            finally
            {
                _analysisLock.Release();
            }
        }

        public async Task<IEnumerable<Analysis>> BatchAnalyzeAsync(IEnumerable<string> filePaths, Guid parserId, CancellationToken cancellationToken = default)
        {
            var analyses = new List<Analysis>();
            var batchId = Guid.NewGuid();

            foreach (var filePath in filePaths)
            {
                try
                {
                    var analysis = await AnalyzeFileAsync(filePath, parserId, cancellationToken);
                    analysis.BatchId = batchId;
                    analyses.Add(analysis);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to analyze file in batch: {FilePath}", filePath);
                }
            }

            return analyses;
        }

        public async Task<Analysis> ReanalyzeAsync(Guid analysisId, CancellationToken cancellationToken = default)
        {
            var originalAnalysis = await _context.Analyses
                .Include(a => a.IOCs)
                .Include(a => a.Rules)
                .Include(a => a.MITRE)
                .FirstOrDefaultAsync(a => a.Id == analysisId, cancellationToken);

            if (originalAnalysis == null)
                throw new InvalidOperationException($"Analysis not found: {analysisId}");

            var newAnalysis = new Analysis
            {
                Id = Guid.NewGuid(),
                Name = $"{originalAnalysis.Name}_Reanalysis_{DateTime.UtcNow:yyyyMMddHHmmss}",
                Description = $"Reanalysis of {originalAnalysis.Name}",
                SourceFile = originalAnalysis.SourceFile,
                FileSize = originalAnalysis.FileSize,
                FileHash = originalAnalysis.FileHash,
                Status = AnalysisStatus.Queued,
                StartTime = DateTime.UtcNow,
                ParserId = originalAnalysis.ParserId,
                ParentAnalysisId = originalAnalysis.Id,
                CreatedAt = DateTime.UtcNow,
                CreatedBy = "System",
                UpdatedAt = DateTime.UtcNow,
                UpdatedBy = "System"
            };

            _context.Analyses.Add(newAnalysis);
            await _context.SaveChangesAsync(cancellationToken);

            _ = Task.Run(async () => await ExecuteAnalysisAsync(newAnalysis.Id, cancellationToken), cancellationToken);

            return newAnalysis;
        }

        public async Task<Analysis> CreateAnalysisAsync(Analysis analysis, CancellationToken cancellationToken = default)
        {
            analysis.Id = Guid.NewGuid();
            analysis.CreatedAt = DateTime.UtcNow;
            analysis.UpdatedAt = DateTime.UtcNow;
            analysis.Status = AnalysisStatus.Queued;

            _context.Analyses.Add(analysis);
            await _context.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Created analysis: {AnalysisId}", analysis.Id);
            return analysis;
        }

        public async Task<Analysis> GetAnalysisAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var cacheKey = $"analysis_{id}";
            if (_cache.TryGetValue<Analysis>(cacheKey, out var cached))
                return cached;

            var analysis = await _context.Analyses
                .Include(a => a.IOCs)
                .Include(a => a.Rules)
                .Include(a => a.MITRE)
                .Include(a => a.Parser)
                .FirstOrDefaultAsync(a => a.Id == id, cancellationToken);

            if (analysis != null)
            {
                _cache.Set(cacheKey, analysis, TimeSpan.FromMinutes(5));
            }

            return analysis;
        }

        public async Task<Analysis> UpdateAnalysisAsync(Guid id, Analysis analysis, CancellationToken cancellationToken = default)
        {
            var existing = await _context.Analyses.FindAsync(new object[] { id }, cancellationToken);
            if (existing == null)
                throw new InvalidOperationException($"Analysis not found: {id}");

            existing.Name = analysis.Name;
            existing.Description = analysis.Description;
            existing.ThreatLevel = analysis.ThreatLevel;
            existing.Findings = analysis.Findings;
            existing.UpdatedAt = DateTime.UtcNow;
            existing.UpdatedBy = analysis.UpdatedBy;

            await _context.SaveChangesAsync(cancellationToken);

            _cache.Remove($"analysis_{id}");
            return existing;
        }

        public async Task<bool> DeleteAnalysisAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var analysis = await _context.Analyses.FindAsync(new object[] { id }, cancellationToken);
            if (analysis == null)
                return false;

            _context.Analyses.Remove(analysis);
            await _context.SaveChangesAsync(cancellationToken);

            _cache.Remove($"analysis_{id}");
            _progressTracking.TryRemove(id, out _);

            return true;
        }

        public async Task<IEnumerable<Analysis>> GetAllAnalysesAsync(CancellationToken cancellationToken = default)
        {
            return await _context.Analyses
                .Include(a => a.Parser)
                .OrderByDescending(a => a.CreatedAt)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<Analysis>> GetAnalysesByDateRangeAsync(DateTime startDate, DateTime endDate, CancellationToken cancellationToken = default)
        {
            return await _context.Analyses
                .Include(a => a.Parser)
                .Where(a => a.CreatedAt >= startDate && a.CreatedAt <= endDate)
                .OrderByDescending(a => a.CreatedAt)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<Analysis>> GetAnalysesByThreatLevelAsync(ThreatLevel threatLevel, CancellationToken cancellationToken = default)
        {
            return await _context.Analyses
                .Include(a => a.Parser)
                .Include(a => a.IOCs)
                .Where(a => a.ThreatLevel == threatLevel)
                .OrderByDescending(a => a.CreatedAt)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<Analysis>> SearchAnalysesAsync(string searchTerm, CancellationToken cancellationToken = default)
        {
            var normalizedSearch = searchTerm.ToLower();
            
            return await _context.Analyses
                .Include(a => a.Parser)
                .Include(a => a.IOCs)
                .Where(a => a.Name.ToLower().Contains(normalizedSearch) ||
                           a.Description.ToLower().Contains(normalizedSearch) ||
                           a.Findings.ToLower().Contains(normalizedSearch) ||
                           a.SourceFile.ToLower().Contains(normalizedSearch))
                .OrderByDescending(a => a.CreatedAt)
                .ToListAsync(cancellationToken);
        }

        public async Task<bool> StartAnalysisAsync(Guid analysisId, CancellationToken cancellationToken = default)
        {
            var analysis = await _context.Analyses.FindAsync(new object[] { analysisId }, cancellationToken);
            if (analysis == null)
                return false;

            if (analysis.Status != AnalysisStatus.Queued && analysis.Status != AnalysisStatus.Paused)
                return false;

            analysis.Status = AnalysisStatus.Running;
            analysis.StartTime = DateTime.UtcNow;
            await _context.SaveChangesAsync(cancellationToken);

            _ = Task.Run(async () => await ExecuteAnalysisAsync(analysisId, cancellationToken), cancellationToken);

            return true;
        }

        public async Task<bool> PauseAnalysisAsync(Guid analysisId, CancellationToken cancellationToken = default)
        {
            var analysis = await _context.Analyses.FindAsync(new object[] { analysisId }, cancellationToken);
            if (analysis == null || analysis.Status != AnalysisStatus.Running)
                return false;

            analysis.Status = AnalysisStatus.Paused;
            await _context.SaveChangesAsync(cancellationToken);

            if (_progressTracking.TryGetValue(analysisId, out var progress))
            {
                progress.Status = AnalysisStatus.Paused;
            }

            return true;
        }

        public async Task<bool> StopAnalysisAsync(Guid analysisId, CancellationToken cancellationToken = default)
        {
            var analysis = await _context.Analyses.FindAsync(new object[] { analysisId }, cancellationToken);
            if (analysis == null)
                return false;

            analysis.Status = AnalysisStatus.Completed;
            analysis.EndTime = DateTime.UtcNow;
            await _context.SaveChangesAsync(cancellationToken);

            _progressTracking.TryRemove(analysisId, out _);

            return true;
        }

        public async Task<AnalysisProgress> GetProgressAsync(Guid analysisId, CancellationToken cancellationToken = default)
        {
            if (_progressTracking.TryGetValue(analysisId, out var progress))
                return progress;

            var analysis = await _context.Analyses.FindAsync(new object[] { analysisId }, cancellationToken);
            if (analysis == null)
                return null;

            return new AnalysisProgress
            {
                AnalysisId = analysisId,
                Progress = analysis.Status == AnalysisStatus.Completed ? 100 : 0,
                Status = analysis.Status,
                CurrentPhase = analysis.Status.ToString()
            };
        }

        public async Task<AnalysisResult> GetAnalysisResultsAsync(Guid analysisId, CancellationToken cancellationToken = default)
        {
            var analysis = await GetAnalysisAsync(analysisId, cancellationToken);
            if (analysis == null)
                return null;

            var result = new AnalysisResult
            {
                AnalysisId = analysisId,
                ThreatLevel = analysis.ThreatLevel,
                IOCCount = analysis.IOCs?.Count ?? 0,
                RuleMatches = analysis.Rules?.Count ?? 0,
                MITRETechniques = analysis.MITRE?.Count ?? 0,
                Findings = analysis.Findings,
                StartTime = analysis.StartTime,
                EndTime = analysis.EndTime,
                Duration = analysis.EndTime.HasValue && analysis.StartTime.HasValue
                    ? analysis.EndTime.Value - analysis.StartTime.Value
                    : TimeSpan.Zero,
                IOCs = analysis.IOCs?.ToList() ?? new List<IOC>(),
                MatchedRules = analysis.Rules?.ToList() ?? new List<Rule>(),
                MITREMappings = analysis.MITRE?.ToList() ?? new List<MITRE>()
            };

            return result;
        }

        public async Task<byte[]> ExportAnalysisAsync(Guid analysisId, ExportFormat format, CancellationToken cancellationToken = default)
        {
            var result = await GetAnalysisResultsAsync(analysisId, cancellationToken);
            if (result == null)
                throw new InvalidOperationException($"Analysis not found: {analysisId}");

            switch (format)
            {
                case ExportFormat.JSON:
                    return Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(result, new System.Text.Json.JsonSerializerOptions
                    {
                        WriteIndented = true
                    }));

                case ExportFormat.CSV:
                    return ExportToCsv(result);

                case ExportFormat.PDF:
                    return await ExportToPdfAsync(result);

                default:
                    throw new NotSupportedException($"Export format not supported: {format}");
            }
        }

        public async Task<string> GenerateReportAsync(Guid analysisId, ReportFormat format, CancellationToken cancellationToken = default)
        {
            var analysis = await GetAnalysisAsync(analysisId, cancellationToken);
            if (analysis == null)
                throw new InvalidOperationException($"Analysis not found: {analysisId}");

            var result = await GetAnalysisResultsAsync(analysisId, cancellationToken);
            var aiSummary = await _aiService.SummarizeAnalysisAsync(result);

            var report = new StringBuilder();
            
            switch (format)
            {
                case ReportFormat.Executive:
                    report.AppendLine("# Executive Summary");
                    report.AppendLine($"## Analysis: {analysis.Name}");
                    report.AppendLine($"**Date:** {analysis.CreatedAt:yyyy-MM-dd HH:mm:ss}");
                    report.AppendLine($"**Threat Level:** {analysis.ThreatLevel}");
                    report.AppendLine($"**Status:** {analysis.Status}");
                    report.AppendLine();
                    report.AppendLine("### Key Findings");
                    report.AppendLine(aiSummary);
                    report.AppendLine();
                    report.AppendLine($"- **IOCs Detected:** {result.IOCCount}");
                    report.AppendLine($"- **Rule Matches:** {result.RuleMatches}");
                    report.AppendLine($"- **MITRE Techniques:** {result.MITRETechniques}");
                    break;

                case ReportFormat.Technical:
                    report.AppendLine("# Technical Analysis Report");
                    report.AppendLine($"## {analysis.Name}");
                    report.AppendLine($"**Analysis ID:** {analysis.Id}");
                    report.AppendLine($"**File:** {analysis.SourceFile}");
                    report.AppendLine($"**Hash:** {analysis.FileHash}");
                    report.AppendLine();
                    report.AppendLine("### Detailed Findings");
                    report.AppendLine(analysis.Findings);
                    report.AppendLine();
                    report.AppendLine("### Indicators of Compromise");
                    foreach (var ioc in result.IOCs)
                    {
                        report.AppendLine($"- **{ioc.Type}:** {ioc.Value} (Confidence: {ioc.Confidence}%)");
                    }
                    report.AppendLine();
                    report.AppendLine("### MITRE ATT&CK Mapping");
                    foreach (var mitre in result.MITREMappings)
                    {
                        report.AppendLine($"- **{mitre.TechniqueId}:** {mitre.Name} ({mitre.Tactic})");
                    }
                    break;

                case ReportFormat.Forensics:
                    report.AppendLine("# Digital Forensics Report");
                    report.AppendLine($"## Case: {analysis.Name}");
                    report.AppendLine($"**Evidence ID:** {analysis.Id}");
                    report.AppendLine($"**Examiner:** {analysis.CreatedBy}");
                    report.AppendLine($"**Date of Analysis:** {analysis.CreatedAt:yyyy-MM-dd HH:mm:ss}");
                    report.AppendLine();
                    report.AppendLine("### Evidence Details");
                    report.AppendLine($"- **Source File:** {analysis.SourceFile}");
                    report.AppendLine($"- **File Size:** {analysis.FileSize:N0} bytes");
                    report.AppendLine($"- **SHA256 Hash:** {analysis.FileHash}");
                    report.AppendLine();
                    report.AppendLine("### Chain of Custody");
                    report.AppendLine($"- **Acquired:** {analysis.CreatedAt:yyyy-MM-dd HH:mm:ss}");
                    report.AppendLine($"- **Analysis Started:** {analysis.StartTime:yyyy-MM-dd HH:mm:ss}");
                    report.AppendLine($"- **Analysis Completed:** {analysis.EndTime:yyyy-MM-dd HH:mm:ss}");
                    report.AppendLine();
                    report.AppendLine("### Forensic Findings");
                    report.AppendLine(analysis.Findings);
                    break;
            }

            return report.ToString();
        }

        public async Task<IEnumerable<Analysis>> GetRelatedAnalysesAsync(Guid analysisId, CancellationToken cancellationToken = default)
        {
            var analysis = await GetAnalysisAsync(analysisId, cancellationToken);
            if (analysis == null)
                return Enumerable.Empty<Analysis>();

            // Find analyses with similar IOCs
            var analysisIOCs = analysis.IOCs?.Select(i => i.Value).ToList() ?? new List<string>();
            
            var relatedAnalyses = await _context.Analyses
                .Include(a => a.IOCs)
                .Where(a => a.Id != analysisId && 
                           a.IOCs.Any(i => analysisIOCs.Contains(i.Value)))
                .OrderByDescending(a => a.CreatedAt)
                .Take(10)
                .ToListAsync(cancellationToken);

            return relatedAnalyses;
        }

        public async Task<bool> LinkAnalysisAsync(Guid analysisId, Guid relatedAnalysisId, string relationship, CancellationToken cancellationToken = default)
        {
            var analysis = await _context.Analyses.FindAsync(new object[] { analysisId }, cancellationToken);
            var relatedAnalysis = await _context.Analyses.FindAsync(new object[] { relatedAnalysisId }, cancellationToken);

            if (analysis == null || relatedAnalysis == null)
                return false;

            // Store relationship in metadata
            var metadata = analysis.Metadata ?? new Dictionary<string, object>();
            var relationships = metadata.ContainsKey("relationships") 
                ? metadata["relationships"] as List<object> ?? new List<object>()
                : new List<object>();

            relationships.Add(new
            {
                RelatedAnalysisId = relatedAnalysisId,
                Relationship = relationship,
                CreatedAt = DateTime.UtcNow
            });

            metadata["relationships"] = relationships;
            analysis.Metadata = metadata;

            await _context.SaveChangesAsync(cancellationToken);
            return true;
        }

        public async Task<IEnumerable<Analysis>> GetAnalysisChainAsync(Guid analysisId, CancellationToken cancellationToken = default)
        {
            var chain = new List<Analysis>();
            var visited = new HashSet<Guid>();
            
            await BuildAnalysisChainAsync(analysisId, chain, visited, cancellationToken);
            
            return chain.OrderBy(a => a.CreatedAt);
        }

        public async Task<IEnumerable<IOC>> ExtractIOCsAsync(Guid analysisId, CancellationToken cancellationToken = default)
        {
            var analysis = await GetAnalysisAsync(analysisId, cancellationToken);
            if (analysis == null || string.IsNullOrEmpty(analysis.SourceFile))
                return Enumerable.Empty<IOC>();

            var content = await File.ReadAllTextAsync(analysis.SourceFile, cancellationToken);
            var extractedIOCs = await _iocExtractor.ExtractIOCsAsync(content, analysis.Id);

            foreach (var ioc in extractedIOCs)
            {
                _context.IOCs.Add(ioc);
            }

            await _context.SaveChangesAsync(cancellationToken);
            return extractedIOCs;
        }

        public async Task<IEnumerable<MITRE>> MapToMITREAsync(Guid analysisId, CancellationToken cancellationToken = default)
        {
            var analysis = await GetAnalysisAsync(analysisId, cancellationToken);
            if (analysis == null)
                return Enumerable.Empty<MITRE>();

            var mappings = await _mitreMapper.MapTechniquesAsync(analysis);

            foreach (var mapping in mappings)
            {
                _context.MITREs.Add(mapping);
            }

            await _context.SaveChangesAsync(cancellationToken);
            return mappings;
        }

        public async Task<ThreatLevel> CalculateThreatLevelAsync(Guid analysisId, CancellationToken cancellationToken = default)
        {
            var result = await GetAnalysisResultsAsync(analysisId, cancellationToken);
            if (result == null)
                return ThreatLevel.Low;

            var score = 0;

            // Score based on IOC count
            score += result.IOCCount switch
            {
                > 50 => 40,
                > 20 => 30,
                > 10 => 20,
                > 5 => 10,
                _ => 5
            };

            // Score based on MITRE techniques
            score += result.MITRETechniques switch
            {
                > 10 => 40,
                > 5 => 30,
                > 3 => 20,
                > 1 => 10,
                _ => 5
            };

            // Score based on high-confidence IOCs
            var highConfidenceIOCs = result.IOCs.Count(i => i.Confidence >= 80);
            score += highConfidenceIOCs switch
            {
                > 20 => 20,
                > 10 => 15,
                > 5 => 10,
                _ => 5
            };

            return score switch
            {
                >= 80 => ThreatLevel.Critical,
                >= 60 => ThreatLevel.High,
                >= 40 => ThreatLevel.Medium,
                _ => ThreatLevel.Low
            };
        }

        public async Task<bool> ValidateAnalysisAsync(Guid analysisId, CancellationToken cancellationToken = default)
        {
            var analysis = await GetAnalysisAsync(analysisId, cancellationToken);
            if (analysis == null)
                return false;

            // Validate file integrity
            if (!string.IsNullOrEmpty(analysis.SourceFile) && File.Exists(analysis.SourceFile))
            {
                var currentHash = await CalculateFileHashAsync(analysis.SourceFile);
                if (currentHash != analysis.FileHash)
                {
                    _logger.LogWarning("File hash mismatch for analysis {AnalysisId}", analysisId);
                    return false;
                }
            }

            // Validate IOCs
            foreach (var ioc in analysis.IOCs ?? Enumerable.Empty<IOC>())
            {
                if (!await _iocExtractor.ValidateIOCAsync(ioc))
                {
                    _logger.LogWarning("Invalid IOC detected: {IOCValue}", ioc.Value);
                    return false;
                }
            }

            return true;
        }

        // Private helper methods
        private async Task ExecuteAnalysisAsync(Guid analysisId, CancellationToken cancellationToken)
        {
            try
            {
                var analysis = await GetAnalysisAsync(analysisId, cancellationToken);
                if (analysis == null || analysis.Status != AnalysisStatus.Queued)
                    return;

                await UpdateProgressAsync(analysisId, 10, "Starting analysis", AnalysisStatus.Running);

                // Phase 1: IOC Extraction
                await UpdateProgressAsync(analysisId, 20, "Extracting IOCs", AnalysisStatus.Running);
                var iocs = await ExtractIOCsAsync(analysisId, cancellationToken);

                // Phase 2: AI Analysis
                await UpdateProgressAsync(analysisId, 40, "Running AI analysis", AnalysisStatus.Running);
                var aiResults = await _aiService.AnalyzeFileContentAsync(analysis.SourceFile);
                analysis.Findings = aiResults;

                // Phase 3: MITRE Mapping
                await UpdateProgressAsync(analysisId, 60, "Mapping to MITRE ATT&CK", AnalysisStatus.Running);
                var mitreMappings = await MapToMITREAsync(analysisId, cancellationToken);

                // Phase 4: Threat Assessment
                await UpdateProgressAsync(analysisId, 80, "Calculating threat level", AnalysisStatus.Running);
                analysis.ThreatLevel = await CalculateThreatLevelAsync(analysisId, cancellationToken);

                // Phase 5: Finalization
                await UpdateProgressAsync(analysisId, 90, "Finalizing analysis", AnalysisStatus.Running);
                analysis.Status = AnalysisStatus.Completed;
                analysis.EndTime = DateTime.UtcNow;
                analysis.UpdatedAt = DateTime.UtcNow;

                await _context.SaveChangesAsync(cancellationToken);
                await UpdateProgressAsync(analysisId, 100, "Analysis complete", AnalysisStatus.Completed);

                _logger.LogInformation("Analysis completed successfully: {AnalysisId}", analysisId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Analysis failed: {AnalysisId}", analysisId);
                await UpdateProgressAsync(analysisId, 0, $"Analysis failed: {ex.Message}", AnalysisStatus.Failed);
                
                var analysis = await _context.Analyses.FindAsync(new object[] { analysisId }, cancellationToken);
                if (analysis != null)
                {
                    analysis.Status = AnalysisStatus.Failed;
                    analysis.EndTime = DateTime.UtcNow;
                    await _context.SaveChangesAsync(cancellationToken);
                }
            }
        }

        private async Task UpdateProgressAsync(Guid analysisId, int progress, string phase, AnalysisStatus status)
        {
            var progressData = new AnalysisProgress
            {
                AnalysisId = analysisId,
                Progress = progress,
                CurrentPhase = phase,
                Status = status
            };

            _progressTracking.AddOrUpdate(analysisId, progressData, (_, _) => progressData);

            await _hubContext.Clients.All.SendAsync("AnalysisProgress", progressData);
        }

        private async Task<string> CalculateFileHashAsync(string filePath)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hash = await sha256.ComputeHashAsync(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        private byte[] ExportToCsv(AnalysisResult result)
        {
            var csv = new StringBuilder();
            csv.AppendLine("Type,Value,Confidence,Context");
            
            foreach (var ioc in result.IOCs)
            {
                csv.AppendLine($"{ioc.Type},{ioc.Value},{ioc.Confidence},{ioc.Context}");
            }

            return Encoding.UTF8.GetBytes(csv.ToString());
        }

        private async Task<byte[]> ExportToPdfAsync(AnalysisResult result)
        {
            // Simplified PDF generation - in production use a proper PDF library
            var pdf = new StringBuilder();
            pdf.AppendLine($"Analysis Report - {result.AnalysisId}");
            pdf.AppendLine($"Generated: {DateTime.UtcNow}");
            pdf.AppendLine($"Threat Level: {result.ThreatLevel}");
            pdf.AppendLine($"IOCs Found: {result.IOCCount}");
            pdf.AppendLine($"Duration: {result.Duration}");
            pdf.AppendLine();
            pdf.AppendLine("Findings:");
            pdf.AppendLine(result.Findings);

            return Encoding.UTF8.GetBytes(pdf.ToString());
        }

        private async Task BuildAnalysisChainAsync(Guid analysisId, List<Analysis> chain, HashSet<Guid> visited, CancellationToken cancellationToken)
        {
            if (visited.Contains(analysisId))
                return;

            visited.Add(analysisId);
            var analysis = await GetAnalysisAsync(analysisId, cancellationToken);
            
            if (analysis == null)
                return;

            chain.Add(analysis);

            // Follow parent relationship
            if (analysis.ParentAnalysisId.HasValue)
            {
                await BuildAnalysisChainAsync(analysis.ParentAnalysisId.Value, chain, visited, cancellationToken);
            }

            // Follow metadata relationships
            if (analysis.Metadata != null && analysis.Metadata.ContainsKey("relationships"))
            {
                var relationships = analysis.Metadata["relationships"] as List<object>;
                // Process related analyses
            }
        }
    }

    public class AnalysisProgress
    {
        public Guid AnalysisId { get; set; }
        public int Progress { get; set; }
        public string CurrentPhase { get; set; }
        public AnalysisStatus Status { get; set; }
    }

    public class AnalysisResult
    {
        public Guid AnalysisId { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
        public int IOCCount { get; set; }
        public int RuleMatches { get; set; }
        public int MITRETechniques { get; set; }
        public string Findings { get; set; }
        public DateTime? StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public List<IOC> IOCs { get; set; }
        public List<Rule> MatchedRules { get; set; }
        public List<MITRE> MITREMappings { get; set; }
    }

    public enum ExportFormat
    {
        JSON,
        CSV,
        PDF
    }

    public enum ReportFormat
    {
        Executive,
        Technical,
        Forensics
    }
}