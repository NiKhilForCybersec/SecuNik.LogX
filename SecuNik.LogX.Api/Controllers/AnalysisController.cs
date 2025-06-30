using Microsoft.AspNetCore.Mvc;
using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Core.DTOs;
using SecuNik.LogX.Api.Data;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

namespace SecuNik.LogX.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AnalysisController : ControllerBase
    {
        private readonly IAnalysisService _analysisService;
        private readonly IStorageService _storageService;
        private readonly LogXDbContext _dbContext;
        private readonly ILogger<AnalysisController> _logger;

        public AnalysisController(
            IAnalysisService analysisService,
            IStorageService storageService,
            LogXDbContext dbContext,
            ILogger<AnalysisController> logger)
        {
            _analysisService = analysisService;
            _storageService = storageService;
            _dbContext = dbContext;
            _logger = logger;
        }

        /// <summary>
        /// Start analysis for an uploaded file
        /// </summary>
        [HttpPost("{uploadId}")]
        public async Task<ActionResult> StartAnalysis(Guid uploadId, [FromBody] AnalysisRequestDto request)
        {
            try
            {
                // Check if upload exists
                var files = await _storageService.ListAnalysisFilesAsync(uploadId);
                if (files.Count == 0)
                {
                    return NotFound($"Upload with ID {uploadId} not found");
                }

                // Map DTO to options
                var options = new Core.Interfaces.AnalysisOptions
                {
                    PreferredParserId = request.Options?.ParserID,
                    DeepScan = request.Options?.DeepScan ?? true,
                    ExtractIOCs = request.Options?.ExtractIOCs ?? true,
                    CheckVirusTotal = request.Options?.CheckVirusTotal ?? false,
                    EnableAI = request.Options?.EnableAI ?? false,
                    MaxEvents = request.Options?.MaxEvents ?? 100000,
                    TimeoutMinutes = request.Options?.TimeoutMinutes ?? 30,
                    IncludeRuleTypes = request.Options?.IncludeRuleTypes,
                    ExcludeRuleCategories = request.Options?.ExcludeRuleCategories,
                    CustomOptions = request.Options?.CustomOptions
                };

                // Start analysis
                var analysis = await _analysisService.StartAnalysisAsync(uploadId, options);

                return Ok(new
                {
                    analysis_id = analysis.Id,
                    file_name = analysis.FileName,
                    file_hash = analysis.FileHash,
                    status = analysis.Status,
                    message = "Analysis started successfully"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error starting analysis for upload {UploadId}", uploadId);
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Get analysis status
        /// </summary>
        [HttpGet("status/{analysisId}")]
        public async Task<ActionResult> GetAnalysisStatus(Guid analysisId)
        {
            try
            {
                var analysis = await _analysisService.GetAnalysisAsync(analysisId);
                if (analysis == null)
                {
                    return NotFound($"Analysis with ID {analysisId} not found");
                }

                return Ok(new
                {
                    analysis_id = analysis.Id,
                    status = analysis.Status,
                    progress = analysis.Progress,
                    file_name = analysis.FileName,
                    file_hash = analysis.FileHash,
                    threat_score = analysis.ThreatScore,
                    severity = analysis.Severity,
                    start_time = analysis.StartTime,
                    completion_time = analysis.CompletionTime,
                    error_message = analysis.ErrorMessage
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting analysis status for {AnalysisId}", analysisId);
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Get analysis results
        /// </summary>
        [HttpGet("result/{analysisId}")]
        public async Task<ActionResult> GetAnalysisResults(Guid analysisId)
        {
            try
            {
                var analysis = await _dbContext.Analyses
                    .Include(a => a.RuleMatches)
                    .Include(a => a.Parser)
                    .FirstOrDefaultAsync(a => a.Id == analysisId);

                if (analysis == null)
                {
                    return NotFound($"Analysis with ID {analysisId} not found");
                }

                // Parse JSON data
                var parsedData = analysis.ParsedDataJson != null
                    ? JsonSerializer.Deserialize<List<LogEvent>>(analysis.ParsedDataJson)
                    : new List<LogEvent>();

                var timeline = analysis.TimelineJson != null
                    ? JsonSerializer.Deserialize<List<TimelineEventDto>>(analysis.TimelineJson)
                    : new List<TimelineEventDto>();

                var iocs = analysis.IOCsJson != null
                    ? JsonSerializer.Deserialize<List<IOCDto>>(analysis.IOCsJson)
                    : new List<IOCDto>();

                var mitreResults = analysis.MitreResultsJson != null
                    ? JsonSerializer.Deserialize<MitreAttackDto>(analysis.MitreResultsJson)
                    : null;

                var threatIntelligence = analysis.ThreatIntelligenceJson != null
                    ? JsonSerializer.Deserialize<ThreatIntelligenceDto>(analysis.ThreatIntelligenceJson)
                    : null;

                // Map rule matches
                var ruleMatches = analysis.RuleMatches.Select(rm => new RuleMatchDto
                {
                    Id = rm.Id,
                    RuleId = rm.RuleId,
                    RuleName = rm.RuleName,
                    RuleType = rm.RuleType.ToString(),
                    Severity = rm.Severity.ToString(),
                    MatchCount = rm.MatchCount,
                    MatchedAt = rm.MatchedAt,
                    MatchedContent = rm.MatchedContent,
                    FileOffset = rm.FileOffset,
                    LineNumber = rm.LineNumber,
                    Confidence = rm.Confidence,
                    Context = rm.Context,
                    MitreAttackIds = rm.GetMitreAttackIds(),
                    IsFalsePositive = rm.IsFalsePositive,
                    AnalystNotes = rm.AnalystNotes
                }).ToList();

                // Build response
                var result = new AnalysisResultDto
                {
                    Id = analysis.Id,
                    FileName = analysis.FileName,
                    FileHash = analysis.FileHash,
                    FileSize = analysis.FileSize,
                    FileType = analysis.FileType,
                    UploadTime = analysis.UploadTime,
                    StartTime = analysis.StartTime,
                    CompletionTime = analysis.CompletionTime,
                    Status = analysis.Status,
                    Progress = analysis.Progress,
                    ThreatScore = analysis.ThreatScore,
                    Severity = analysis.Severity,
                    Summary = analysis.Summary,
                    AISummary = analysis.AISummary,
                    ErrorMessage = analysis.ErrorMessage,
                    Duration = analysis.Duration,
                    Parser = analysis.Parser != null ? new ParserInfoDto
                    {
                        Id = analysis.Parser.Id,
                        Name = analysis.Parser.Name,
                        Version = analysis.Parser.Version,
                        Type = analysis.Parser.Type
                    } : null,
                    RuleMatches = ruleMatches,
                    IOCs = iocs,
                    Timeline = timeline,
                    MitreResults = mitreResults,
                    ThreatIntelligence = threatIntelligence,
                    Tags = analysis.Tags != null ? JsonSerializer.Deserialize<List<string>>(analysis.Tags) ?? new List<string>() : new List<string>(),
                    Notes = analysis.Notes
                };

                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting analysis results for {AnalysisId}", analysisId);
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Cancel an ongoing analysis
        /// </summary>
        [HttpPost("cancel/{analysisId}")]
        public async Task<ActionResult> CancelAnalysis(Guid analysisId)
        {
            try
            {
                var success = await _analysisService.CancelAnalysisAsync(analysisId);
                if (!success)
                {
                    return NotFound($"Analysis with ID {analysisId} not found or cannot be cancelled");
                }

                return Ok(new { message = "Analysis cancelled successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cancelling analysis {AnalysisId}", analysisId);
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Delete an analysis
        /// </summary>
        [HttpDelete("{analysisId}")]
        public async Task<ActionResult> DeleteAnalysis(Guid analysisId)
        {
            try
            {
                var success = await _analysisService.DeleteAnalysisAsync(analysisId);
                if (!success)
                {
                    return NotFound($"Analysis with ID {analysisId} not found");
                }

                return NoContent();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting analysis {AnalysisId}", analysisId);
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Get analysis history
        /// </summary>
        [HttpGet("history")]
        public async Task<ActionResult> GetAnalysisHistory(
            [FromQuery] int limit = 20,
            [FromQuery] int offset = 0,
            [FromQuery] string? status = null,
            [FromQuery] string? severity = null,
            [FromQuery] int? minThreatScore = null,
            [FromQuery] string? fileType = null,
            [FromQuery] string? search = null)
        {
            try
            {
                var query = _dbContext.Analyses.AsQueryable();

                // Apply filters
                if (!string.IsNullOrEmpty(status))
                {
                    query = query.Where(a => a.Status == status);
                }

                if (!string.IsNullOrEmpty(severity))
                {
                    query = query.Where(a => a.Severity == severity);
                }

                if (minThreatScore.HasValue)
                {
                    query = query.Where(a => a.ThreatScore >= minThreatScore.Value);
                }

                if (!string.IsNullOrEmpty(fileType))
                {
                    query = query.Where(a => a.FileType == fileType);
                }

                if (!string.IsNullOrEmpty(search))
                {
                    query = query.Where(a => 
                        a.FileName.Contains(search) || 
                        a.FileHash.Contains(search) ||
                        a.Summary.Contains(search));
                }

                // Get total count
                var totalCount = await query.CountAsync();

                // Apply pagination
                query = query.OrderByDescending(a => a.UploadTime)
                    .Skip(offset).Take(limit);

                // Get analyses
                var analyses = await query.ToListAsync();

                // Map to DTOs
                var analysesDtos = analyses.Select(a => new
                {
                    id = a.Id,
                    file_name = a.FileName,
                    file_hash = a.FileHash,
                    file_size = a.FileSize,
                    file_type = a.FileType,
                    upload_time = a.UploadTime,
                    start_time = a.StartTime,
                    completion_time = a.CompletionTime,
                    status = a.Status,
                    threat_score = a.ThreatScore,
                    severity = a.Severity,
                    duration = a.Duration,
                    iocs_count = a.IOCsJson != null ? JsonSerializer.Deserialize<List<IOCDto>>(a.IOCsJson)?.Count ?? 0 : 0,
                    rule_matches_count = a.RuleMatches.Count,
                    tags = a.Tags != null ? JsonSerializer.Deserialize<List<string>>(a.Tags) ?? new List<string>() : new List<string>()
                }).ToList();

                return Ok(new
                {
                    analyses = analysesDtos,
                    total = totalCount,
                    limit = limit,
                    offset = offset
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting analysis history");
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Get analysis statistics
        /// </summary>
        [HttpGet("stats")]
        public async Task<ActionResult> GetAnalysisStats([FromQuery] int days = 30)
        {
            try
            {
                var cutoffDate = DateTime.UtcNow.AddDays(-days);

                var totalAnalyses = await _dbContext.Analyses.CountAsync();
                var recentAnalyses = await _dbContext.Analyses
                    .Where(a => a.UploadTime >= cutoffDate)
                    .ToListAsync();

                var analysesByDay = recentAnalyses
                    .GroupBy(a => a.UploadTime.Date)
                    .Select(g => new
                    {
                        date = g.Key.ToString("yyyy-MM-dd"),
                        count = g.Count(),
                        threats = g.Sum(a => a.RuleMatches.Count)
                    })
                    .OrderBy(g => g.date)
                    .ToList();

                var analysesByStatus = recentAnalyses
                    .GroupBy(a => a.Status)
                    .Select(g => new
                    {
                        status = g.Key,
                        count = g.Count()
                    })
                    .ToList();

                var analysesBySeverity = recentAnalyses
                    .GroupBy(a => a.Severity)
                    .Select(g => new
                    {
                        severity = g.Key,
                        count = g.Count()
                    })
                    .ToList();

                var analysesByFileType = recentAnalyses
                    .GroupBy(a => a.FileType)
                    .Select(g => new
                    {
                        file_type = g.Key,
                        count = g.Count()
                    })
                    .OrderByDescending(g => g.count)
                    .ToList();

                var totalThreatsFound = recentAnalyses.Sum(a => a.RuleMatches.Count);

                return Ok(new
                {
                    total_analyses = totalAnalyses,
                    recent_analyses = recentAnalyses.Count,
                    analyses_by_day = analysesByDay,
                    analyses_by_status = analysesByStatus,
                    analyses_by_severity = analysesBySeverity,
                    analyses_by_file_type = analysesByFileType,
                    total_threats_found = totalThreatsFound
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting analysis statistics");
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Export analysis results
        /// </summary>
        [HttpGet("export/{analysisId}")]
        public async Task<ActionResult> ExportAnalysis(Guid analysisId, [FromQuery] string format = "json")
        {
            try
            {
                var analysis = await _dbContext.Analyses
                    .Include(a => a.RuleMatches)
                    .Include(a => a.Parser)
                    .FirstOrDefaultAsync(a => a.Id == analysisId);

                if (analysis == null)
                {
                    return NotFound($"Analysis with ID {analysisId} not found");
                }

                // Build export data
                var exportData = new
                {
                    analysis_id = analysis.Id,
                    file_name = analysis.FileName,
                    file_hash = analysis.FileHash,
                    file_size = analysis.FileSize,
                    file_type = analysis.FileType,
                    upload_time = analysis.UploadTime,
                    start_time = analysis.StartTime,
                    completion_time = analysis.CompletionTime,
                    status = analysis.Status,
                    threat_score = analysis.ThreatScore,
                    severity = analysis.Severity,
                    summary = analysis.Summary,
                    ai_summary = analysis.AISummary,
                    parser = analysis.Parser != null ? new
                    {
                        id = analysis.Parser.Id,
                        name = analysis.Parser.Name,
                        version = analysis.Parser.Version
                    } : null,
                    rule_matches = analysis.RuleMatches.Select(rm => new
                    {
                        rule_id = rm.RuleId,
                        rule_name = rm.RuleName,
                        rule_type = rm.RuleType.ToString(),
                        severity = rm.Severity.ToString(),
                        match_count = rm.MatchCount,
                        matched_at = rm.MatchedAt,
                        confidence = rm.Confidence,
                        mitre_attack_ids = rm.GetMitreAttackIds()
                    }).ToList(),
                    parsed_data = analysis.ParsedDataJson != null
                        ? JsonSerializer.Deserialize<List<LogEvent>>(analysis.ParsedDataJson)
                        : new List<LogEvent>(),
                    iocs = analysis.IOCsJson != null
                        ? JsonSerializer.Deserialize<List<IOCDto>>(analysis.IOCsJson)
                        : new List<IOCDto>(),
                    timeline = analysis.TimelineJson != null
                        ? JsonSerializer.Deserialize<List<TimelineEventDto>>(analysis.TimelineJson)
                        : new List<TimelineEventDto>(),
                    mitre_results = analysis.MitreResultsJson != null
                        ? JsonSerializer.Deserialize<MitreAttackDto>(analysis.MitreResultsJson)
                        : null,
                    tags = analysis.Tags != null
                        ? JsonSerializer.Deserialize<List<string>>(analysis.Tags) ?? new List<string>()
                        : new List<string>(),
                    notes = analysis.Notes,
                    export_date = DateTime.UtcNow
                };

                if (format.ToLower() == "json")
                {
                    return Ok(exportData);
                }
                else if (format.ToLower() == "csv")
                {
                    // In a real implementation, we'd convert to CSV format
                    return Ok(exportData);
                }
                else
                {
                    return BadRequest($"Unsupported export format: {format}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error exporting analysis {AnalysisId}", analysisId);
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Add tags to analysis
        /// </summary>
        [HttpPost("{analysisId}/tags")]
        public async Task<ActionResult> AddTags(Guid analysisId, [FromBody] List<string> tags)
        {
            try
            {
                var analysis = await _dbContext.Analyses.FindAsync(analysisId);
                if (analysis == null)
                {
                    return NotFound($"Analysis with ID {analysisId} not found");
                }

                // Get existing tags
                var existingTags = analysis.Tags != null
                    ? JsonSerializer.Deserialize<List<string>>(analysis.Tags) ?? new List<string>()
                    : new List<string>();

                // Add new tags
                foreach (var tag in tags)
                {
                    if (!existingTags.Contains(tag))
                    {
                        existingTags.Add(tag);
                    }
                }

                // Update tags
                analysis.Tags = JsonSerializer.Serialize(existingTags);
                await _dbContext.SaveChangesAsync();

                return Ok(new
                {
                    tags = existingTags
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error adding tags to analysis {AnalysisId}", analysisId);
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Update analysis notes
        /// </summary>
        [HttpPut("{analysisId}/notes")]
        public async Task<ActionResult> UpdateNotes(Guid analysisId, [FromBody] UpdateNotesRequest request)
        {
            try
            {
                var analysis = await _dbContext.Analyses.FindAsync(analysisId);
                if (analysis == null)
                {
                    return NotFound($"Analysis with ID {analysisId} not found");
                }

                analysis.Notes = request.Notes;
                await _dbContext.SaveChangesAsync();

                return Ok(new
                {
                    notes = analysis.Notes
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating notes for analysis {AnalysisId}", analysisId);
                return StatusCode(500, "Internal server error");
            }
        }
    }

    public class UpdateNotesRequest
    {
        public string Notes { get; set; } = string.Empty;
    }
}