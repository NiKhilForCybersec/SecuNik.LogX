using Microsoft.AspNetCore.Mvc;
using SecuNikLogX.Core.Interfaces;
using SecuNikLogX.API.DTOs;
using SecuNikLogX.API.Models;
using FluentValidation;
using System.ComponentModel.DataAnnotations;

namespace SecuNikLogX.API.Controllers
{
    /// <summary>
    /// RESTful API controller for forensics analysis operations and workflow management
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    public class AnalysisController : ControllerBase
    {
        private readonly IAnalysisService _analysisService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AnalysisController> _logger;

        /// <summary>
        /// Initializes a new instance of the AnalysisController
        /// </summary>
        /// <param name="analysisService">Analysis service for forensics operations</param>
        /// <param name="configuration">Application configuration</param>
        /// <param name="logger">Logger instance</param>
        public AnalysisController(
            IAnalysisService analysisService,
            IConfiguration configuration,
            ILogger<AnalysisController> logger)
        {
            _analysisService = analysisService ?? throw new ArgumentNullException(nameof(analysisService));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Gets a paginated list of analyses with optional filtering
        /// </summary>
        /// <param name="pageNumber">Page number (1-based)</param>
        /// <param name="pageSize">Number of items per page</param>
        /// <param name="status">Filter by analysis status</param>
        /// <param name="threatLevel">Filter by threat level</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Paginated list of analyses</returns>
        [HttpGet]
        [ProducesResponseType(typeof(AnalysisListResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<AnalysisListResponse>> GetAnalyses(
            [FromQuery] int pageNumber = 1,
            [FromQuery] int pageSize = 20,
            [FromQuery] string? status = null,
            [FromQuery] string? threatLevel = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                if (pageNumber <= 0 || pageSize <= 0 || pageSize > 100)
                {
                    return BadRequest("Invalid pagination parameters");
                }

                var analyses = await _analysisService.GetAnalysesAsync(
                    pageNumber, pageSize, status, threatLevel, cancellationToken);

                return Ok(new AnalysisListResponse
                {
                    Analyses = analyses.Select(a => MapToAnalysisResponse(a)).ToList(),
                    TotalCount = await _analysisService.GetAnalysisCountAsync(status, threatLevel, cancellationToken),
                    PageNumber = pageNumber,
                    PageSize = pageSize
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving analyses");
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Gets a specific analysis by ID
        /// </summary>
        /// <param name="id">Analysis ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Analysis details</returns>
        [HttpGet("{id:guid}")]
        [ProducesResponseType(typeof(AnalysisResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<AnalysisResponse>> GetAnalysis(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var analysis = await _analysisService.GetAnalysisByIdAsync(id, cancellationToken);
                if (analysis == null)
                {
                    return NotFound($"Analysis with ID {id} not found");
                }

                return Ok(MapToAnalysisResponse(analysis));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving analysis {AnalysisId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Creates a new analysis
        /// </summary>
        /// <param name="request">Analysis creation request</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Created analysis</returns>
        [HttpPost]
        [ProducesResponseType(typeof(AnalysisResponse), StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<AnalysisResponse>> CreateAnalysis(
            [FromBody] AnalysisCreateRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var analysis = await _analysisService.CreateAnalysisAsync(
                    request.FilePath,
                    request.FileName,
                    request.FileSize,
                    request.FileHash,
                    request.AnalysisType,
                    request.Priority,
                    cancellationToken);

                var response = MapToAnalysisResponse(analysis);
                return CreatedAtAction(nameof(GetAnalysis), new { id = analysis.Id }, response);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating analysis");
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Updates an existing analysis
        /// </summary>
        /// <param name="id">Analysis ID</param>
        /// <param name="request">Analysis update request</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Updated analysis</returns>
        [HttpPut("{id:guid}")]
        [ProducesResponseType(typeof(AnalysisResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<AnalysisResponse>> UpdateAnalysis(
            Guid id,
            [FromBody] AnalysisUpdateRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var analysis = await _analysisService.UpdateAnalysisAsync(
                    id,
                    request.Priority,
                    request.Notes,
                    request.ThreatLevel,
                    cancellationToken);

                if (analysis == null)
                {
                    return NotFound($"Analysis with ID {id} not found");
                }

                return Ok(MapToAnalysisResponse(analysis));
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating analysis {AnalysisId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Deletes an analysis
        /// </summary>
        /// <param name="id">Analysis ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>No content</returns>
        [HttpDelete("{id:guid}")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> DeleteAnalysis(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var deleted = await _analysisService.DeleteAnalysisAsync(id, cancellationToken);
                if (!deleted)
                {
                    return NotFound($"Analysis with ID {id} not found");
                }

                return NoContent();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting analysis {AnalysisId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Uploads a file for analysis
        /// </summary>
        /// <param name="request">File upload request</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Created analysis</returns>
        [HttpPost("upload")]
        [ProducesResponseType(typeof(AnalysisResponse), StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status413PayloadTooLarge)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<AnalysisResponse>> UploadFile(
            [FromForm] FileUploadRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                if (request.File == null || request.File.Length == 0)
                {
                    return BadRequest("No file provided");
                }

                var maxFileSize = _configuration.GetValue<long>("FileStorage:MaxFileSizeMB", 100) * 1024 * 1024;
                if (request.File.Length > maxFileSize)
                {
                    return StatusCode(413, "File size exceeds maximum allowed size");
                }

                var analysis = await _analysisService.CreateAnalysisFromFileAsync(
                    request.File,
                    request.AnalysisType,
                    request.Priority,
                    cancellationToken);

                return CreatedAtAction(nameof(GetAnalysis), new { id = analysis.Id }, MapToAnalysisResponse(analysis));
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading file for analysis");
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Starts an analysis
        /// </summary>
        /// <param name="id">Analysis ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Analysis with updated status</returns>
        [HttpPost("{id:guid}/start")]
        [ProducesResponseType(typeof(AnalysisResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<AnalysisResponse>> StartAnalysis(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var analysis = await _analysisService.StartAnalysisAsync(id, cancellationToken);
                if (analysis == null)
                {
                    return NotFound($"Analysis with ID {id} not found");
                }

                return Ok(MapToAnalysisResponse(analysis));
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error starting analysis {AnalysisId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Pauses an analysis
        /// </summary>
        /// <param name="id">Analysis ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Analysis with updated status</returns>
        [HttpPost("{id:guid}/pause")]
        [ProducesResponseType(typeof(AnalysisResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<AnalysisResponse>> PauseAnalysis(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var analysis = await _analysisService.PauseAnalysisAsync(id, cancellationToken);
                if (analysis == null)
                {
                    return NotFound($"Analysis with ID {id} not found");
                }

                return Ok(MapToAnalysisResponse(analysis));
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error pausing analysis {AnalysisId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Stops an analysis
        /// </summary>
        /// <param name="id">Analysis ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Analysis with updated status</returns>
        [HttpPost("{id:guid}/stop")]
        [ProducesResponseType(typeof(AnalysisResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<AnalysisResponse>> StopAnalysis(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var analysis = await _analysisService.StopAnalysisAsync(id, cancellationToken);
                if (analysis == null)
                {
                    return NotFound($"Analysis with ID {id} not found");
                }

                return Ok(MapToAnalysisResponse(analysis));
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error stopping analysis {AnalysisId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Searches analyses based on criteria
        /// </summary>
        /// <param name="query">Search query</param>
        /// <param name="fileType">Filter by file type</param>
        /// <param name="threatLevel">Filter by threat level</param>
        /// <param name="pageNumber">Page number</param>
        /// <param name="pageSize">Page size</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Search results</returns>
        [HttpGet("search")]
        [ProducesResponseType(typeof(AnalysisListResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<AnalysisListResponse>> SearchAnalyses(
            [FromQuery] string? query = null,
            [FromQuery] string? fileType = null,
            [FromQuery] string? threatLevel = null,
            [FromQuery] int pageNumber = 1,
            [FromQuery] int pageSize = 20,
            CancellationToken cancellationToken = default)
        {
            try
            {
                if (pageNumber <= 0 || pageSize <= 0 || pageSize > 100)
                {
                    return BadRequest("Invalid pagination parameters");
                }

                var analyses = await _analysisService.SearchAnalysesAsync(
                    query, fileType, threatLevel, pageNumber, pageSize, cancellationToken);

                return Ok(new AnalysisListResponse
                {
                    Analyses = analyses.Select(a => MapToAnalysisResponse(a)).ToList(),
                    TotalCount = await _analysisService.GetSearchCountAsync(query, fileType, threatLevel, cancellationToken),
                    PageNumber = pageNumber,
                    PageSize = pageSize
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error searching analyses");
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Gets analyses within a date range
        /// </summary>
        /// <param name="startDate">Start date</param>
        /// <param name="endDate">End date</param>
        /// <param name="pageNumber">Page number</param>
        /// <param name="pageSize">Page size</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Analyses in date range</returns>
        [HttpGet("date-range")]
        [ProducesResponseType(typeof(AnalysisListResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<AnalysisListResponse>> GetAnalysesByDateRange(
            [FromQuery] DateTime startDate,
            [FromQuery] DateTime endDate,
            [FromQuery] int pageNumber = 1,
            [FromQuery] int pageSize = 20,
            CancellationToken cancellationToken = default)
        {
            try
            {
                if (startDate > endDate)
                {
                    return BadRequest("Start date must be before end date");
                }

                if (pageNumber <= 0 || pageSize <= 0 || pageSize > 100)
                {
                    return BadRequest("Invalid pagination parameters");
                }

                var analyses = await _analysisService.GetAnalysesByDateRangeAsync(
                    startDate, endDate, pageNumber, pageSize, cancellationToken);

                return Ok(new AnalysisListResponse
                {
                    Analyses = analyses.Select(a => MapToAnalysisResponse(a)).ToList(),
                    TotalCount = await _analysisService.GetDateRangeCountAsync(startDate, endDate, cancellationToken),
                    PageNumber = pageNumber,
                    PageSize = pageSize
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving analyses by date range");
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Gets analyses by threat level
        /// </summary>
        /// <param name="threatLevel">Threat level</param>
        /// <param name="pageNumber">Page number</param>
        /// <param name="pageSize">Page size</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Analyses with specified threat level</returns>
        [HttpGet("threat-level")]
        [ProducesResponseType(typeof(AnalysisListResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<AnalysisListResponse>> GetAnalysesByThreatLevel(
            [FromQuery] [Required] string threatLevel,
            [FromQuery] int pageNumber = 1,
            [FromQuery] int pageSize = 20,
            CancellationToken cancellationToken = default)
        {
            try
            {
                if (pageNumber <= 0 || pageSize <= 0 || pageSize > 100)
                {
                    return BadRequest("Invalid pagination parameters");
                }

                var analyses = await _analysisService.GetAnalysesByThreatLevelAsync(
                    threatLevel, pageNumber, pageSize, cancellationToken);

                return Ok(new AnalysisListResponse
                {
                    Analyses = analyses.Select(a => MapToAnalysisResponse(a)).ToList(),
                    TotalCount = await _analysisService.GetThreatLevelCountAsync(threatLevel, cancellationToken),
                    PageNumber = pageNumber,
                    PageSize = pageSize
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving analyses by threat level");
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Gets analysis results
        /// </summary>
        /// <param name="id">Analysis ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Analysis results</returns>
        [HttpGet("{id:guid}/results")]
        [ProducesResponseType(typeof(AnalysisResultResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<AnalysisResultResponse>> GetAnalysisResults(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var results = await _analysisService.GetAnalysisResultsAsync(id, cancellationToken);
                if (results == null)
                {
                    return NotFound($"Analysis results for ID {id} not found");
                }

                return Ok(results);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving analysis results {AnalysisId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Exports analysis results
        /// </summary>
        /// <param name="id">Analysis ID</param>
        /// <param name="format">Export format (json, xml, csv)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Exported results file</returns>
        [HttpGet("{id:guid}/export")]
        [ProducesResponseType(typeof(FileResult), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> ExportAnalysisResults(
            Guid id,
            [FromQuery] string format = "json",
            CancellationToken cancellationToken = default)
        {
            try
            {
                var allowedFormats = new[] { "json", "xml", "csv" };
                if (!allowedFormats.Contains(format.ToLower()))
                {
                    return BadRequest("Invalid export format. Allowed formats: json, xml, csv");
                }

                var exportData = await _analysisService.ExportAnalysisResultsAsync(id, format, cancellationToken);
                if (exportData == null)
                {
                    return NotFound($"Analysis results for ID {id} not found");
                }

                var contentType = format.ToLower() switch
                {
                    "xml" => "application/xml",
                    "csv" => "text/csv",
                    _ => "application/json"
                };

                var fileName = $"analysis_{id}_{DateTime.UtcNow:yyyyMMdd_HHmmss}.{format}";
                return File(exportData, contentType, fileName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error exporting analysis results {AnalysisId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Generates analysis report
        /// </summary>
        /// <param name="id">Analysis ID</param>
        /// <param name="includeDetails">Include detailed findings</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Analysis report</returns>
        [HttpGet("{id:guid}/report")]
        [ProducesResponseType(typeof(FileResult), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> GenerateAnalysisReport(
            Guid id,
            [FromQuery] bool includeDetails = true,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var reportData = await _analysisService.GenerateAnalysisReportAsync(id, includeDetails, cancellationToken);
                if (reportData == null)
                {
                    return NotFound($"Analysis for ID {id} not found");
                }

                var fileName = $"analysis_report_{id}_{DateTime.UtcNow:yyyyMMdd_HHmmss}.pdf";
                return File(reportData, "application/pdf", fileName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating analysis report {AnalysisId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Gets related analyses
        /// </summary>
        /// <param name="id">Analysis ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Related analyses</returns>
        [HttpGet("{id:guid}/related")]
        [ProducesResponseType(typeof(AnalysisListResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<AnalysisListResponse>> GetRelatedAnalyses(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var relatedAnalyses = await _analysisService.GetRelatedAnalysesAsync(id, cancellationToken);
                if (relatedAnalyses == null)
                {
                    return NotFound($"Analysis with ID {id} not found");
                }

                return Ok(new AnalysisListResponse
                {
                    Analyses = relatedAnalyses.Select(a => MapToAnalysisResponse(a)).ToList(),
                    TotalCount = relatedAnalyses.Count(),
                    PageNumber = 1,
                    PageSize = relatedAnalyses.Count()
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving related analyses {AnalysisId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Links two analyses
        /// </summary>
        /// <param name="id">Primary analysis ID</param>
        /// <param name="relatedId">Related analysis ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Success result</returns>
        [HttpPost("{id:guid}/link")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> LinkAnalyses(
            Guid id,
            [FromBody] Guid relatedId,
            CancellationToken cancellationToken = default)
        {
            try
            {
                if (id == relatedId)
                {
                    return BadRequest("Cannot link analysis to itself");
                }

                var success = await _analysisService.LinkAnalysesAsync(id, relatedId, cancellationToken);
                if (!success)
                {
                    return NotFound("One or both analyses not found");
                }

                return Ok();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error linking analyses {AnalysisId} and {RelatedId}", id, relatedId);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Gets analysis progress
        /// </summary>
        /// <param name="id">Analysis ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Analysis progress information</returns>
        [HttpGet("{id:guid}/progress")]
        [ProducesResponseType(typeof(AnalysisProgressResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<AnalysisProgressResponse>> GetAnalysisProgress(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var progress = await _analysisService.GetAnalysisProgressAsync(id, cancellationToken);
                if (progress == null)
                {
                    return NotFound($"Analysis with ID {id} not found");
                }

                return Ok(progress);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving analysis progress {AnalysisId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Gets analysis statistics
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Analysis statistics</returns>
        [HttpGet("statistics")]
        [ProducesResponseType(typeof(AnalysisStatisticsResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<AnalysisStatisticsResponse>> GetAnalysisStatistics(
            CancellationToken cancellationToken = default)
        {
            try
            {
                var statistics = await _analysisService.GetAnalysisStatisticsAsync(cancellationToken);
                return Ok(statistics);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving analysis statistics");
                return StatusCode(500, "Internal server error occurred");
            }
        }

        private static AnalysisResponse MapToAnalysisResponse(Analysis analysis)
        {
            return new AnalysisResponse
            {
                Id = analysis.Id,
                FilePath = analysis.FilePath,
                FileName = analysis.FileName,
                FileSize = analysis.FileSize,
                FileHash = analysis.FileHash,
                FileType = analysis.FileType,
                Status = analysis.Status,
                Priority = analysis.Priority,
                ThreatLevel = analysis.ThreatLevel,
                Progress = analysis.Progress,
                StartTime = analysis.StartTime,
                EndTime = analysis.EndTime,
                Duration = analysis.Duration,
                ResultSummary = analysis.ResultSummary,
                ErrorMessage = analysis.ErrorMessage,
                Notes = analysis.Notes,
                CreatedAt = analysis.CreatedAt,
                UpdatedAt = analysis.UpdatedAt,
                CreatedBy = analysis.CreatedBy
            };
        }
    }
}