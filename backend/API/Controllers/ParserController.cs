using Microsoft.AspNetCore.Mvc;
using SecuNikLogX.Core.Interfaces;
using SecuNikLogX.API.DTOs;
using SecuNikLogX.API.Models;
using FluentValidation;
using System.ComponentModel.DataAnnotations;

namespace SecuNikLogX.API.Controllers
{
    /// <summary>
    /// Custom C# parser management and lifecycle controller
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    public class ParserController : ControllerBase
    {
        private readonly IParserService _parserService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<ParserController> _logger;

        /// <summary>
        /// Initializes a new instance of the ParserController
        /// </summary>
        /// <param name="parserService">Parser service for C# parser operations</param>
        /// <param name="configuration">Application configuration</param>
        /// <param name="logger">Logger instance</param>
        public ParserController(
            IParserService parserService,
            IConfiguration configuration,
            ILogger<ParserController> logger)
        {
            _parserService = parserService ?? throw new ArgumentNullException(nameof(parserService));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Gets a paginated list of parsers with optional filtering
        /// </summary>
        /// <param name="pageNumber">Page number (1-based)</param>
        /// <param name="pageSize">Number of items per page</param>
        /// <param name="category">Filter by parser category</param>
        /// <param name="status">Filter by parser status</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Paginated list of parsers</returns>
        [HttpGet]
        [ProducesResponseType(typeof(ParserListResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserListResponse>> GetParsers(
            [FromQuery] int pageNumber = 1,
            [FromQuery] int pageSize = 20,
            [FromQuery] string? category = null,
            [FromQuery] string? status = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                if (pageNumber <= 0 || pageSize <= 0 || pageSize > 100)
                {
                    return BadRequest("Invalid pagination parameters");
                }

                var parsers = await _parserService.GetParsersAsync(
                    pageNumber, pageSize, category, status, cancellationToken);

                return Ok(new ParserListResponse
                {
                    Parsers = parsers.Select(p => MapToParserResponse(p)).ToList(),
                    TotalCount = await _parserService.GetParserCountAsync(category, status, cancellationToken),
                    PageNumber = pageNumber,
                    PageSize = pageSize
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving parsers");
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Gets a specific parser by ID
        /// </summary>
        /// <param name="id">Parser ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Parser details</returns>
        [HttpGet("{id:guid}")]
        [ProducesResponseType(typeof(ParserResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserResponse>> GetParser(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var parser = await _parserService.GetParserByIdAsync(id, cancellationToken);
                if (parser == null)
                {
                    return NotFound($"Parser with ID {id} not found");
                }

                return Ok(MapToParserResponse(parser));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving parser {ParserId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Creates a new parser
        /// </summary>
        /// <param name="request">Parser creation request</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Created parser</returns>
        [HttpPost]
        [ProducesResponseType(typeof(ParserResponse), StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserResponse>> CreateParser(
            [FromBody] ParserCreateRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var parser = await _parserService.CreateParserAsync(
                    request.Name,
                    request.Description,
                    request.SourceCode,
                    request.Category,
                    request.Version,
                    request.Author,
                    cancellationToken);

                var response = MapToParserResponse(parser);
                return CreatedAtAction(nameof(GetParser), new { id = parser.Id }, response);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating parser");
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Updates an existing parser
        /// </summary>
        /// <param name="id">Parser ID</param>
        /// <param name="request">Parser update request</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Updated parser</returns>
        [HttpPut("{id:guid}")]
        [ProducesResponseType(typeof(ParserResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserResponse>> UpdateParser(
            Guid id,
            [FromBody] ParserUpdateRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var parser = await _parserService.UpdateParserAsync(
                    id,
                    request.Name,
                    request.Description,
                    request.SourceCode,
                    request.Version,
                    cancellationToken);

                if (parser == null)
                {
                    return NotFound($"Parser with ID {id} not found");
                }

                return Ok(MapToParserResponse(parser));
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating parser {ParserId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Deletes a parser
        /// </summary>
        /// <param name="id">Parser ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>No content</returns>
        [HttpDelete("{id:guid}")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> DeleteParser(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var deleted = await _parserService.DeleteParserAsync(id, cancellationToken);
                if (!deleted)
                {
                    return NotFound($"Parser with ID {id} not found");
                }

                return NoContent();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting parser {ParserId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Compiles a parser from source code
        /// </summary>
        /// <param name="id">Parser ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Compilation result</returns>
        [HttpPost("{id:guid}/compile")]
        [ProducesResponseType(typeof(ParserCompilationResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserCompilationResponse>> CompileParser(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var compilationResult = await _parserService.CompileParserAsync(id, cancellationToken);
                if (compilationResult == null)
                {
                    return NotFound($"Parser with ID {id} not found");
                }

                return Ok(compilationResult);
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error compiling parser {ParserId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Validates parser source code syntax and dependencies
        /// </summary>
        /// <param name="id">Parser ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Validation result</returns>
        [HttpPost("{id:guid}/validate")]
        [ProducesResponseType(typeof(ParserValidationResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserValidationResponse>> ValidateParser(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var validationResult = await _parserService.ValidateParserAsync(id, cancellationToken);
                if (validationResult == null)
                {
                    return NotFound($"Parser with ID {id} not found");
                }

                return Ok(validationResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating parser {ParserId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Tests parser functionality with sample data
        /// </summary>
        /// <param name="id">Parser ID</param>
        /// <param name="request">Test request with sample data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Test execution result</returns>
        [HttpPost("{id:guid}/test")]
        [ProducesResponseType(typeof(ParserTestResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserTestResponse>> TestParser(
            Guid id,
            [FromBody] ParserTestRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var testResult = await _parserService.TestParserAsync(id, request.TestData, cancellationToken);
                if (testResult == null)
                {
                    return NotFound($"Parser with ID {id} not found");
                }

                return Ok(testResult);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error testing parser {ParserId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Executes a parser against a specific file
        /// </summary>
        /// <param name="id">Parser ID</param>
        /// <param name="request">Execution request with file information</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Parser execution result</returns>
        [HttpPost("{id:guid}/execute")]
        [ProducesResponseType(typeof(ParserExecutionResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserExecutionResponse>> ExecuteParser(
            Guid id,
            [FromBody] ParserExecutionRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var executionResult = await _parserService.ExecuteParserAsync(
                    id, request.FilePath, request.Parameters, cancellationToken);

                if (executionResult == null)
                {
                    return NotFound($"Parser with ID {id} not found");
                }

                return Ok(executionResult);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error executing parser {ParserId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Gets available parser templates
        /// </summary>
        /// <param name="category">Filter by category</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>List of parser templates</returns>
        [HttpGet("templates")]
        [ProducesResponseType(typeof(ParserTemplateListResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserTemplateListResponse>> GetParserTemplates(
            [FromQuery] string? category = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var templates = await _parserService.GetParserTemplatesAsync(category, cancellationToken);

                return Ok(new ParserTemplateListResponse
                {
                    Templates = templates,
                    TotalCount = templates.Count()
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving parser templates");
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Creates a parser from a template
        /// </summary>
        /// <param name="request">Template-based parser creation request</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Created parser</returns>
        [HttpPost("from-template")]
        [ProducesResponseType(typeof(ParserResponse), StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserResponse>> CreateParserFromTemplate(
            [FromBody] ParserFromTemplateRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var parser = await _parserService.CreateParserFromTemplateAsync(
                    request.TemplateName,
                    request.Name,
                    request.Description,
                    request.Author,
                    request.Parameters,
                    cancellationToken);

                var response = MapToParserResponse(parser);
                return CreatedAtAction(nameof(GetParser), new { id = parser.Id }, response);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating parser from template");
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Analyzes parser security and compliance
        /// </summary>
        /// <param name="id">Parser ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Security analysis result</returns>
        [HttpPost("{id:guid}/analyze-security")]
        [ProducesResponseType(typeof(ParserSecurityAnalysisResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserSecurityAnalysisResponse>> AnalyzeParserSecurity(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var analysisResult = await _parserService.AnalyzeParserSecurityAsync(id, cancellationToken);
                if (analysisResult == null)
                {
                    return NotFound($"Parser with ID {id} not found");
                }

                return Ok(analysisResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing parser security {ParserId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Checks parser dependencies and compatibility
        /// </summary>
        /// <param name="id">Parser ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Dependency check result</returns>
        [HttpPost("{id:guid}/check-dependencies")]
        [ProducesResponseType(typeof(ParserDependencyCheckResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserDependencyCheckResponse>> CheckParserDependencies(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var dependencyResult = await _parserService.CheckParserDependenciesAsync(id, cancellationToken);
                if (dependencyResult == null)
                {
                    return NotFound($"Parser with ID {id} not found");
                }

                return Ok(dependencyResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking parser dependencies {ParserId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Benchmarks parser performance
        /// </summary>
        /// <param name="id">Parser ID</param>
        /// <param name="request">Benchmark request parameters</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Performance benchmark result</returns>
        [HttpPost("{id:guid}/benchmark")]
        [ProducesResponseType(typeof(ParserBenchmarkResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserBenchmarkResponse>> BenchmarkParser(
            Guid id,
            [FromBody] ParserBenchmarkRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var benchmarkResult = await _parserService.BenchmarkParserAsync(
                    id, request.TestFileSize, request.Iterations, cancellationToken);

                if (benchmarkResult == null)
                {
                    return NotFound($"Parser with ID {id} not found");
                }

                return Ok(benchmarkResult);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error benchmarking parser {ParserId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Gets parser performance metrics
        /// </summary>
        /// <param name="id">Parser ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Parser performance metrics</returns>
        [HttpGet("{id:guid}/metrics")]
        [ProducesResponseType(typeof(ParserMetricsResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserMetricsResponse>> GetParserMetrics(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var metrics = await _parserService.GetParserMetricsAsync(id, cancellationToken);
                if (metrics == null)
                {
                    return NotFound($"Parser with ID {id} not found");
                }

                return Ok(metrics);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving parser metrics {ParserId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Gets parser version history
        /// </summary>
        /// <param name="id">Parser ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Parser version history</returns>
        [HttpGet("{id:guid}/versions")]
        [ProducesResponseType(typeof(ParserVersionHistoryResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserVersionHistoryResponse>> GetParserVersions(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var versions = await _parserService.GetParserVersionHistoryAsync(id, cancellationToken);
                if (versions == null)
                {
                    return NotFound($"Parser with ID {id} not found");
                }

                return Ok(versions);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving parser versions {ParserId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Creates a new version of a parser
        /// </summary>
        /// <param name="id">Parser ID</param>
        /// <param name="request">Version creation request</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Created parser version</returns>
        [HttpPost("{id:guid}/create-version")]
        [ProducesResponseType(typeof(ParserVersionResponse), StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserVersionResponse>> CreateParserVersion(
            Guid id,
            [FromBody] ParserVersionCreateRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var version = await _parserService.CreateParserVersionAsync(
                    id, request.VersionNumber, request.ChangeLog, cancellationToken);

                if (version == null)
                {
                    return NotFound($"Parser with ID {id} not found");
                }

                return CreatedAtAction(nameof(GetParserVersions), new { id }, version);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating parser version {ParserId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Enables a parser for execution
        /// </summary>
        /// <param name="id">Parser ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Parser with updated status</returns>
        [HttpPost("{id:guid}/enable")]
        [ProducesResponseType(typeof(ParserResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserResponse>> EnableParser(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var parser = await _parserService.EnableParserAsync(id, cancellationToken);
                if (parser == null)
                {
                    return NotFound($"Parser with ID {id} not found");
                }

                return Ok(MapToParserResponse(parser));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error enabling parser {ParserId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Disables a parser from execution
        /// </summary>
        /// <param name="id">Parser ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Parser with updated status</returns>
        [HttpPost("{id:guid}/disable")]
        [ProducesResponseType(typeof(ParserResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserResponse>> DisableParser(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var parser = await _parserService.DisableParserAsync(id, cancellationToken);
                if (parser == null)
                {
                    return NotFound($"Parser with ID {id} not found");
                }

                return Ok(MapToParserResponse(parser));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error disabling parser {ParserId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Gets parser execution history
        /// </summary>
        /// <param name="id">Parser ID</param>
        /// <param name="pageNumber">Page number</param>
        /// <param name="pageSize">Page size</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Parser execution history</returns>
        [HttpGet("{id:guid}/execution-history")]
        [ProducesResponseType(typeof(ParserExecutionHistoryResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserExecutionHistoryResponse>> GetParserExecutionHistory(
            Guid id,
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

                var history = await _parserService.GetParserExecutionHistoryAsync(
                    id, pageNumber, pageSize, cancellationToken);

                if (history == null)
                {
                    return NotFound($"Parser with ID {id} not found");
                }

                return Ok(history);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving parser execution history {ParserId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Gets parser statistics
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Parser statistics</returns>
        [HttpGet("statistics")]
        [ProducesResponseType(typeof(ParserStatisticsResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ParserStatisticsResponse>> GetParserStatistics(
            CancellationToken cancellationToken = default)
        {
            try
            {
                var statistics = await _parserService.GetParserStatisticsAsync(cancellationToken);
                return Ok(statistics);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving parser statistics");
                return StatusCode(500, "Internal server error occurred");
            }
        }

        private static ParserResponse MapToParserResponse(Parser parser)
        {
            return new ParserResponse
            {
                Id = parser.Id,
                Name = parser.Name,
                Description = parser.Description,
                SourceCode = parser.SourceCode,
                CompiledAssembly = parser.CompiledAssembly,
                Category = parser.Category,
                Version = parser.Version,
                Author = parser.Author,
                CompilationStatus = parser.CompilationStatus,
                LastCompiled = parser.LastCompiled,
                CompilationErrors = parser.CompilationErrors,
                IsEnabled = parser.IsEnabled,
                ExecutionCount = parser.ExecutionCount,
                LastExecuted = parser.LastExecuted,
                AverageExecutionTime = parser.AverageExecutionTime,
                SuccessRate = parser.SuccessRate,
                CreatedAt = parser.CreatedAt,
                UpdatedAt = parser.UpdatedAt,
                CreatedBy = parser.CreatedBy
            };
        }
    }
}