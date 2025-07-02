using SecuNikLogX.API.Models;

namespace SecuNikLogX.Core.Interfaces
{
    /// <summary>
    /// Service contract for forensics evidence analysis operations and workflow management
    /// </summary>
    public interface IAnalysisService
    {
        #region File Analysis Operations

        /// <summary>
        /// Analyzes a single file for threats and evidence
        /// </summary>
        /// <param name="filePath">Path to the file to analyze</param>
        /// <param name="analysisOptions">Configuration options for the analysis</param>
        /// <param name="cancellationToken">Cancellation token for long-running operations</param>
        /// <returns>Complete analysis result with threat assessment</returns>
        Task<AnalysisResult> AnalyzeFileAsync(string filePath, AnalysisOptions analysisOptions, CancellationToken cancellationToken = default);

        /// <summary>
        /// Analyzes multiple files in batch for efficiency
        /// </summary>
        /// <param name="filePaths">Collection of file paths to analyze</param>
        /// <param name="analysisOptions">Configuration options for batch analysis</param>
        /// <param name="progressCallback">Callback for progress updates</param>
        /// <param name="cancellationToken">Cancellation token for long-running operations</param>
        /// <returns>Collection of analysis results</returns>
        Task<IEnumerable<AnalysisResult>> BatchAnalyzeAsync(IEnumerable<string> filePaths, AnalysisOptions analysisOptions, IProgress<AnalysisProgress>? progressCallback = null, CancellationToken cancellationToken = default);

        /// <summary>
        /// Re-analyzes an existing analysis with updated rules or parsers
        /// </summary>
        /// <param name="analysisId">ID of the analysis to re-run</param>
        /// <param name="forceReanalysis">Whether to force complete re-analysis</param>
        /// <param name="cancellationToken">Cancellation token for long-running operations</param>
        /// <returns>Updated analysis result</returns>
        Task<AnalysisResult> ReanalyzeAsync(Guid analysisId, bool forceReanalysis = false, CancellationToken cancellationToken = default);

        #endregion

        #region CRUD Operations

        /// <summary>
        /// Creates a new analysis record
        /// </summary>
        /// <param name="analysis">Analysis entity to create</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Created analysis with assigned ID</returns>
        Task<Analysis> CreateAnalysisAsync(Analysis analysis, CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves an analysis by its unique identifier
        /// </summary>
        /// <param name="id">Unique identifier of the analysis</param>
        /// <param name="includeRelated">Whether to include related entities (Rules, IOCs, MITRE)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Analysis entity or null if not found</returns>
        Task<Analysis?> GetAnalysisAsync(Guid id, bool includeRelated = false, CancellationToken cancellationToken = default);

        /// <summary>
        /// Updates an existing analysis record
        /// </summary>
        /// <param name="analysis">Analysis entity with updated data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Updated analysis entity</returns>
        Task<Analysis> UpdateAnalysisAsync(Analysis analysis, CancellationToken cancellationToken = default);

        /// <summary>
        /// Soft deletes an analysis and its related data
        /// </summary>
        /// <param name="id">ID of the analysis to delete</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>True if deletion was successful</returns>
        Task<bool> DeleteAnalysisAsync(Guid id, CancellationToken cancellationToken = default);

        #endregion

        #region Query Operations

        /// <summary>
        /// Retrieves analyses within a specific date range
        /// </summary>
        /// <param name="startDate">Start date for the search range</param>
        /// <param name="endDate">End date for the search range</param>
        /// <param name="pageNumber">Page number for pagination</param>
        /// <param name="pageSize">Number of items per page</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Paginated list of analyses</returns>
        Task<PaginatedResult<Analysis>> GetAnalysesByDateRangeAsync(DateTime startDate, DateTime endDate, int pageNumber = 1, int pageSize = 50, CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves analyses filtered by threat level
        /// </summary>
        /// <param name="threatLevel">Minimum threat level to filter by</param>
        /// <param name="pageNumber">Page number for pagination</param>
        /// <param name="pageSize">Number of items per page</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Paginated list of analyses</returns>
        Task<PaginatedResult<Analysis>> GetAnalysesByThreatLevelAsync(ThreatLevel threatLevel, int pageNumber = 1, int pageSize = 50, CancellationToken cancellationToken = default);

        /// <summary>
        /// Searches analyses using flexible criteria
        /// </summary>
        /// <param name="searchCriteria">Search parameters and filters</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Search results with metadata</returns>
        Task<SearchResult<Analysis>> SearchAnalysesAsync(AnalysisSearchCriteria searchCriteria, CancellationToken cancellationToken = default);

        #endregion

        #region Processing Control

        /// <summary>
        /// Starts analysis processing for a queued analysis
        /// </summary>
        /// <param name="analysisId">ID of the analysis to start</param>
        /// <param name="priority">Processing priority level</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Processing status result</returns>
        Task<ProcessingStatus> StartAnalysisAsync(Guid analysisId, ProcessingPriority priority = ProcessingPriority.Normal, CancellationToken cancellationToken = default);

        /// <summary>
        /// Pauses a running analysis operation
        /// </summary>
        /// <param name="analysisId">ID of the analysis to pause</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Updated processing status</returns>
        Task<ProcessingStatus> PauseAnalysisAsync(Guid analysisId, CancellationToken cancellationToken = default);

        /// <summary>
        /// Stops a running analysis operation
        /// </summary>
        /// <param name="analysisId">ID of the analysis to stop</param>
        /// <param name="savePartialResults">Whether to save partial results</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Final processing status</returns>
        Task<ProcessingStatus> StopAnalysisAsync(Guid analysisId, bool savePartialResults = true, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets current progress of a running analysis
        /// </summary>
        /// <param name="analysisId">ID of the analysis to check</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Current progress information</returns>
        Task<AnalysisProgress> GetProgressAsync(Guid analysisId, CancellationToken cancellationToken = default);

        #endregion

        #region Results and Reporting

        /// <summary>
        /// Retrieves comprehensive analysis results
        /// </summary>
        /// <param name="analysisId">ID of the analysis</param>
        /// <param name="includeRawData">Whether to include raw analysis data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Complete analysis results</returns>
        Task<AnalysisResult> GetAnalysisResultsAsync(Guid analysisId, bool includeRawData = false, CancellationToken cancellationToken = default);

        /// <summary>
        /// Exports analysis data in various formats
        /// </summary>
        /// <param name="analysisId">ID of the analysis to export</param>
        /// <param name="exportFormat">Format for export (JSON, XML, CSV, PDF)</param>
        /// <param name="exportOptions">Additional export configuration</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Exported data as byte array</returns>
        Task<ExportResult> ExportAnalysisAsync(Guid analysisId, ExportFormat exportFormat, ExportOptions exportOptions, CancellationToken cancellationToken = default);

        /// <summary>
        /// Generates a comprehensive forensics report
        /// </summary>
        /// <param name="analysisIds">Collection of analysis IDs to include</param>
        /// <param name="reportTemplate">Template for report generation</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Generated report data</returns>
        Task<ReportResult> GenerateReportAsync(IEnumerable<Guid> analysisIds, ReportTemplate reportTemplate, CancellationToken cancellationToken = default);

        #endregion

        #region Relationship Management

        /// <summary>
        /// Finds analyses related to the specified analysis
        /// </summary>
        /// <param name="analysisId">ID of the base analysis</param>
        /// <param name="relationshipTypes">Types of relationships to consider</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Collection of related analyses</returns>
        Task<IEnumerable<AnalysisRelationship>> GetRelatedAnalysesAsync(Guid analysisId, RelationshipType[] relationshipTypes, CancellationToken cancellationToken = default);

        /// <summary>
        /// Links two analyses with a specific relationship type
        /// </summary>
        /// <param name="sourceAnalysisId">ID of the source analysis</param>
        /// <param name="targetAnalysisId">ID of the target analysis</param>
        /// <param name="relationshipType">Type of relationship</param>
        /// <param name="confidence">Confidence in the relationship (0-100)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Created relationship</returns>
        Task<AnalysisRelationship> LinkAnalysisAsync(Guid sourceAnalysisId, Guid targetAnalysisId, RelationshipType relationshipType, int confidence, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets the analysis chain showing related evidence
        /// </summary>
        /// <param name="analysisId">ID of the starting analysis</param>
        /// <param name="maxDepth">Maximum depth to traverse</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Chain of related analyses</returns>
        Task<AnalysisChain> GetAnalysisChainAsync(Guid analysisId, int maxDepth = 5, CancellationToken cancellationToken = default);

        #endregion

        #region Validation and Estimation

        /// <summary>
        /// Validates if a file can be analyzed
        /// </summary>
        /// <param name="filePath">Path to the file to validate</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Validation result with any issues</returns>
        Task<ValidationResult> ValidateFileAsync(string filePath, CancellationToken cancellationToken = default);

        /// <summary>
        /// Checks if the file type is supported for analysis
        /// </summary>
        /// <param name="filePath">Path to the file to check</param>
        /// <param name="mimeType">Optional MIME type override</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Support information and capabilities</returns>
        Task<FileSupportResult> CheckFileSupportAsync(string filePath, string? mimeType = null, CancellationToken cancellationToken = default);

        /// <summary>
        /// Estimates processing time for file analysis
        /// </summary>
        /// <param name="filePath">Path to the file</param>
        /// <param name="analysisOptions">Analysis configuration</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Processing time estimation</returns>
        Task<ProcessingEstimate> EstimateProcessingTimeAsync(string filePath, AnalysisOptions analysisOptions, CancellationToken cancellationToken = default);

        #endregion

        #region Statistics and Metrics

        /// <summary>
        /// Gets comprehensive analysis statistics
        /// </summary>
        /// <param name="dateRange">Optional date range for statistics</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Analysis statistics and metrics</returns>
        Task<AnalysisStatistics> GetAnalysisStatisticsAsync(DateRange? dateRange = null, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets performance metrics for the analysis system
        /// </summary>
        /// <param name="metricsType">Type of metrics to retrieve</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Performance metrics data</returns>
        Task<ProcessingMetrics> GetProcessingMetricsAsync(MetricsType metricsType, CancellationToken cancellationToken = default);

        #endregion
    }

    #region Supporting Types

    /// <summary>
    /// Result of file analysis operation
    /// </summary>
    public class AnalysisResult
    {
        public Guid AnalysisId { get; set; }
        public AnalysisStatus Status { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
        public string? Summary { get; set; }
        public IEnumerable<string> Findings { get; set; } = new List<string>();
        public IEnumerable<IOC> IOCs { get; set; } = new List<IOC>();
        public IEnumerable<MITRE> MITRETechniques { get; set; } = new List<MITRE>();
        public Dictionary<string, object> Metadata { get; set; } = new Dictionary<string, object>();
    }

    /// <summary>
    /// Configuration options for analysis
    /// </summary>
    public class AnalysisOptions
    {
        public bool EnableYaraRules { get; set; } = true;
        public bool EnableSigmaRules { get; set; } = true;
        public bool EnableCustomParsers { get; set; } = true;
        public bool EnableMITREMapping { get; set; } = true;
        public int TimeoutSeconds { get; set; } = 300;
        public string[]? SelectedRuleIds { get; set; }
        public string[]? SelectedParserIds { get; set; }
    }

    /// <summary>
    /// Progress information for analysis operations
    /// </summary>
    public class AnalysisProgress
    {
        public Guid AnalysisId { get; set; }
        public int PercentComplete { get; set; }
        public string CurrentPhase { get; set; } = string.Empty;
        public string? StatusMessage { get; set; }
        public DateTime StartTime { get; set; }
        public TimeSpan ElapsedTime { get; set; }
        public TimeSpan? EstimatedTimeRemaining { get; set; }
    }

    /// <summary>
    /// Processing priority levels
    /// </summary>
    public enum ProcessingPriority
    {
        Low = 0,
        Normal = 1,
        High = 2,
        Critical = 3
    }

    /// <summary>
    /// Export format options
    /// </summary>
    public enum ExportFormat
    {
        JSON = 0,
        XML = 1,
        CSV = 2,
        PDF = 3,
        HTML = 4
    }

    /// <summary>
    /// Types of analysis relationships
    /// </summary>
    public enum RelationshipType
    {
        Similar = 0,
        Related = 1,
        Duplicate = 2,
        Variant = 3,
        Source = 4,
        Target = 5
    }

    /// <summary>
    /// Metrics type enumeration
    /// </summary>
    public enum MetricsType
    {
        Performance = 0,
        Throughput = 1,
        Accuracy = 2,
        Resource = 3
    }

    #endregion
}