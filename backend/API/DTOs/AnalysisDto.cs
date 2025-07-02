using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace SecuNikLogX.API.DTOs
{
    /// <summary>
    /// Data Transfer Objects for Analysis API requests and responses
    /// </summary>

    /// <summary>
    /// Request for creating a new analysis
    /// </summary>
    public class AnalysisCreateRequest
    {
        /// <summary>
        /// File path for the evidence file to analyze
        /// </summary>
        [Required(ErrorMessage = "File path is required")]
        [StringLength(500, ErrorMessage = "File path cannot exceed 500 characters")]
        public string FilePath { get; set; } = string.Empty;

        /// <summary>
        /// Original name of the file
        /// </summary>
        [Required(ErrorMessage = "File name is required")]
        [StringLength(255, ErrorMessage = "File name cannot exceed 255 characters")]
        public string FileName { get; set; } = string.Empty;

        /// <summary>
        /// Size of the file in bytes
        /// </summary>
        [Range(1, long.MaxValue, ErrorMessage = "File size must be greater than 0")]
        public long FileSize { get; set; }

        /// <summary>
        /// SHA256 hash of the file
        /// </summary>
        [Required(ErrorMessage = "File hash is required")]
        [RegularExpression(@"^[a-fA-F0-9]{64}$", ErrorMessage = "File hash must be a valid SHA256 hash")]
        public string FileHash { get; set; } = string.Empty;

        /// <summary>
        /// Type of analysis to perform
        /// </summary>
        [Required(ErrorMessage = "Analysis type is required")]
        [StringLength(50, ErrorMessage = "Analysis type cannot exceed 50 characters")]
        public string AnalysisType { get; set; } = string.Empty;

        /// <summary>
        /// Priority level of the analysis
        /// </summary>
        [Range(1, 5, ErrorMessage = "Priority must be between 1 and 5")]
        public int Priority { get; set; } = 3;

        /// <summary>
        /// Optional notes for the analysis
        /// </summary>
        [StringLength(1000, ErrorMessage = "Notes cannot exceed 1000 characters")]
        public string? Notes { get; set; }

        /// <summary>
        /// Configuration parameters for the analysis
        /// </summary>
        public Dictionary<string, object>? Configuration { get; set; }
    }

    /// <summary>
    /// Request for updating an existing analysis
    /// </summary>
    public class AnalysisUpdateRequest
    {
        /// <summary>
        /// Updated priority level
        /// </summary>
        [Range(1, 5, ErrorMessage = "Priority must be between 1 and 5")]
        public int? Priority { get; set; }

        /// <summary>
        /// Updated notes
        /// </summary>
        [StringLength(1000, ErrorMessage = "Notes cannot exceed 1000 characters")]
        public string? Notes { get; set; }

        /// <summary>
        /// Updated threat level assessment
        /// </summary>
        [StringLength(50, ErrorMessage = "Threat level cannot exceed 50 characters")]
        public string? ThreatLevel { get; set; }

        /// <summary>
        /// Additional metadata for the analysis
        /// </summary>
        public Dictionary<string, object>? Metadata { get; set; }
    }

    /// <summary>
    /// Complete analysis response data
    /// </summary>
    public class AnalysisResponse
    {
        /// <summary>
        /// Unique identifier for the analysis
        /// </summary>
        public Guid Id { get; set; }

        /// <summary>
        /// File path of the analyzed evidence
        /// </summary>
        public string FilePath { get; set; } = string.Empty;

        /// <summary>
        /// Original file name
        /// </summary>
        public string FileName { get; set; } = string.Empty;

        /// <summary>
        /// File size in bytes
        /// </summary>
        public long FileSize { get; set; }

        /// <summary>
        /// SHA256 hash of the file
        /// </summary>
        public string FileHash { get; set; } = string.Empty;

        /// <summary>
        /// Detected or specified file type
        /// </summary>
        public string? FileType { get; set; }

        /// <summary>
        /// Current status of the analysis
        /// </summary>
        public string Status { get; set; } = string.Empty;

        /// <summary>
        /// Priority level (1-5)
        /// </summary>
        public int Priority { get; set; }

        /// <summary>
        /// Threat level assessment
        /// </summary>
        public string? ThreatLevel { get; set; }

        /// <summary>
        /// Progress percentage (0-100)
        /// </summary>
        public decimal Progress { get; set; }

        /// <summary>
        /// Analysis start time
        /// </summary>
        public DateTime? StartTime { get; set; }

        /// <summary>
        /// Analysis completion time
        /// </summary>
        public DateTime? EndTime { get; set; }

        /// <summary>
        /// Total analysis duration
        /// </summary>
        public TimeSpan? Duration { get; set; }

        /// <summary>
        /// Summary of analysis results
        /// </summary>
        public string? ResultSummary { get; set; }

        /// <summary>
        /// Error message if analysis failed
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// Additional notes
        /// </summary>
        public string? Notes { get; set; }

        /// <summary>
        /// Analysis creation timestamp
        /// </summary>
        public DateTime CreatedAt { get; set; }

        /// <summary>
        /// Last update timestamp
        /// </summary>
        public DateTime UpdatedAt { get; set; }

        /// <summary>
        /// User who created the analysis
        /// </summary>
        public string? CreatedBy { get; set; }

        /// <summary>
        /// Related IOCs found during analysis
        /// </summary>
        public List<IocSummary>? IOCs { get; set; }

        /// <summary>
        /// MITRE ATT&CK techniques identified
        /// </summary>
        public List<MitreSummary>? MitreTechniques { get; set; }

        /// <summary>
        /// Rules that triggered during analysis
        /// </summary>
        public List<RuleSummary>? TriggeredRules { get; set; }
    }

    /// <summary>
    /// Paginated list of analyses
    /// </summary>
    public class AnalysisListResponse
    {
        /// <summary>
        /// List of analyses for the current page
        /// </summary>
        public List<AnalysisResponse> Analyses { get; set; } = new();

        /// <summary>
        /// Total number of analyses matching the criteria
        /// </summary>
        public int TotalCount { get; set; }

        /// <summary>
        /// Current page number
        /// </summary>
        public int PageNumber { get; set; }

        /// <summary>
        /// Number of items per page
        /// </summary>
        public int PageSize { get; set; }

        /// <summary>
        /// Total number of pages
        /// </summary>
        public int TotalPages => (int)Math.Ceiling((double)TotalCount / PageSize);

        /// <summary>
        /// Whether there is a next page
        /// </summary>
        public bool HasNextPage => PageNumber < TotalPages;

        /// <summary>
        /// Whether there is a previous page
        /// </summary>
        public bool HasPreviousPage => PageNumber > 1;
    }

    /// <summary>
    /// Detailed analysis results with findings and threat assessment
    /// </summary>
    public class AnalysisResultResponse
    {
        /// <summary>
        /// Analysis identifier
        /// </summary>
        public Guid AnalysisId { get; set; }

        /// <summary>
        /// Overall threat assessment
        /// </summary>
        public ThreatAssessment ThreatAssessment { get; set; } = new();

        /// <summary>
        /// Detailed findings from the analysis
        /// </summary>
        public List<Finding> Findings { get; set; } = new();

        /// <summary>
        /// IOCs discovered during analysis
        /// </summary>
        public List<IocDetail> IOCs { get; set; } = new();

        /// <summary>
        /// MITRE ATT&CK techniques mapped
        /// </summary>
        public List<MitreDetail> MitreTechniques { get; set; } = new();

        /// <summary>
        /// Rules that were triggered
        /// </summary>
        public List<RuleResult> RuleResults { get; set; } = new();

        /// <summary>
        /// File metadata and properties
        /// </summary>
        public FileAnalysisMetadata FileMetadata { get; set; } = new();

        /// <summary>
        /// Analysis execution details
        /// </summary>
        public AnalysisExecution ExecutionDetails { get; set; } = new();

        /// <summary>
        /// Recommended actions based on findings
        /// </summary>
        public List<RecommendedAction> RecommendedActions { get; set; } = new();

        /// <summary>
        /// Confidence score for the analysis results
        /// </summary>
        [Range(0, 100)]
        public decimal ConfidenceScore { get; set; }

        /// <summary>
        /// Timestamp when results were generated
        /// </summary>
        public DateTime GeneratedAt { get; set; }
    }

    /// <summary>
    /// Real-time progress information for long-running analysis
    /// </summary>
    public class AnalysisProgressResponse
    {
        /// <summary>
        /// Analysis identifier
        /// </summary>
        public Guid AnalysisId { get; set; }

        /// <summary>
        /// Current status of the analysis
        /// </summary>
        public string Status { get; set; } = string.Empty;

        /// <summary>
        /// Progress percentage (0-100)
        /// </summary>
        [Range(0, 100)]
        public decimal ProgressPercentage { get; set; }

        /// <summary>
        /// Current analysis phase
        /// </summary>
        public string CurrentPhase { get; set; } = string.Empty;

        /// <summary>
        /// Estimated time remaining
        /// </summary>
        public TimeSpan? EstimatedTimeRemaining { get; set; }

        /// <summary>
        /// Elapsed time since analysis started
        /// </summary>
        public TimeSpan ElapsedTime { get; set; }

        /// <summary>
        /// Current operation being performed
        /// </summary>
        public string? CurrentOperation { get; set; }

        /// <summary>
        /// Progress details for different analysis components
        /// </summary>
        public Dictionary<string, decimal> ComponentProgress { get; set; } = new();

        /// <summary>
        /// Intermediate findings discovered so far
        /// </summary>
        public List<IntermediateFinding> IntermediateFindings { get; set; } = new();

        /// <summary>
        /// Timestamp of last progress update
        /// </summary>
        public DateTime LastUpdated { get; set; }
    }

    /// <summary>
    /// Aggregated statistics and metrics for analyses
    /// </summary>
    public class AnalysisStatisticsResponse
    {
        /// <summary>
        /// Total number of analyses performed
        /// </summary>
        public int TotalAnalyses { get; set; }

        /// <summary>
        /// Number of completed analyses
        /// </summary>
        public int CompletedAnalyses { get; set; }

        /// <summary>
        /// Number of failed analyses
        /// </summary>
        public int FailedAnalyses { get; set; }

        /// <summary>
        /// Number of currently running analyses
        /// </summary>
        public int RunningAnalyses { get; set; }

        /// <summary>
        /// Average analysis duration
        /// </summary>
        public TimeSpan AverageAnalysisDuration { get; set; }

        /// <summary>
        /// Distribution of analyses by threat level
        /// </summary>
        public Dictionary<string, int> ThreatLevelDistribution { get; set; } = new();

        /// <summary>
        /// Distribution of analyses by file type
        /// </summary>
        public Dictionary<string, int> FileTypeDistribution { get; set; } = new();

        /// <summary>
        /// Analysis volume over time
        /// </summary>
        public List<AnalysisVolumePoint> VolumeOverTime { get; set; } = new();

        /// <summary>
        /// Top IOCs discovered across all analyses
        /// </summary>
        public List<TopIoc> TopIOCs { get; set; } = new();

        /// <summary>
        /// Most frequently triggered rules
        /// </summary>
        public List<TopRule> TopRules { get; set; } = new();

        /// <summary>
        /// System performance metrics
        /// </summary>
        public PerformanceMetrics Performance { get; set; } = new();

        /// <summary>
        /// Timestamp when statistics were generated
        /// </summary>
        public DateTime GeneratedAt { get; set; }
    }

    /// <summary>
    /// File upload request for analysis
    /// </summary>
    public class FileUploadRequest
    {
        /// <summary>
        /// The file to upload and analyze
        /// </summary>
        [Required(ErrorMessage = "File is required")]
        public IFormFile File { get; set; } = null!;

        /// <summary>
        /// Type of analysis to perform
        /// </summary>
        [Required(ErrorMessage = "Analysis type is required")]
        [StringLength(50, ErrorMessage = "Analysis type cannot exceed 50 characters")]
        public string AnalysisType { get; set; } = string.Empty;

        /// <summary>
        /// Priority level for the analysis
        /// </summary>
        [Range(1, 5, ErrorMessage = "Priority must be between 1 and 5")]
        public int Priority { get; set; } = 3;

        /// <summary>
        /// Optional description for the analysis
        /// </summary>
        [StringLength(500, ErrorMessage = "Description cannot exceed 500 characters")]
        public string? Description { get; set; }

        /// <summary>
        /// Analysis configuration parameters
        /// </summary>
        public Dictionary<string, object>? Configuration { get; set; }

        /// <summary>
        /// Whether to preserve the original filename
        /// </summary>
        public bool PreserveOriginalName { get; set; } = false;

        /// <summary>
        /// Tags to associate with the analysis
        /// </summary>
        public List<string>? Tags { get; set; }
    }

    #region Supporting DTOs

    /// <summary>
    /// Summary information for an IOC
    /// </summary>
    public class IocSummary
    {
        public Guid Id { get; set; }
        public string Type { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string ThreatLevel { get; set; } = string.Empty;
        public decimal Confidence { get; set; }
    }

    /// <summary>
    /// Summary information for a MITRE technique
    /// </summary>
    public class MitreSummary
    {
        public string TechniqueId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Tactic { get; set; } = string.Empty;
        public decimal Confidence { get; set; }
    }

    /// <summary>
    /// Summary information for a triggered rule
    /// </summary>
    public class RuleSummary
    {
        public Guid RuleId { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public int MatchCount { get; set; }
    }

    /// <summary>
    /// Threat assessment details
    /// </summary>
    public class ThreatAssessment
    {
        public string ThreatLevel { get; set; } = string.Empty;
        public decimal RiskScore { get; set; }
        public string RiskCategory { get; set; } = string.Empty;
        public List<string> ThreatIndicators { get; set; } = new();
        public string Summary { get; set; } = string.Empty;
    }

    /// <summary>
    /// Individual finding from analysis
    /// </summary>
    public class Finding
    {
        public Guid Id { get; set; }
        public string Type { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public decimal Confidence { get; set; }
        public Dictionary<string, object> Evidence { get; set; } = new();
        public DateTime DiscoveredAt { get; set; }
    }

    /// <summary>
    /// Detailed IOC information
    /// </summary>
    public class IocDetail
    {
        public Guid Id { get; set; }
        public string Type { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public string ThreatLevel { get; set; } = string.Empty;
        public decimal Confidence { get; set; }
        public Dictionary<string, object> EnrichmentData { get; set; } = new();
        public List<string> Tags { get; set; } = new();
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
    }

    /// <summary>
    /// Detailed MITRE technique information
    /// </summary>
    public class MitreDetail
    {
        public string TechniqueId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Tactic { get; set; } = string.Empty;
        public List<string> SubTechniques { get; set; } = new();
        public decimal Confidence { get; set; }
        public List<string> Evidence { get; set; } = new();
    }

    /// <summary>
    /// Rule execution result
    /// </summary>
    public class RuleResult
    {
        public Guid RuleId { get; set; }
        public string RuleName { get; set; } = string.Empty;
        public string RuleType { get; set; } = string.Empty;
        public bool Matched { get; set; }
        public int MatchCount { get; set; }
        public List<RuleMatch> Matches { get; set; } = new();
        public TimeSpan ExecutionTime { get; set; }
    }

    /// <summary>
    /// Individual rule match
    /// </summary>
    public class RuleMatch
    {
        public string Pattern { get; set; } = string.Empty;
        public long Offset { get; set; }
        public int Length { get; set; }
        public string Context { get; set; } = string.Empty;
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    /// <summary>
    /// File analysis metadata
    /// </summary>
    public class FileAnalysisMetadata
    {
        public string FileType { get; set; } = string.Empty;
        public long FileSize { get; set; }
        public string Hash { get; set; } = string.Empty;
        public decimal Entropy { get; set; }
        public Dictionary<string, object> Properties { get; set; } = new();
        public List<string> Signatures { get; set; } = new();
    }

    /// <summary>
    /// Analysis execution details
    /// </summary>
    public class AnalysisExecution
    {
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public string Status { get; set; } = string.Empty;
        public List<string> PhasesCompleted { get; set; } = new();
        public Dictionary<string, TimeSpan> PhaseTimings { get; set; } = new();
        public string? ErrorMessage { get; set; }
    }

    /// <summary>
    /// Recommended action based on analysis
    /// </summary>
    public class RecommendedAction
    {
        public string Action { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Priority { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public List<string> Steps { get; set; } = new();
    }

    /// <summary>
    /// Intermediate finding during analysis
    /// </summary>
    public class IntermediateFinding
    {
        public string Type { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public decimal Confidence { get; set; }
        public DateTime DiscoveredAt { get; set; }
    }

    /// <summary>
    /// Analysis volume data point
    /// </summary>
    public class AnalysisVolumePoint
    {
        public DateTime Timestamp { get; set; }
        public int Count { get; set; }
        public TimeSpan AverageDuration { get; set; }
    }

    /// <summary>
    /// Top IOC statistics
    /// </summary>
    public class TopIoc
    {
        public string Type { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public int Occurrences { get; set; }
        public string ThreatLevel { get; set; } = string.Empty;
    }

    /// <summary>
    /// Top rule statistics
    /// </summary>
    public class TopRule
    {
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public int Triggers { get; set; }
        public decimal SuccessRate { get; set; }
    }

    /// <summary>
    /// Performance metrics
    /// </summary>
    public class PerformanceMetrics
    {
        public TimeSpan AverageAnalysisTime { get; set; }
        public decimal ThroughputPerHour { get; set; }
        public decimal SuccessRate { get; set; }
        public decimal SystemLoad { get; set; }
        public long MemoryUsage { get; set; }
    }

    #endregion
}