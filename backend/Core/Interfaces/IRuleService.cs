using SecuNikLogX.API.Models;

namespace SecuNikLogX.Core.Interfaces
{
    /// <summary>
    /// Service contract for YARA and Sigma rule management, validation, and execution
    /// </summary>
    public interface IRuleService
    {
        #region Rule Lifecycle Management

        /// <summary>
        /// Creates a new rule from source content
        /// </summary>
        /// <param name="rule">Rule entity with content and metadata</param>
        /// <param name="validateSyntax">Whether to validate syntax during creation</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Created rule with validation results</returns>
        Task<RuleCreationResult> CreateRuleAsync(Rule rule, bool validateSyntax = true, CancellationToken cancellationToken = default);

        /// <summary>
        /// Validates rule syntax and structure
        /// </summary>
        /// <param name="ruleId">ID of the rule to validate</param>
        /// <param name="validationLevel">Level of validation to perform</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Validation results with syntax errors and warnings</returns>
        Task<RuleValidationResult> ValidateRuleAsync(Guid ruleId, ValidationLevel validationLevel = ValidationLevel.Full, CancellationToken cancellationToken = default);

        /// <summary>
        /// Tests a rule against sample data before deployment
        /// </summary>
        /// <param name="ruleId">ID of the rule to test</param>
        /// <param name="testData">Sample data for testing</param>
        /// <param name="testOptions">Testing configuration</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Test results and performance metrics</returns>
        Task<RuleTestResult> TestRuleAsync(Guid ruleId, IEnumerable<byte[]> testData, TestOptions testOptions, CancellationToken cancellationToken = default);

        /// <summary>
        /// Deploys a validated rule for production use
        /// </summary>
        /// <param name="ruleId">ID of the rule to deploy</param>
        /// <param name="deploymentOptions">Deployment configuration</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Deployment result and status</returns>
        Task<RuleDeploymentResult> DeployRuleAsync(Guid ruleId, RuleDeploymentOptions deploymentOptions, CancellationToken cancellationToken = default);

        #endregion

        #region CRUD Operations

        /// <summary>
        /// Retrieves a rule by its unique identifier
        /// </summary>
        /// <param name="id">Unique identifier of the rule</param>
        /// <param name="includeContent">Whether to include rule content in result</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Rule entity or null if not found</returns>
        Task<Rule?> GetRuleAsync(Guid id, bool includeContent = false, CancellationToken cancellationToken = default);

        /// <summary>
        /// Updates an existing rule
        /// </summary>
        /// <param name="rule">Rule entity with updated data</param>
        /// <param name="revalidateIfNeeded">Whether to revalidate if content changed</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Updated rule entity</returns>
        Task<Rule> UpdateRuleAsync(Rule rule, bool revalidateIfNeeded = true, CancellationToken cancellationToken = default);

        /// <summary>
        /// Soft deletes a rule
        /// </summary>
        /// <param name="id">ID of the rule to delete</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>True if deletion was successful</returns>
        Task<bool> DeleteRuleAsync(Guid id, CancellationToken cancellationToken = default);

        /// <summary>
        /// Lists rules with optional filtering and pagination
        /// </summary>
        /// <param name="filter">Optional filter criteria</param>
        /// <param name="pageNumber">Page number for pagination</param>
        /// <param name="pageSize">Number of items per page</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Paginated list of rules</returns>
        Task<PaginatedResult<Rule>> ListRulesAsync(RuleFilter? filter = null, int pageNumber = 1, int pageSize = 50, CancellationToken cancellationToken = default);

        #endregion

        #region Rule Syntax Validation

        /// <summary>
        /// Validates rule syntax based on rule type
        /// </summary>
        /// <param name="content">Rule content to validate</param>
        /// <param name="ruleType">Type of rule (YARA or Sigma)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Syntax validation results</returns>
        Task<SyntaxValidationResult> ValidateSyntaxAsync(string content, RuleType ruleType, CancellationToken cancellationToken = default);

        /// <summary>
        /// Tests rule execution without full analysis
        /// </summary>
        /// <param name="content">Rule content to test</param>
        /// <param name="ruleType">Type of rule</param>
        /// <param name="testData">Data to test against</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Test execution results</returns>
        Task<RuleTestResult> TestRuleAsync(string content, RuleType ruleType, byte[] testData, CancellationToken cancellationToken = default);

        /// <summary>
        /// Checks rule performance characteristics
        /// </summary>
        /// <param name="ruleId">ID of the rule to check</param>
        /// <param name="performanceOptions">Performance testing options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Performance analysis results</returns>
        Task<RulePerformanceResult> CheckPerformanceAsync(Guid ruleId, PerformanceOptions performanceOptions, CancellationToken cancellationToken = default);

        #endregion

        #region Rule Execution

        /// <summary>
        /// Executes a rule against input data
        /// </summary>
        /// <param name="ruleId">ID of the rule to execute</param>
        /// <param name="inputData">Data to analyze</param>
        /// <param name="executionOptions">Execution configuration</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Execution result with matches</returns>
        Task<RuleExecutionResult> ExecuteRuleAsync(Guid ruleId, byte[] inputData, RuleExecutionOptions executionOptions, CancellationToken cancellationToken = default);

        /// <summary>
        /// Executes multiple rules against data in batch
        /// </summary>
        /// <param name="ruleIds">Collection of rule IDs to execute</param>
        /// <param name="inputData">Data to analyze</param>
        /// <param name="executionOptions">Execution configuration</param>
        /// <param name="progressCallback">Callback for progress updates</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Collection of execution results</returns>
        Task<IEnumerable<RuleExecutionResult>> BatchExecuteAsync(IEnumerable<Guid> ruleIds, byte[] inputData, RuleExecutionOptions executionOptions, IProgress<RuleExecutionProgress>? progressCallback = null, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets match results from a completed rule execution
        /// </summary>
        /// <param name="executionId">ID of the execution to retrieve</param>
        /// <param name="includeMatchDetails">Whether to include detailed match information</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Match results and metadata</returns>
        Task<RuleMatchResult> GetMatchResultsAsync(Guid executionId, bool includeMatchDetails = false, CancellationToken cancellationToken = default);

        #endregion

        #region Rule Status Management

        /// <summary>
        /// Enables a rule for production use
        /// </summary>
        /// <param name="ruleId">ID of the rule to enable</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Updated rule status</returns>
        Task<RuleStatus> EnableRuleAsync(Guid ruleId, CancellationToken cancellationToken = default);

        /// <summary>
        /// Disables a rule from production use
        /// </summary>
        /// <param name="ruleId">ID of the rule to disable</param>
        /// <param name="reason">Reason for disabling</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Updated rule status</returns>
        Task<RuleStatus> DisableRuleAsync(Guid ruleId, string? reason = null, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets current status of a rule
        /// </summary>
        /// <param name="ruleId">ID of the rule to check</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Current rule status and health</returns>
        Task<RuleStatus> GetRuleStatusAsync(Guid ruleId, CancellationToken cancellationToken = default);

        #endregion

        #region Import/Export Operations

        /// <summary>
        /// Imports rules from various sources and formats
        /// </summary>
        /// <param name="importSource">Source of rules to import</param>
        /// <param name="importOptions">Import configuration options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Import results with created rules</returns>
        Task<RuleImportResult> ImportRuleSetAsync(RuleImportSource importSource, ImportOptions importOptions, CancellationToken cancellationToken = default);

        /// <summary>
        /// Exports rules to various formats
        /// </summary>
        /// <param name="ruleIds">Collection of rule IDs to export</param>
        /// <param name="exportFormat">Format for export</param>
        /// <param name="exportOptions">Export configuration</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Exported rule data</returns>
        Task<RuleExportResult> ExportRulesAsync(IEnumerable<Guid> ruleIds, RuleExportFormat exportFormat, ExportOptions exportOptions, CancellationToken cancellationToken = default);

        /// <summary>
        /// Synchronizes rules with external rule repositories
        /// </summary>
        /// <param name="repositoryConfig">Repository configuration</param>
        /// <param name="syncOptions">Synchronization options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Synchronization results</returns>
        Task<RuleSyncResult> SyncRulebaseAsync(RepositoryConfig repositoryConfig, SyncOptions syncOptions, CancellationToken cancellationToken = default);

        #endregion

        #region Performance and Optimization

        /// <summary>
        /// Benchmarks rule performance with test data
        /// </summary>
        /// <param name="ruleId">ID of the rule to benchmark</param>
        /// <param name="benchmarkData">Test data for benchmarking</param>
        /// <param name="benchmarkOptions">Benchmark configuration</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Performance benchmark results</returns>
        Task<RuleBenchmarkResult> BenchmarkRuleAsync(Guid ruleId, IEnumerable<byte[]> benchmarkData, BenchmarkOptions benchmarkOptions, CancellationToken cancellationToken = default);

        /// <summary>
        /// Optimizes rule content for better performance
        /// </summary>
        /// <param name="ruleId">ID of the rule to optimize</param>
        /// <param name="optimizationLevel">Level of optimization to apply</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Optimization results and recommendations</returns>
        Task<RuleOptimizationResult> OptimizeRuleAsync(Guid ruleId, OptimizationLevel optimizationLevel, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets execution statistics for a rule
        /// </summary>
        /// <param name="ruleId">ID of the rule</param>
        /// <param name="statsTimeRange">Time range for statistics</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Execution statistics and performance metrics</returns>
        Task<RuleExecutionStats> GetExecutionStatsAsync(Guid ruleId, TimeRange statsTimeRange, CancellationToken cancellationToken = default);

        #endregion

        #region Rule Categorization

        /// <summary>
        /// Categorizes a rule based on its content and metadata
        /// </summary>
        /// <param name="ruleId">ID of the rule to categorize</param>
        /// <param name="categorizationOptions">Categorization configuration</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Categorization results</returns>
        Task<RuleCategorizationResult> CategorizeRuleAsync(Guid ruleId, CategorizationOptions categorizationOptions, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets rules by category with filtering
        /// </summary>
        /// <param name="category">Category to filter by</param>
        /// <param name="subcategory">Optional subcategory filter</param>
        /// <param name="pageNumber">Page number for pagination</param>
        /// <param name="pageSize">Number of items per page</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Paginated list of rules in category</returns>
        Task<PaginatedResult<Rule>> GetRulesByCategoryAsync(string category, string? subcategory = null, int pageNumber = 1, int pageSize = 50, CancellationToken cancellationToken = default);

        /// <summary>
        /// Updates the category of a rule
        /// </summary>
        /// <param name="ruleId">ID of the rule to update</param>
        /// <param name="newCategory">New category assignment</param>
        /// <param name="reason">Reason for category change</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Updated rule with new category</returns>
        Task<Rule> UpdateCategoryAsync(Guid ruleId, string newCategory, string? reason = null, CancellationToken cancellationToken = default);

        #endregion

        #region Version Control

        /// <summary>
        /// Gets version history for a rule
        /// </summary>
        /// <param name="ruleId">ID of the rule</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Version history with changes</returns>
        Task<IEnumerable<RuleVersion>> GetRuleVersionsAsync(Guid ruleId, CancellationToken cancellationToken = default);

        /// <summary>
        /// Creates a new version of a rule
        /// </summary>
        /// <param name="ruleId">ID of the rule</param>
        /// <param name="versionInfo">Version information and changes</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Created version information</returns>
        Task<RuleVersion> CreateVersionAsync(Guid ruleId, VersionInfo versionInfo, CancellationToken cancellationToken = default);

        /// <summary>
        /// Compares two versions of a rule
        /// </summary>
        /// <param name="ruleId">ID of the rule</param>
        /// <param name="version1">First version to compare</param>
        /// <param name="version2">Second version to compare</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Comparison results with differences</returns>
        Task<RuleVersionComparison> CompareVersionsAsync(Guid ruleId, string version1, string version2, CancellationToken cancellationToken = default);

        #endregion

        #region Threat Intelligence Integration

        /// <summary>
        /// Enriches rule with threat intelligence data
        /// </summary>
        /// <param name="ruleId">ID of the rule to enrich</param>
        /// <param name="threatIntelSources">Sources for threat intelligence</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Enrichment results with threat context</returns>
        Task<RuleEnrichmentResult> EnrichRuleAsync(Guid ruleId, IEnumerable<ThreatIntelSource> threatIntelSources, CancellationToken cancellationToken = default);

        /// <summary>
        /// Updates rule with latest threat intelligence data
        /// </summary>
        /// <param name="ruleId">ID of the rule to update</param>
        /// <param name="threatData">Latest threat intelligence data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Update result with changes</returns>
        Task<ThreatDataUpdateResult> UpdateThreatDataAsync(Guid ruleId, ThreatIntelligenceData threatData, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets threat context for a rule
        /// </summary>
        /// <param name="ruleId">ID of the rule</param>
        /// <param name="contextDepth">Depth of context to retrieve</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Threat context and intelligence</returns>
        Task<ThreatContext> GetThreatContextAsync(Guid ruleId, ContextDepth contextDepth, CancellationToken cancellationToken = default);

        #endregion
    }

    #region Supporting Types

    /// <summary>
    /// Result of rule creation operation
    /// </summary>
    public class RuleCreationResult
    {
        public Rule Rule { get; set; } = new();
        public bool Success { get; set; }
        public IEnumerable<string> ValidationErrors { get; set; } = new List<string>();
        public IEnumerable<string> Warnings { get; set; } = new List<string>();
        public RuleMetadata Metadata { get; set; } = new();
    }

    /// <summary>
    /// Rule validation result
    /// </summary>
    public class RuleValidationResult
    {
        public bool IsValid { get; set; }
        public IEnumerable<ValidationError> SyntaxErrors { get; set; } = new List<ValidationError>();
        public IEnumerable<ValidationWarning> Warnings { get; set; } = new List<ValidationWarning>();
        public RuleComplexity Complexity { get; set; } = new();
        public PerformanceEstimate PerformanceEstimate { get; set; } = new();
    }

    /// <summary>
    /// Rule test result
    /// </summary>
    public class RuleTestResult
    {
        public Guid TestId { get; set; }
        public bool Success { get; set; }
        public int MatchCount { get; set; }
        public IEnumerable<RuleMatch> Matches { get; set; } = new List<RuleMatch>();
        public TimeSpan ExecutionTime { get; set; }
        public long MemoryUsed { get; set; }
        public string? ErrorMessage { get; set; }
    }

    /// <summary>
    /// Rule execution result
    /// </summary>
    public class RuleExecutionResult
    {
        public Guid ExecutionId { get; set; }
        public Guid RuleId { get; set; }
        public bool Success { get; set; }
        public bool HasMatches { get; set; }
        public int MatchCount { get; set; }
        public IEnumerable<RuleMatch> Matches { get; set; } = new List<RuleMatch>();
        public TimeSpan ExecutionTime { get; set; }
        public long MemoryUsed { get; set; }
        public string? ErrorMessage { get; set; }
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    /// <summary>
    /// Rule status information
    /// </summary>
    public class RuleStatus
    {
        public Guid RuleId { get; set; }
        public bool IsActive { get; set; }
        public bool SyntaxValid { get; set; }
        public DateTime LastValidated { get; set; }
        public DateTime LastUsed { get; set; }
        public long HitCount { get; set; }
        public string? StatusMessage { get; set; }
        public RuleHealthStatus Health { get; set; }
    }

    /// <summary>
    /// Filter criteria for rule queries
    /// </summary>
    public class RuleFilter
    {
        public RuleType? RuleType { get; set; }
        public RuleSeverity? MinSeverity { get; set; }
        public bool? IsActive { get; set; }
        public string? Author { get; set; }
        public string? Category { get; set; }
        public string? Platform { get; set; }
        public DateTime? CreatedAfter { get; set; }
        public DateTime? CreatedBefore { get; set; }
        public string? SearchText { get; set; }
    }

    /// <summary>
    /// Rule import source configuration
    /// </summary>
    public class RuleImportSource
    {
        public ImportSourceType SourceType { get; set; }
        public string SourcePath { get; set; } = string.Empty;
        public Dictionary<string, string> Authentication { get; set; } = new();
        public IEnumerable<string> IncludePatterns { get; set; } = new List<string>();
        public IEnumerable<string> ExcludePatterns { get; set; } = new List<string>();
    }

    /// <summary>
    /// Export formats for rules
    /// </summary>
    public enum RuleExportFormat
    {
        Native = 0,
        JSON = 1,
        XML = 2,
        YAML = 3,
        Archive = 4
    }

    /// <summary>
    /// Import source types
    /// </summary>
    public enum ImportSourceType
    {
        File = 0,
        Directory = 1,
        URL = 2,
        Repository = 3,
        Database = 4
    }

    /// <summary>
    /// Rule health status
    /// </summary>
    public enum RuleHealthStatus
    {
        Unknown = 0,
        Healthy = 1,
        Warning = 2,
        Error = 3,
        Deprecated = 4
    }

    /// <summary>
    /// Context depth for threat intelligence
    /// </summary>
    public enum ContextDepth
    {
        Basic = 0,
        Standard = 1,
        Detailed = 2,
        Comprehensive = 3
    }

    /// <summary>
    /// Rule execution progress information
    /// </summary>
    public class RuleExecutionProgress
    {
        public int TotalRules { get; set; }
        public int CompletedRules { get; set; }
        public int PercentComplete { get; set; }
        public string CurrentRule { get; set; } = string.Empty;
        public TimeSpan ElapsedTime { get; set; }
        public TimeSpan? EstimatedTimeRemaining { get; set; }
    }

    #endregion
}