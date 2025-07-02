using SecuNikLogX.API.Models;

namespace SecuNikLogX.Core.Interfaces
{
    /// <summary>
    /// Service contract for custom C# parser management, compilation, and execution
    /// </summary>
    public interface IParserService
    {
        #region Parser Lifecycle Management

        /// <summary>
        /// Creates a new parser from source code
        /// </summary>
        /// <param name="parser">Parser entity with source code and metadata</param>
        /// <param name="validateSyntax">Whether to validate syntax during creation</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Created parser with validation results</returns>
        Task<ParserCreationResult> CreateParserAsync(Parser parser, bool validateSyntax = true, CancellationToken cancellationToken = default);

        /// <summary>
        /// Compiles a parser from C# source code to executable assembly
        /// </summary>
        /// <param name="parserId">ID of the parser to compile</param>
        /// <param name="compilationOptions">Compilation configuration options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Compilation result with status and any errors</returns>
        Task<CompilationResult> CompileParserAsync(Guid parserId, CompilationOptions compilationOptions, CancellationToken cancellationToken = default);

        /// <summary>
        /// Tests a parser with sample data before deployment
        /// </summary>
        /// <param name="parserId">ID of the parser to test</param>
        /// <param name="testData">Sample data for testing</param>
        /// <param name="testOptions">Testing configuration</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Test results and performance metrics</returns>
        Task<ParserTestResult> TestParserAsync(Guid parserId, byte[] testData, TestOptions testOptions, CancellationToken cancellationToken = default);

        /// <summary>
        /// Deploys a compiled parser for production use
        /// </summary>
        /// <param name="parserId">ID of the parser to deploy</param>
        /// <param name="deploymentOptions">Deployment configuration</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Deployment result and status</returns>
        Task<DeploymentResult> DeployParserAsync(Guid parserId, DeploymentOptions deploymentOptions, CancellationToken cancellationToken = default);

        #endregion

        #region CRUD Operations

        /// <summary>
        /// Retrieves a parser by its unique identifier
        /// </summary>
        /// <param name="id">Unique identifier of the parser</param>
        /// <param name="includeSourceCode">Whether to include source code in result</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Parser entity or null if not found</returns>
        Task<Parser?> GetParserAsync(Guid id, bool includeSourceCode = false, CancellationToken cancellationToken = default);

        /// <summary>
        /// Updates an existing parser
        /// </summary>
        /// <param name="parser">Parser entity with updated data</param>
        /// <param name="recompileIfNeeded">Whether to recompile if source changed</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Updated parser entity</returns>
        Task<Parser> UpdateParserAsync(Parser parser, bool recompileIfNeeded = true, CancellationToken cancellationToken = default);

        /// <summary>
        /// Soft deletes a parser and its compiled assembly
        /// </summary>
        /// <param name="id">ID of the parser to delete</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>True if deletion was successful</returns>
        Task<bool> DeleteParserAsync(Guid id, CancellationToken cancellationToken = default);

        /// <summary>
        /// Lists parsers with optional filtering and pagination
        /// </summary>
        /// <param name="filter">Optional filter criteria</param>
        /// <param name="pageNumber">Page number for pagination</param>
        /// <param name="pageSize">Number of items per page</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Paginated list of parsers</returns>
        Task<PaginatedResult<Parser>> ListParsersAsync(ParserFilter? filter = null, int pageNumber = 1, int pageSize = 50, CancellationToken cancellationToken = default);

        #endregion

        #region Compilation Management

        /// <summary>
        /// Validates C# source code syntax and structure
        /// </summary>
        /// <param name="sourceCode">C# source code to validate</param>
        /// <param name="validationLevel">Level of validation to perform</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Validation results with syntax errors and warnings</returns>
        Task<CodeValidationResult> ValidateCodeAsync(string sourceCode, ValidationLevel validationLevel = ValidationLevel.Full, CancellationToken cancellationToken = default);

        /// <summary>
        /// Compiles C# source code to assembly
        /// </summary>
        /// <param name="sourceCode">C# source code to compile</param>
        /// <param name="compilationOptions">Compilation configuration</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Compilation result with assembly or errors</returns>
        Task<CompilationResult> CompileAsync(string sourceCode, CompilationOptions compilationOptions, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets compilation errors for a failed compilation
        /// </summary>
        /// <param name="parserId">ID of the parser with compilation errors</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Detailed compilation error information</returns>
        Task<IEnumerable<CompilationError>> GetCompilationErrorsAsync(Guid parserId, CancellationToken cancellationToken = default);

        #endregion

        #region Execution Management

        /// <summary>
        /// Executes a parser on input data
        /// </summary>
        /// <param name="parserId">ID of the parser to execute</param>
        /// <param name="inputData">Data to process</param>
        /// <param name="executionOptions">Execution configuration</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Execution result with parsed data</returns>
        Task<ParserExecutionResult> ExecuteParserAsync(Guid parserId, byte[] inputData, ExecutionOptions executionOptions, CancellationToken cancellationToken = default);

        /// <summary>
        /// Executes a parser on multiple input files in batch
        /// </summary>
        /// <param name="parserId">ID of the parser to execute</param>
        /// <param name="inputFiles">Collection of file paths to process</param>
        /// <param name="executionOptions">Execution configuration</param>
        /// <param name="progressCallback">Callback for progress updates</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Collection of execution results</returns>
        Task<IEnumerable<ParserExecutionResult>> BatchExecuteAsync(Guid parserId, IEnumerable<string> inputFiles, ExecutionOptions executionOptions, IProgress<BatchProgress>? progressCallback = null, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets execution results for a completed parser run
        /// </summary>
        /// <param name="executionId">ID of the execution to retrieve</param>
        /// <param name="includeRawOutput">Whether to include raw output data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Execution results and metadata</returns>
        Task<ParserExecutionResult> GetExecutionResultsAsync(Guid executionId, bool includeRawOutput = false, CancellationToken cancellationToken = default);

        #endregion

        #region Parser Status Management

        /// <summary>
        /// Enables a parser for production use
        /// </summary>
        /// <param name="parserId">ID of the parser to enable</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Updated parser status</returns>
        Task<ParserStatus> EnableParserAsync(Guid parserId, CancellationToken cancellationToken = default);

        /// <summary>
        /// Disables a parser from production use
        /// </summary>
        /// <param name="parserId">ID of the parser to disable</param>
        /// <param name="reason">Reason for disabling</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Updated parser status</returns>
        Task<ParserStatus> DisableParserAsync(Guid parserId, string? reason = null, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets current status of a parser
        /// </summary>
        /// <param name="parserId">ID of the parser to check</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Current parser status and health</returns>
        Task<ParserStatus> GetParserStatusAsync(Guid parserId, CancellationToken cancellationToken = default);

        #endregion

        #region Code Analysis and Security

        /// <summary>
        /// Performs security analysis on parser source code
        /// </summary>
        /// <param name="sourceCode">Source code to analyze</param>
        /// <param name="securityRules">Security rules to apply</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Security analysis results</returns>
        Task<SecurityAnalysisResult> AnalyzeSecurityAsync(string sourceCode, SecurityRules securityRules, CancellationToken cancellationToken = default);

        /// <summary>
        /// Checks dependencies and references in parser code
        /// </summary>
        /// <param name="sourceCode">Source code to analyze</param>
        /// <param name="allowedDependencies">List of allowed dependencies</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Dependency check results</returns>
        Task<DependencyCheckResult> CheckDependenciesAsync(string sourceCode, IEnumerable<string> allowedDependencies, CancellationToken cancellationToken = default);

        /// <summary>
        /// Validates syntax and structure of C# code
        /// </summary>
        /// <param name="sourceCode">Source code to validate</param>
        /// <param name="syntaxRules">Syntax validation rules</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Syntax validation results</returns>
        Task<SyntaxValidationResult> ValidateSyntaxAsync(string sourceCode, SyntaxRules syntaxRules, CancellationToken cancellationToken = default);

        #endregion

        #region Performance and Optimization

        /// <summary>
        /// Benchmarks parser performance with test data
        /// </summary>
        /// <param name="parserId">ID of the parser to benchmark</param>
        /// <param name="benchmarkData">Test data for benchmarking</param>
        /// <param name="benchmarkOptions">Benchmark configuration</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Performance benchmark results</returns>
        Task<BenchmarkResult> BenchmarkParserAsync(Guid parserId, IEnumerable<byte[]> benchmarkData, BenchmarkOptions benchmarkOptions, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets performance metrics for a parser
        /// </summary>
        /// <param name="parserId">ID of the parser</param>
        /// <param name="metricsTimeRange">Time range for metrics</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Performance metrics and statistics</returns>
        Task<ParserMetrics> GetPerformanceMetricsAsync(Guid parserId, TimeRange metricsTimeRange, CancellationToken cancellationToken = default);

        /// <summary>
        /// Optimizes parser code for better performance
        /// </summary>
        /// <param name="parserId">ID of the parser to optimize</param>
        /// <param name="optimizationLevel">Level of optimization to apply</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Optimization results and recommendations</returns>
        Task<OptimizationResult> OptimizeParserAsync(Guid parserId, OptimizationLevel optimizationLevel, CancellationToken cancellationToken = default);

        #endregion

        #region Templates and Code Generation

        /// <summary>
        /// Gets a parser template for common use cases
        /// </summary>
        /// <param name="templateType">Type of template to retrieve</param>
        /// <param name="templateOptions">Template customization options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Template source code and metadata</returns>
        Task<ParserTemplate> GetParserTemplateAsync(TemplateType templateType, TemplateOptions templateOptions, CancellationToken cancellationToken = default);

        /// <summary>
        /// Creates a parser from a predefined template
        /// </summary>
        /// <param name="templateType">Template to use for creation</param>
        /// <param name="parserName">Name for the new parser</param>
        /// <param name="templateParameters">Parameters for template customization</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Created parser from template</returns>
        Task<Parser> CreateFromTemplateAsync(TemplateType templateType, string parserName, Dictionary<string, object> templateParameters, CancellationToken cancellationToken = default);

        /// <summary>
        /// Lists available parser templates
        /// </summary>
        /// <param name="category">Optional category filter</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Available templates with descriptions</returns>
        Task<IEnumerable<TemplateInfo>> ListTemplatesAsync(string? category = null, CancellationToken cancellationToken = default);

        #endregion

        #region Documentation and Help

        /// <summary>
        /// Generates documentation for a parser
        /// </summary>
        /// <param name="parserId">ID of the parser</param>
        /// <param name="documentationFormat">Format for documentation</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Generated documentation</returns>
        Task<DocumentationResult> GenerateDocumentationAsync(Guid parserId, DocumentationFormat documentationFormat, CancellationToken cancellationToken = default);

        /// <summary>
        /// Validates parser documentation completeness
        /// </summary>
        /// <param name="parserId">ID of the parser to validate</param>
        /// <param name="documentationStandards">Standards to validate against</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Documentation validation results</returns>
        Task<DocumentationValidationResult> ValidateDocumentationAsync(Guid parserId, DocumentationStandards documentationStandards, CancellationToken cancellationToken = default);

        #endregion

        #region Version Control

        /// <summary>
        /// Gets version history for a parser
        /// </summary>
        /// <param name="parserId">ID of the parser</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Version history with changes</returns>
        Task<IEnumerable<ParserVersion>> GetParserVersionsAsync(Guid parserId, CancellationToken cancellationToken = default);

        /// <summary>
        /// Creates a new version of a parser
        /// </summary>
        /// <param name="parserId">ID of the parser</param>
        /// <param name="versionInfo">Version information and changes</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Created version information</returns>
        Task<ParserVersion> CreateVersionAsync(Guid parserId, VersionInfo versionInfo, CancellationToken cancellationToken = default);

        /// <summary>
        /// Rolls back a parser to a previous version
        /// </summary>
        /// <param name="parserId">ID of the parser</param>
        /// <param name="targetVersion">Version to rollback to</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Rollback result and status</returns>
        Task<RollbackResult> RollbackVersionAsync(Guid parserId, string targetVersion, CancellationToken cancellationToken = default);

        #endregion
    }

    #region Supporting Types

    /// <summary>
    /// Result of parser creation operation
    /// </summary>
    public class ParserCreationResult
    {
        public Parser Parser { get; set; } = new();
        public bool Success { get; set; }
        public IEnumerable<string> ValidationErrors { get; set; } = new List<string>();
        public IEnumerable<string> Warnings { get; set; } = new List<string>();
    }

    /// <summary>
    /// Compilation configuration options
    /// </summary>
    public class CompilationOptions
    {
        public bool OptimizeCode { get; set; } = true;
        public bool DebugMode { get; set; } = false;
        public IEnumerable<string> References { get; set; } = new List<string>();
        public string TargetFramework { get; set; } = "net8.0";
        public int TimeoutSeconds { get; set; } = 60;
    }

    /// <summary>
    /// Result of compilation operation
    /// </summary>
    public class CompilationResult
    {
        public bool Success { get; set; }
        public byte[]? CompiledAssembly { get; set; }
        public IEnumerable<CompilationError> Errors { get; set; } = new List<CompilationError>();
        public IEnumerable<CompilationWarning> Warnings { get; set; } = new List<CompilationWarning>();
        public TimeSpan CompilationTime { get; set; }
    }

    /// <summary>
    /// Parser execution result
    /// </summary>
    public class ParserExecutionResult
    {
        public Guid ExecutionId { get; set; }
        public bool Success { get; set; }
        public object? ParsedData { get; set; }
        public string? ErrorMessage { get; set; }
        public TimeSpan ExecutionTime { get; set; }
        public long MemoryUsed { get; set; }
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    /// <summary>
    /// Parser status information
    /// </summary>
    public class ParserStatus
    {
        public Guid ParseId { get; set; }
        public bool IsActive { get; set; }
        public CompilationStatus CompilationStatus { get; set; }
        public DateTime LastUsed { get; set; }
        public long ExecutionCount { get; set; }
        public string? StatusMessage { get; set; }
        public Dictionary<string, object> HealthMetrics { get; set; } = new();
    }

    /// <summary>
    /// Template types for parser generation
    /// </summary>
    public enum TemplateType
    {
        LogParser = 0,
        CSVParser = 1,
        XMLParser = 2,
        JSONParser = 3,
        BinaryParser = 4,
        NetworkParser = 5,
        RegistryParser = 6,
        EventLogParser = 7
    }

    /// <summary>
    /// Validation levels for code analysis
    /// </summary>
    public enum ValidationLevel
    {
        Basic = 0,
        Standard = 1,
        Full = 2,
        Strict = 3
    }

    /// <summary>
    /// Optimization levels for parser code
    /// </summary>
    public enum OptimizationLevel
    {
        None = 0,
        Basic = 1,
        Standard = 2,
        Aggressive = 3
    }

    /// <summary>
    /// Documentation formats
    /// </summary>
    public enum DocumentationFormat
    {
        Markdown = 0,
        HTML = 1,
        XML = 2,
        PDF = 3
    }

    #endregion
}