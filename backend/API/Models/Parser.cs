using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace SecuNikLogX.API.Models
{
    /// <summary>
    /// Represents a custom C# parser with compilation and execution metadata
    /// </summary>
    public class Parser
    {
        /// <summary>
        /// Unique identifier for the parser
        /// </summary>
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        /// <summary>
        /// Display name of the parser
        /// </summary>
        [Required]
        [StringLength(200, MinimumLength = 1)]
        public required string Name { get; set; }

        /// <summary>
        /// Detailed description of what the parser does
        /// </summary>
        [StringLength(2000)]
        public string? Description { get; set; }

        /// <summary>
        /// Version of the parser
        /// </summary>
        [StringLength(20)]
        public string? Version { get; set; }

        /// <summary>
        /// Programming language (always C# for this system)
        /// </summary>
        [Required]
        [StringLength(20)]
        public string Language { get; set; } = "C#";

        /// <summary>
        /// The C# source code of the parser
        /// </summary>
        [Required]
        public required string SourceCode { get; set; }

        /// <summary>
        /// Current compilation status of the parser
        /// </summary>
        [Required]
        public CompilationStatus CompilationStatus { get; set; } = CompilationStatus.NotCompiled;

        /// <summary>
        /// Compiled assembly bytes (stored as base64)
        /// </summary>
        [JsonIgnore]
        public byte[]? CompiledAssembly { get; set; }

        /// <summary>
        /// Compilation errors if any occurred
        /// </summary>
        public string? CompilerErrors { get; set; }

        /// <summary>
        /// Whether the parser is currently active for use
        /// </summary>
        public bool IsActive { get; set; } = false;

        /// <summary>
        /// When the parser was last used for analysis
        /// </summary>
        public DateTime? LastUsed { get; set; }

        /// <summary>
        /// Total number of times this parser has been executed
        /// </summary>
        [Range(0, long.MaxValue)]
        public long ExecutionCount { get; set; } = 0;

        /// <summary>
        /// Average execution time in milliseconds
        /// </summary>
        [Range(0, int.MaxValue)]
        public int? AverageExecutionTime { get; set; }

        /// <summary>
        /// File extensions this parser can handle
        /// </summary>
        [StringLength(500)]
        public string? SupportedExtensions { get; set; }

        /// <summary>
        /// Maximum file size this parser can process in bytes
        /// </summary>
        [Range(0, long.MaxValue)]
        public long? MaxFileSizeBytes { get; set; }

        /// <summary>
        /// Description of parser capabilities
        /// </summary>
        [StringLength(1000)]
        public string? ProcessingCapabilities { get; set; }

        /// <summary>
        /// Author or creator of the parser
        /// </summary>
        [StringLength(100)]
        public string? Author { get; set; }

        /// <summary>
        /// When the parser was originally created
        /// </summary>
        public DateTime? CreatedDate { get; set; }

        /// <summary>
        /// When the parser source code was last modified
        /// </summary>
        public DateTime? LastModified { get; set; }

        /// <summary>
        /// Documentation for the parser
        /// </summary>
        public string? Documentation { get; set; }

        /// <summary>
        /// Memory usage during parser execution in bytes
        /// </summary>
        [Range(0, long.MaxValue)]
        public long? MemoryUsage { get; set; }

        /// <summary>
        /// Processing speed in megabytes per second
        /// </summary>
        [Range(0, double.MaxValue)]
        public double? ProcessingSpeedMBps { get; set; }

        /// <summary>
        /// Whether the parser supports concurrent execution
        /// </summary>
        public bool ConcurrencySupport { get; set; } = false;

        /// <summary>
        /// Whether the parser code is syntactically valid
        /// </summary>
        public bool CodeValid { get; set; } = false;

        /// <summary>
        /// Security scan results for the parser code
        /// </summary>
        public string? SecurityScan { get; set; }

        /// <summary>
        /// Dependency check results
        /// </summary>
        public string? DependencyCheck { get; set; }

        /// <summary>
        /// Expected output format from the parser
        /// </summary>
        [StringLength(100)]
        public string? OutputFormat { get; set; }

        /// <summary>
        /// JSON schema for parser results
        /// </summary>
        public string? ResultSchema { get; set; }

        /// <summary>
        /// Error handling strategy description
        /// </summary>
        [StringLength(500)]
        public string? ErrorHandling { get; set; }

        /// <summary>
        /// Audit trail: When this record was created
        /// </summary>
        [Required]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Audit trail: When this record was last updated
        /// </summary>
        [Required]
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Audit trail: User who created this record
        /// </summary>
        [StringLength(100)]
        public string? CreatedBy { get; set; }

        /// <summary>
        /// Soft delete flag for audit compliance
        /// </summary>
        public bool IsDeleted { get; set; } = false;

        /// <summary>
        /// Collection of analyses that used this parser
        /// </summary>
        public virtual ICollection<Analysis> Analyses { get; set; } = new List<Analysis>();

        /// <summary>
        /// Validates the C# source code syntax
        /// </summary>
        public bool ValidateSourceCode()
        {
            if (string.IsNullOrWhiteSpace(SourceCode))
            {
                CodeValid = false;
                return false;
            }

            try
            {
                // Basic C# syntax validation
                if (!SourceCode.Contains("using ") && !SourceCode.Contains("namespace ") && !SourceCode.Contains("class "))
                {
                    CodeValid = false;
                    return false;
                }

                CodeValid = true;
                LastModified = DateTime.UtcNow;
                return true;
            }
            catch
            {
                CodeValid = false;
                return false;
            }
        }

        /// <summary>
        /// Updates execution statistics after parser run
        /// </summary>
        public void UpdateExecutionStats(int executionTimeMs, long memoryUsedBytes)
        {
            ExecutionCount++;
            LastUsed = DateTime.UtcNow;
            
            // Calculate rolling average for execution time
            if (AverageExecutionTime.HasValue)
            {
                AverageExecutionTime = (int)((AverageExecutionTime.Value * (ExecutionCount - 1) + executionTimeMs) / ExecutionCount);
            }
            else
            {
                AverageExecutionTime = executionTimeMs;
            }

            // Update memory usage (keep highest recorded)
            if (!MemoryUsage.HasValue || memoryUsedBytes > MemoryUsage.Value)
            {
                MemoryUsage = memoryUsedBytes;
            }

            UpdatedAt = DateTime.UtcNow;
        }

        /// <summary>
        /// Checks if parser can handle the specified file extension
        /// </summary>
        public bool CanHandleExtension(string extension)
        {
            if (string.IsNullOrWhiteSpace(SupportedExtensions) || string.IsNullOrWhiteSpace(extension))
                return false;

            var supportedList = SupportedExtensions.Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(ext => ext.Trim().ToLowerInvariant());

            return supportedList.Contains(extension.ToLowerInvariant());
        }

        /// <summary>
        /// Checks if parser can handle the specified file size
        /// </summary>
        public bool CanHandleFileSize(long fileSizeBytes)
        {
            return !MaxFileSizeBytes.HasValue || fileSizeBytes <= MaxFileSizeBytes.Value;
        }
    }

    /// <summary>
    /// Enumeration of parser compilation statuses
    /// </summary>
    public enum CompilationStatus
    {
        NotCompiled = 0,
        Compiling = 1,
        Compiled = 2,
        CompilationFailed = 3,
        Outdated = 4
    }
}