using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace SecuNikLogX.API.DTOs
{
    /// <summary>
    /// Data Transfer Objects for file upload operations and validation
    /// </summary>

    /// <summary>
    /// Multi-file upload request with metadata and validation options
    /// </summary>
    public class FileUploadRequest
    {
        /// <summary>
        /// The file to upload
        /// </summary>
        [Required(ErrorMessage = "File is required")]
        public IFormFile File { get; set; } = null!;

        /// <summary>
        /// Optional description for the file
        /// </summary>
        [StringLength(500, ErrorMessage = "Description cannot exceed 500 characters")]
        public string? Description { get; set; }

        /// <summary>
        /// Whether to preserve the original filename
        /// </summary>
        public bool PreserveOriginalName { get; set; } = false;

        /// <summary>
        /// Tags to associate with the file
        /// </summary>
        public List<string>? Tags { get; set; }

        /// <summary>
        /// Validation level to apply
        /// </summary>
        [StringLength(20, ErrorMessage = "Validation level cannot exceed 20 characters")]
        public string ValidationLevel { get; set; } = "Standard";

        /// <summary>
        /// Whether to automatically quarantine suspicious files
        /// </summary>
        public bool AutoQuarantine { get; set; } = true;

        /// <summary>
        /// Custom metadata for the file
        /// </summary>
        public Dictionary<string, object>? Metadata { get; set; }
    }

    /// <summary>
    /// Upload results with file IDs and validation status
    /// </summary>
    public class FileUploadResponse
    {
        /// <summary>
        /// Unique identifier for the uploaded file
        /// </summary>
        public Guid FileId { get; set; }

        /// <summary>
        /// Stored filename (may be different from original)
        /// </summary>
        public string FileName { get; set; } = string.Empty;

        /// <summary>
        /// Original filename from upload
        /// </summary>
        public string OriginalFileName { get; set; } = string.Empty;

        /// <summary>
        /// Full path where file is stored
        /// </summary>
        public string FilePath { get; set; } = string.Empty;

        /// <summary>
        /// File size in bytes
        /// </summary>
        public long FileSize { get; set; }

        /// <summary>
        /// SHA256 hash of the file
        /// </summary>
        public string FileHash { get; set; } = string.Empty;

        /// <summary>
        /// MIME content type
        /// </summary>
        public string? ContentType { get; set; }

        /// <summary>
        /// Timestamp when file was uploaded
        /// </summary>
        public DateTime UploadedAt { get; set; }

        /// <summary>
        /// Optional description provided during upload
        /// </summary>
        public string? Description { get; set; }

        /// <summary>
        /// File metadata extracted during upload
        /// </summary>
        public Dictionary<string, object>? Metadata { get; set; }

        /// <summary>
        /// Whether the file has been validated
        /// </summary>
        public bool IsValidated { get; set; }

        /// <summary>
        /// Whether the file is currently in quarantine
        /// </summary>
        public bool IsQuarantined { get; set; }

        /// <summary>
        /// Upload status and any warnings
        /// </summary>
        public UploadStatus Status { get; set; } = new();

        /// <summary>
        /// Tags associated with the file
        /// </summary>
        public List<string>? Tags { get; set; }
    }

    /// <summary>
    /// File format and content validation parameters
    /// </summary>
    public class FileValidationRequest
    {
        /// <summary>
        /// Validation level to apply
        /// </summary>
        [StringLength(20, ErrorMessage = "Validation level cannot exceed 20 characters")]
        public string? ValidationLevel { get; set; } = "Standard";

        /// <summary>
        /// Specific validation rules to apply
        /// </summary>
        public List<string>? ValidationRules { get; set; }

        /// <summary>
        /// Whether to perform deep content analysis
        /// </summary>
        public bool DeepScan { get; set; } = false;

        /// <summary>
        /// Whether to check against known malware signatures
        /// </summary>
        public bool MalwareScan { get; set; } = true;

        /// <summary>
        /// Whether to validate file format integrity
        /// </summary>
        public bool FormatValidation { get; set; } = true;

        /// <summary>
        /// Whether to extract and validate metadata
        /// </summary>
        public bool MetadataValidation { get; set; } = true;

        /// <summary>
        /// Maximum time to spend on validation (in seconds)
        /// </summary>
        [Range(1, 3600, ErrorMessage = "Timeout must be between 1 and 3600 seconds")]
        public int TimeoutSeconds { get; set; } = 300;

        /// <summary>
        /// Custom validation parameters
        /// </summary>
        public Dictionary<string, object>? CustomParameters { get; set; }
    }

    /// <summary>
    /// Validation results with detailed error information
    /// </summary>
    public class FileValidationResponse
    {
        /// <summary>
        /// File identifier
        /// </summary>
        public Guid FileId { get; set; }

        /// <summary>
        /// Overall validation result
        /// </summary>
        public bool IsValid { get; set; }

        /// <summary>
        /// Detailed validation results for each check
        /// </summary>
        public List<ValidationResult> ValidationResults { get; set; } = new();

        /// <summary>
        /// Security scan results
        /// </summary>
        public SecurityScanResult SecurityScan { get; set; } = new();

        /// <summary>
        /// File format analysis results
        /// </summary>
        public FormatAnalysisResult FormatAnalysis { get; set; } = new();

        /// <summary>
        /// Metadata extraction results
        /// </summary>
        public MetadataExtractionResult MetadataExtraction { get; set; } = new();

        /// <summary>
        /// Risk assessment based on validation
        /// </summary>
        public RiskAssessment RiskAssessment { get; set; } = new();

        /// <summary>
        /// Validation level applied
        /// </summary>
        public string ValidationLevel { get; set; } = string.Empty;

        /// <summary>
        /// Timestamp when validation was performed
        /// </summary>
        public DateTime ValidatedAt { get; set; }

        /// <summary>
        /// Time taken for validation
        /// </summary>
        public TimeSpan ValidationDuration { get; set; }

        /// <summary>
        /// Recommended actions based on validation results
        /// </summary>
        public List<RecommendedAction> RecommendedActions { get; set; } = new();
    }

    /// <summary>
    /// Complete file metadata including hashes and properties
    /// </summary>
    public class FileMetadataResponse
    {
        /// <summary>
        /// File identifier
        /// </summary>
        public Guid FileId { get; set; }

        /// <summary>
        /// Current filename
        /// </summary>
        public string FileName { get; set; } = string.Empty;

        /// <summary>
        /// Original filename
        /// </summary>
        public string OriginalFileName { get; set; } = string.Empty;

        /// <summary>
        /// File size in bytes
        /// </summary>
        public long FileSize { get; set; }

        /// <summary>
        /// MIME content type
        /// </summary>
        public string? FileType { get; set; }

        /// <summary>
        /// File creation timestamp
        /// </summary>
        public DateTime CreatedAt { get; set; }

        /// <summary>
        /// Last modification timestamp
        /// </summary>
        public DateTime ModifiedAt { get; set; }

        /// <summary>
        /// Primary file hash (SHA256)
        /// </summary>
        public string Hash { get; set; } = string.Empty;

        /// <summary>
        /// Additional hash algorithms
        /// </summary>
        public Dictionary<string, string> AdditionalHashes { get; set; } = new();

        /// <summary>
        /// File properties and characteristics
        /// </summary>
        public Dictionary<string, object> Properties { get; set; } = new();

        /// <summary>
        /// File format specific metadata
        /// </summary>
        public Dictionary<string, object> FormatMetadata { get; set; } = new();

        /// <summary>
        /// Security attributes
        /// </summary>
        public SecurityAttributes Security { get; set; } = new();

        /// <summary>
        /// Forensics-relevant information
        /// </summary>
        public ForensicsMetadata Forensics { get; set; } = new();
    }

    /// <summary>
    /// Batch file operations with parallel processing options
    /// </summary>
    public class FileBatchRequest
    {
        /// <summary>
        /// List of files to process in batch
        /// </summary>
        [Required(ErrorMessage = "At least one file is required")]
        [MinLength(1, ErrorMessage = "At least one file must be provided")]
        public List<IFormFile> Files { get; set; } = new();

        /// <summary>
        /// Batch description
        /// </summary>
        [StringLength(500, ErrorMessage = "Description cannot exceed 500 characters")]
        public string? Description { get; set; }

        /// <summary>
        /// Whether to preserve original filenames
        /// </summary>
        public bool PreserveOriginalNames { get; set; } = false;

        /// <summary>
        /// Whether to process files in parallel
        /// </summary>
        public bool ParallelProcessing { get; set; } = true;

        /// <summary>
        /// Maximum number of parallel operations
        /// </summary>
        [Range(1, 10, ErrorMessage = "Parallel limit must be between 1 and 10")]
        public int ParallelLimit { get; set; } = 3;

        /// <summary>
        /// Validation level for all files
        /// </summary>
        [StringLength(20, ErrorMessage = "Validation level cannot exceed 20 characters")]
        public string ValidationLevel { get; set; } = "Standard";

        /// <summary>
        /// Whether to stop batch on first error
        /// </summary>
        public bool StopOnError { get; set; } = false;

        /// <summary>
        /// Common tags for all files in batch
        /// </summary>
        public List<string>? Tags { get; set; }

        /// <summary>
        /// Common metadata for all files
        /// </summary>
        public Dictionary<string, object>? CommonMetadata { get; set; }
    }

    /// <summary>
    /// Batch upload results with individual file status
    /// </summary>
    public class FileBatchUploadResponse
    {
        /// <summary>
        /// Unique batch identifier
        /// </summary>
        public Guid BatchId { get; set; }

        /// <summary>
        /// Total number of files in batch
        /// </summary>
        public int TotalFiles { get; set; }

        /// <summary>
        /// Number of successfully uploaded files
        /// </summary>
        public int SuccessfulUploads { get; set; }

        /// <summary>
        /// Number of failed uploads
        /// </summary>
        public int FailedUploads { get; set; }

        /// <summary>
        /// Individual upload results
        /// </summary>
        public List<FileUploadResponse> UploadedFiles { get; set; } = new();

        /// <summary>
        /// Error messages for failed uploads
        /// </summary>
        public List<string> Errors { get; set; } = new();

        /// <summary>
        /// Batch processing duration
        /// </summary>
        public TimeSpan ProcessingDuration { get; set; }

        /// <summary>
        /// Batch description
        /// </summary>
        public string? BatchDescription { get; set; }

        /// <summary>
        /// Timestamp when batch was uploaded
        /// </summary>
        public DateTime UploadedAt { get; set; }

        /// <summary>
        /// Batch processing statistics
        /// </summary>
        public BatchStatistics Statistics { get; set; } = new();
    }

    /// <summary>
    /// Quarantine operations with reason and duration
    /// </summary>
    public class FileQuarantineRequest
    {
        /// <summary>
        /// Reason for quarantine
        /// </summary>
        [Required(ErrorMessage = "Quarantine reason is required")]
        [StringLength(500, ErrorMessage = "Reason cannot exceed 500 characters")]
        public string Reason { get; set; } = string.Empty;

        /// <summary>
        /// Duration of quarantine
        /// </summary>
        public TimeSpan? Duration { get; set; }

        /// <summary>
        /// Severity level
        /// </summary>
        [StringLength(20, ErrorMessage = "Severity cannot exceed 20 characters")]
        public string Severity { get; set; } = "Medium";

        /// <summary>
        /// Whether to automatically analyze the file in quarantine
        /// </summary>
        public bool AnalyzeInQuarantine { get; set; } = true;

        /// <summary>
        /// Additional notes
        /// </summary>
        [StringLength(1000, ErrorMessage = "Notes cannot exceed 1000 characters")]
        public string? Notes { get; set; }

        /// <summary>
        /// User who initiated quarantine
        /// </summary>
        [StringLength(100, ErrorMessage = "User identifier cannot exceed 100 characters")]
        public string? QuarantinedBy { get; set; }
    }

    /// <summary>
    /// Quarantine status and information
    /// </summary>
    public class FileQuarantineResponse
    {
        /// <summary>
        /// File identifier
        /// </summary>
        public Guid FileId { get; set; }

        /// <summary>
        /// Whether file is currently quarantined
        /// </summary>
        public bool IsQuarantined { get; set; }

        /// <summary>
        /// Timestamp when file was quarantined
        /// </summary>
        public DateTime? QuarantinedAt { get; set; }

        /// <summary>
        /// Timestamp when file was released from quarantine
        /// </summary>
        public DateTime? ReleasedAt { get; set; }

        /// <summary>
        /// Reason for quarantine
        /// </summary>
        public string? Reason { get; set; }

        /// <summary>
        /// Quarantine duration
        /// </summary>
        public TimeSpan? QuarantineDuration { get; set; }

        /// <summary>
        /// Severity level
        /// </summary>
        public string? Severity { get; set; }

        /// <summary>
        /// Quarantine location path
        /// </summary>
        public string? QuarantinePath { get; set; }

        /// <summary>
        /// User who quarantined the file
        /// </summary>
        public string? QuarantinedBy { get; set; }

        /// <summary>
        /// User who released the file
        /// </summary>
        public string? ReleasedBy { get; set; }

        /// <summary>
        /// Additional notes
        /// </summary>
        public string? Notes { get; set; }

        /// <summary>
        /// Actions performed while in quarantine
        /// </summary>
        public List<QuarantineAction> Actions { get; set; } = new();
    }

    /// <summary>
    /// File integrity check results with hash verification
    /// </summary>
    public class FileIntegrityResponse
    {
        /// <summary>
        /// File identifier
        /// </summary>
        public Guid FileId { get; set; }

        /// <summary>
        /// Whether file integrity is valid
        /// </summary>
        public bool IsIntegrityValid { get; set; }

        /// <summary>
        /// Original hash when file was uploaded
        /// </summary>
        public string OriginalHash { get; set; } = string.Empty;

        /// <summary>
        /// Current hash of the file
        /// </summary>
        public string CurrentHash { get; set; } = string.Empty;

        /// <summary>
        /// Hash algorithm used
        /// </summary>
        public string HashAlgorithm { get; set; } = "SHA256";

        /// <summary>
        /// File size when uploaded
        /// </summary>
        public long OriginalSize { get; set; }

        /// <summary>
        /// Current file size
        /// </summary>
        public long CurrentSize { get; set; }

        /// <summary>
        /// Last modification timestamp
        /// </summary>
        public DateTime LastModified { get; set; }

        /// <summary>
        /// Timestamp when integrity was verified
        /// </summary>
        public DateTime VerifiedAt { get; set; }

        /// <summary>
        /// Detailed integrity check results
        /// </summary>
        public List<IntegrityCheck> IntegrityChecks { get; set; } = new();

        /// <summary>
        /// Any issues found during integrity check
        /// </summary>
        public List<IntegrityIssue> Issues { get; set; } = new();
    }

    /// <summary>
    /// File hash calculation result
    /// </summary>
    public class FileHashResponse
    {
        /// <summary>
        /// File identifier
        /// </summary>
        public Guid FileId { get; set; }

        /// <summary>
        /// Hash algorithm used
        /// </summary>
        public string Algorithm { get; set; } = string.Empty;

        /// <summary>
        /// Calculated hash value
        /// </summary>
        public string Hash { get; set; } = string.Empty;

        /// <summary>
        /// Timestamp when hash was calculated
        /// </summary>
        public DateTime CalculatedAt { get; set; }

        /// <summary>
        /// Time taken to calculate hash
        /// </summary>
        public TimeSpan CalculationDuration { get; set; }

        /// <summary>
        /// File size at time of hash calculation
        /// </summary>
        public long FileSize { get; set; }

        /// <summary>
        /// Additional hash algorithms if calculated
        /// </summary>
        public Dictionary<string, string> AdditionalHashes { get; set; } = new();
    }

    /// <summary>
    /// Comprehensive file properties response
    /// </summary>
    public class FilePropertiesResponse
    {
        /// <summary>
        /// File identifier
        /// </summary>
        public Guid FileId { get; set; }

        /// <summary>
        /// Basic file properties
        /// </summary>
        public Dictionary<string, object> BasicProperties { get; set; } = new();

        /// <summary>
        /// Extended file properties
        /// </summary>
        public Dictionary<string, object> ExtendedProperties { get; set; } = new();

        /// <summary>
        /// Forensics-specific properties
        /// </summary>
        public Dictionary<string, object> ForensicsProperties { get; set; } = new();

        /// <summary>
        /// Security-related properties
        /// </summary>
        public Dictionary<string, object> SecurityProperties { get; set; } = new();

        /// <summary>
        /// File format specific properties
        /// </summary>
        public Dictionary<string, object> FormatProperties { get; set; } = new();

        /// <summary>
        /// Timestamp when properties were analyzed
        /// </summary>
        public DateTime AnalyzedAt { get; set; }

        /// <summary>
        /// Analysis duration
        /// </summary>
        public TimeSpan AnalysisDuration { get; set; }
    }

    /// <summary>
    /// File list response with pagination
    /// </summary>
    public class FileListResponse
    {
        /// <summary>
        /// List of files for current page
        /// </summary>
        public List<FileListItem> Files { get; set; } = new();

        /// <summary>
        /// Total number of files
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
        /// Filter criteria applied
        /// </summary>
        public Dictionary<string, string> AppliedFilters { get; set; } = new();
    }

    /// <summary>
    /// Batch validation request for multiple files
    /// </summary>
    public class FileBatchValidationRequest
    {
        /// <summary>
        /// List of file IDs to validate
        /// </summary>
        [Required(ErrorMessage = "File IDs are required")]
        [MinLength(1, ErrorMessage = "At least one file ID must be provided")]
        public List<Guid> FileIds { get; set; } = new();

        /// <summary>
        /// Validation level to apply
        /// </summary>
        [StringLength(20, ErrorMessage = "Validation level cannot exceed 20 characters")]
        public string ValidationLevel { get; set; } = "Standard";

        /// <summary>
        /// Whether to perform parallel validation
        /// </summary>
        public bool ParallelValidation { get; set; } = true;

        /// <summary>
        /// Maximum parallel operations
        /// </summary>
        [Range(1, 10, ErrorMessage = "Parallel limit must be between 1 and 10")]
        public int ParallelLimit { get; set; } = 3;

        /// <summary>
        /// Whether to stop validation on first failure
        /// </summary>
        public bool StopOnFirstFailure { get; set; } = false;

        /// <summary>
        /// Custom validation parameters
        /// </summary>
        public Dictionary<string, object>? ValidationParameters { get; set; }
    }

    /// <summary>
    /// Batch validation response
    /// </summary>
    public class FileBatchValidationResponse
    {
        /// <summary>
        /// Batch identifier
        /// </summary>
        public Guid BatchId { get; set; }

        /// <summary>
        /// Total number of files validated
        /// </summary>
        public int TotalFiles { get; set; }

        /// <summary>
        /// Number of valid files
        /// </summary>
        public int ValidFiles { get; set; }

        /// <summary>
        /// Number of invalid files
        /// </summary>
        public int InvalidFiles { get; set; }

        /// <summary>
        /// Individual validation results
        /// </summary>
        public List<FileValidationResult> ValidationResults { get; set; } = new();

        /// <summary>
        /// Overall batch statistics
        /// </summary>
        public BatchValidationStatistics Statistics { get; set; } = new();

        /// <summary>
        /// Timestamp when validation was completed
        /// </summary>
        public DateTime ValidatedAt { get; set; }

        /// <summary>
        /// Total validation duration
        /// </summary>
        public TimeSpan ValidationDuration { get; set; }
    }

    /// <summary>
    /// Batch status information
    /// </summary>
    public class FileBatchStatusResponse
    {
        /// <summary>
        /// Batch identifier
        /// </summary>
        public Guid BatchId { get; set; }

        /// <summary>
        /// Current batch status
        /// </summary>
        public string Status { get; set; } = string.Empty;

        /// <summary>
        /// Total number of files in batch
        /// </summary>
        public int TotalFiles { get; set; }

        /// <summary>
        /// Number of files processed
        /// </summary>
        public int ProcessedFiles { get; set; }

        /// <summary>
        /// Number of successful operations
        /// </summary>
        public int SuccessfulFiles { get; set; }

        /// <summary>
        /// Number of failed operations
        /// </summary>
        public int FailedFiles { get; set; }

        /// <summary>
        /// Current progress percentage
        /// </summary>
        [Range(0, 100)]
        public decimal ProgressPercentage { get; set; }

        /// <summary>
        /// Estimated time remaining
        /// </summary>
        public TimeSpan? EstimatedTimeRemaining { get; set; }

        /// <summary>
        /// Batch start timestamp
        /// </summary>
        public DateTime? StartedAt { get; set; }

        /// <summary>
        /// Batch completion timestamp
        /// </summary>
        public DateTime? CompletedAt { get; set; }

        /// <summary>
        /// Error messages if any
        /// </summary>
        public List<string> Errors { get; set; } = new();
    }

    #region Supporting Classes

    /// <summary>
    /// Upload status information
    /// </summary>
    public class UploadStatus
    {
        public bool IsSuccessful { get; set; } = true;
        public List<string> Warnings { get; set; } = new();
        public string? ErrorMessage { get; set; }
    }

    /// <summary>
    /// Individual validation result
    /// </summary>
    public class ValidationResult
    {
        public string Rule { get; set; } = string.Empty;
        public bool Passed { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? Details { get; set; }
        public string Severity { get; set; } = "Info";
    }

    /// <summary>
    /// Security scan result
    /// </summary>
    public class SecurityScanResult
    {
        public bool IsThreatDetected { get; set; }
        public string ThreatLevel { get; set; } = "None";
        public List<string> ThreatsFound { get; set; } = new();
        public List<string> ScanEngines { get; set; } = new();
        public DateTime ScanTimestamp { get; set; }
    }

    /// <summary>
    /// Format analysis result
    /// </summary>
    public class FormatAnalysisResult
    {
        public bool IsValidFormat { get; set; }
        public string DetectedFormat { get; set; } = string.Empty;
        public string ExpectedFormat { get; set; } = string.Empty;
        public List<string> FormatIssues { get; set; } = new();
        public Dictionary<string, object> FormatDetails { get; set; } = new();
    }

    /// <summary>
    /// Metadata extraction result
    /// </summary>
    public class MetadataExtractionResult
    {
        public bool ExtractionSuccessful { get; set; }
        public Dictionary<string, object> ExtractedMetadata { get; set; } = new();
        public List<string> ExtractionErrors { get; set; } = new();
        public List<string> SuspiciousMetadata { get; set; } = new();
    }

    /// <summary>
    /// Risk assessment
    /// </summary>
    public class RiskAssessment
    {
        public string RiskLevel { get; set; } = "Low";
        public decimal RiskScore { get; set; }
        public List<string> RiskFactors { get; set; } = new();
        public List<string> Mitigations { get; set; } = new();
    }

    /// <summary>
    /// Security attributes
    /// </summary>
    public class SecurityAttributes
    {
        public bool IsEncrypted { get; set; }
        public bool IsPasswordProtected { get; set; }
        public bool HasDigitalSignature { get; set; }
        public List<string> SecurityFlags { get; set; } = new();
        public Dictionary<string, object> Permissions { get; set; } = new();
    }

    /// <summary>
    /// Forensics metadata
    /// </summary>
    public class ForensicsMetadata
    {
        public decimal Entropy { get; set; }
        public List<string> Signatures { get; set; } = new();
        public Dictionary<string, object> Artifacts { get; set; } = new();
        public List<string> SuspiciousPatterns { get; set; } = new();
    }

    /// <summary>
    /// Batch statistics
    /// </summary>
    public class BatchStatistics
    {
        public TimeSpan AverageProcessingTime { get; set; }
        public long TotalBytesProcessed { get; set; }
        public decimal SuccessRate { get; set; }
        public Dictionary<string, int> FileTypeDistribution { get; set; } = new();
    }

    /// <summary>
    /// Quarantine action
    /// </summary>
    public class QuarantineAction
    {
        public string Action { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string PerformedBy { get; set; } = string.Empty;
        public string? Details { get; set; }
    }

    /// <summary>
    /// Integrity check detail
    /// </summary>
    public class IntegrityCheck
    {
        public string CheckType { get; set; } = string.Empty;
        public bool Passed { get; set; }
        public string? Details { get; set; }
        public DateTime CheckedAt { get; set; }
    }

    /// <summary>
    /// Integrity issue
    /// </summary>
    public class IntegrityIssue
    {
        public string IssueType { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public DateTime DetectedAt { get; set; }
    }

    /// <summary>
    /// File list item
    /// </summary>
    public class FileListItem
    {
        public Guid FileId { get; set; }
        public string FileName { get; set; } = string.Empty;
        public long FileSize { get; set; }
        public string? FileType { get; set; }
        public DateTime UploadedAt { get; set; }
        public bool IsQuarantined { get; set; }
        public bool IsValidated { get; set; }
        public string Status { get; set; } = string.Empty;
    }

    /// <summary>
    /// File validation result for batch operations
    /// </summary>
    public class FileValidationResult
    {
        public Guid FileId { get; set; }
        public bool IsValid { get; set; }
        public List<string> ValidationMessages { get; set; } = new();
        public TimeSpan ValidationDuration { get; set; }
        public string? ErrorMessage { get; set; }
    }

    /// <summary>
    /// Batch validation statistics
    /// </summary>
    public class BatchValidationStatistics
    {
        public TimeSpan AverageValidationTime { get; set; }
        public decimal SuccessRate { get; set; }
        public Dictionary<string, int> IssueDistribution { get; set; } = new();
        public int TotalIssuesFound { get; set; }
    }

    /// <summary>
    /// Recommended action for file handling
    /// </summary>
    public class RecommendedAction
    {
        public string Action { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Priority { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
    }

    #endregion
}