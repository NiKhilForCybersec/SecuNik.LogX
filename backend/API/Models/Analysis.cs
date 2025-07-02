using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace SecuNikLogX.API.Models
{
    /// <summary>
    /// Represents a forensics evidence analysis operation with complete tracking and relationship management
    /// </summary>
    public class Analysis
    {
        /// <summary>
        /// Unique identifier for the analysis operation
        /// </summary>
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        /// <summary>
        /// Original name of the file being analyzed
        /// </summary>
        [Required]
        [StringLength(255, MinimumLength = 1)]
        public required string FileName { get; set; }

        /// <summary>
        /// Full file system path to the evidence file
        /// </summary>
        [Required]
        [StringLength(1000, MinimumLength = 1)]
        public required string FilePath { get; set; }

        /// <summary>
        /// SHA256 hash of the file for integrity verification
        /// </summary>
        [Required]
        [StringLength(64, MinimumLength = 64)]
        [RegularExpression(@"^[a-fA-F0-9]{64}$", ErrorMessage = "FileHash must be a valid SHA256 hash")]
        public required string FileHash { get; set; }

        /// <summary>
        /// Size of the file in bytes
        /// </summary>
        [Range(0, long.MaxValue)]
        public long FileSize { get; set; }

        /// <summary>
        /// MIME type of the analyzed file
        /// </summary>
        [StringLength(100)]
        public string? MimeType { get; set; }

        /// <summary>
        /// Current status of the analysis operation
        /// </summary>
        [Required]
        public AnalysisStatus Status { get; set; } = AnalysisStatus.Pending;

        /// <summary>
        /// Timestamp when the analysis started
        /// </summary>
        public DateTime? StartTime { get; set; }

        /// <summary>
        /// Timestamp when the analysis completed
        /// </summary>
        public DateTime? EndTime { get; set; }

        /// <summary>
        /// Total processing duration in milliseconds
        /// </summary>
        [Range(0, int.MaxValue)]
        public int? ProcessingDuration { get; set; }

        /// <summary>
        /// Overall threat level determined by the analysis
        /// </summary>
        public ThreatLevel ThreatLevel { get; set; } = ThreatLevel.Unknown;

        /// <summary>
        /// High-level summary of analysis results
        /// </summary>
        public string? SummaryReport { get; set; }

        /// <summary>
        /// Detailed technical findings from the analysis
        /// </summary>
        public string? DetailedFindings { get; set; }

        /// <summary>
        /// Timestamp when the file was uploaded for analysis
        /// </summary>
        [Required]
        public DateTime UploadTimestamp { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Version of the analysis engine used
        /// </summary>
        [StringLength(50)]
        public string? AnalysisVersion { get; set; }

        /// <summary>
        /// Information about the processor/engine that performed the analysis
        /// </summary>
        [StringLength(200)]
        public string? ProcessorInfo { get; set; }

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
        /// Collection of rules applied during this analysis
        /// </summary>
        public virtual ICollection<Rule> Rules { get; set; } = new List<Rule>();

        /// <summary>
        /// Collection of IOCs discovered during this analysis
        /// </summary>
        public virtual ICollection<IOC> IOCs { get; set; } = new List<IOC>();

        /// <summary>
        /// Collection of MITRE ATT&CK techniques mapped to this analysis
        /// </summary>
        public virtual ICollection<MITRE> MITREMappings { get; set; } = new List<MITRE>();

        /// <summary>
        /// Parser used for this analysis, if applicable
        /// </summary>
        public Guid? ParserId { get; set; }

        /// <summary>
        /// Navigation property to the parser used
        /// </summary>
        [ForeignKey(nameof(ParserId))]
        public virtual Parser? Parser { get; set; }

        /// <summary>
        /// Validates that the analysis has required fields for forensics compliance
        /// </summary>
        public bool IsValidForForensics()
        {
            return !string.IsNullOrWhiteSpace(FileName) &&
                   !string.IsNullOrWhiteSpace(FilePath) &&
                   !string.IsNullOrWhiteSpace(FileHash) &&
                   FileSize > 0 &&
                   UploadTimestamp != default;
        }

        /// <summary>
        /// Calculates processing duration if both start and end times are available
        /// </summary>
        public void UpdateProcessingDuration()
        {
            if (StartTime.HasValue && EndTime.HasValue)
            {
                ProcessingDuration = (int)(EndTime.Value - StartTime.Value).TotalMilliseconds;
            }
        }
    }

    /// <summary>
    /// Enumeration of possible analysis statuses
    /// </summary>
    public enum AnalysisStatus
    {
        Pending = 0,
        Running = 1,
        Completed = 2,
        Failed = 3,
        Cancelled = 4,
        Paused = 5
    }

    /// <summary>
    /// Enumeration of threat levels for analysis results
    /// </summary>
    public enum ThreatLevel
    {
        Unknown = 0,
        Clean = 1,
        Low = 2,
        Medium = 3,
        High = 4,
        Critical = 5
    }
}