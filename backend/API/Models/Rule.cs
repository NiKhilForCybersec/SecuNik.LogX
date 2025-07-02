using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace SecuNikLogX.API.Models
{
    /// <summary>
    /// Represents a YARA or Sigma rule with complete metadata and execution tracking
    /// </summary>
    public class Rule
    {
        /// <summary>
        /// Unique identifier for the rule
        /// </summary>
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        /// <summary>
        /// Display name of the rule
        /// </summary>
        [Required]
        [StringLength(200, MinimumLength = 1)]
        public required string Name { get; set; }

        /// <summary>
        /// Detailed description of what the rule detects
        /// </summary>
        [StringLength(2000)]
        public string? Description { get; set; }

        /// <summary>
        /// Type of rule (YARA or Sigma)
        /// </summary>
        [Required]
        public RuleType RuleType { get; set; }

        /// <summary>
        /// The actual rule content/definition
        /// </summary>
        [Required]
        public required string Content { get; set; }

        /// <summary>
        /// Author or creator of the rule
        /// </summary>
        [StringLength(100)]
        public string? Author { get; set; }

        /// <summary>
        /// Version of the rule
        /// </summary>
        [StringLength(20)]
        public string? Version { get; set; }

        /// <summary>
        /// When the rule was last modified
        /// </summary>
        public DateTime? LastModified { get; set; }

        /// <summary>
        /// Whether the rule is currently active for analysis
        /// </summary>
        public bool IsActive { get; set; } = true;

        /// <summary>
        /// Severity level of threats detected by this rule
        /// </summary>
        public RuleSeverity Severity { get; set; } = RuleSeverity.Medium;

        /// <summary>
        /// Whether the rule syntax is valid
        /// </summary>
        public bool SyntaxValid { get; set; } = false;

        /// <summary>
        /// When the rule syntax was last validated
        /// </summary>
        public DateTime? LastValidated { get; set; }

        /// <summary>
        /// Any validation errors found in the rule
        /// </summary>
        public string? ValidationErrors { get; set; }

        /// <summary>
        /// Average execution time in milliseconds
        /// </summary>
        [Range(0, int.MaxValue)]
        public int? ExecutionTimeMs { get; set; }

        /// <summary>
        /// Memory usage during rule execution in bytes
        /// </summary>
        [Range(0, long.MaxValue)]
        public long? MemoryUsage { get; set; }

        /// <summary>
        /// Number of times this rule has matched/hit
        /// </summary>
        [Range(0, long.MaxValue)]
        public long HitCount { get; set; } = 0;

        /// <summary>
        /// Source file where the rule was imported from
        /// </summary>
        [StringLength(500)]
        public string? SourceFile { get; set; }

        /// <summary>
        /// SHA256 checksum of the rule content
        /// </summary>
        [StringLength(64)]
        [RegularExpression(@"^[a-fA-F0-9]{64}$", ErrorMessage = "ChecksumSHA256 must be a valid SHA256 hash")]
        public string? ChecksumSHA256 { get; set; }

        /// <summary>
        /// Size of the rule file in bytes
        /// </summary>
        [Range(0, long.MaxValue)]
        public long? FileSizeBytes { get; set; }

        /// <summary>
        /// Threat category this rule targets
        /// </summary>
        [StringLength(100)]
        public string? ThreatCategory { get; set; }

        /// <summary>
        /// Target platform for the rule (Windows, Linux, etc.)
        /// </summary>
        [StringLength(50)]
        public string? Platform { get; set; }

        /// <summary>
        /// Programming or scripting language targeted by the rule
        /// </summary>
        [StringLength(50)]
        public string? Language { get; set; }

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
        /// Collection of analyses that used this rule
        /// </summary>
        public virtual ICollection<Analysis> Analyses { get; set; } = new List<Analysis>();

        /// <summary>
        /// Updates the rule's checksum based on its content
        /// </summary>
        public void UpdateChecksum()
        {
            if (!string.IsNullOrWhiteSpace(Content))
            {
                using var sha256 = System.Security.Cryptography.SHA256.Create();
                var bytes = System.Text.Encoding.UTF8.GetBytes(Content);
                var hash = sha256.ComputeHash(bytes);
                ChecksumSHA256 = Convert.ToHexString(hash).ToLowerInvariant();
            }
        }

        /// <summary>
        /// Validates rule syntax based on rule type
        /// </summary>
        public bool ValidateRuleSyntax()
        {
            if (string.IsNullOrWhiteSpace(Content))
            {
                SyntaxValid = false;
                ValidationErrors = "Rule content cannot be empty";
                return false;
            }

            try
            {
                switch (RuleType)
                {
                    case RuleType.YARA:
                        return ValidateYaraRule();
                    case RuleType.Sigma:
                        return ValidateSigmaRule();
                    default:
                        SyntaxValid = false;
                        ValidationErrors = "Unknown rule type";
                        return false;
                }
            }
            catch (Exception ex)
            {
                SyntaxValid = false;
                ValidationErrors = ex.Message;
                return false;
            }
        }

        private bool ValidateYaraRule()
        {
            // Basic YARA rule structure validation
            if (!Content.Contains("rule ") || !Content.Contains("{") || !Content.Contains("}"))
            {
                SyntaxValid = false;
                ValidationErrors = "Invalid YARA rule structure";
                return false;
            }

            SyntaxValid = true;
            ValidationErrors = null;
            LastValidated = DateTime.UtcNow;
            return true;
        }

        private bool ValidateSigmaRule()
        {
            // Basic Sigma rule structure validation
            if (!Content.Contains("title:") || !Content.Contains("detection:"))
            {
                SyntaxValid = false;
                ValidationErrors = "Invalid Sigma rule structure";
                return false;
            }

            SyntaxValid = true;
            ValidationErrors = null;
            LastValidated = DateTime.UtcNow;
            return true;
        }

        /// <summary>
        /// Increments the hit count when the rule matches
        /// </summary>
        public void RecordHit()
        {
            HitCount++;
            UpdatedAt = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// Enumeration of supported rule types
    /// </summary>
    public enum RuleType
    {
        YARA = 0,
        Sigma = 1
    }

    /// <summary>
    /// Enumeration of rule severity levels
    /// </summary>
    public enum RuleSeverity
    {
        Info = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }
}