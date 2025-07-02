using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace SecuNikLogX.API.Models
{
    /// <summary>
    /// Represents a MITRE ATT&CK technique mapping with comprehensive threat framework integration
    /// </summary>
    public class MITRE
    {
        /// <summary>
        /// Unique identifier for the MITRE technique record
        /// </summary>
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        /// <summary>
        /// MITRE ATT&CK technique identifier (e.g., T1234)
        /// </summary>
        [Required]
        [StringLength(20, MinimumLength = 2)]
        [RegularExpression(@"^T\d{4}(\.\d{3})?$", ErrorMessage = "TechniqueId must be in format T#### or T####.###")]
        public required string TechniqueId { get; set; }

        /// <summary>
        /// Human-readable name of the technique
        /// </summary>
        [Required]
        [StringLength(200, MinimumLength = 1)]
        public required string TechniqueName { get; set; }

        /// <summary>
        /// MITRE tactic name (e.g., Initial Access, Execution)
        /// </summary>
        [Required]
        [StringLength(100, MinimumLength = 1)]
        public required string TacticName { get; set; }

        /// <summary>
        /// Sub-technique identifier if applicable
        /// </summary>
        [StringLength(20)]
        public string? SubTechnique { get; set; }

        /// <summary>
        /// Version of the MITRE ATT&CK framework
        /// </summary>
        [StringLength(20)]
        public string? FrameworkVersion { get; set; }

        /// <summary>
        /// When the MITRE data was last updated
        /// </summary>
        public DateTime? LastUpdated { get; set; }

        /// <summary>
        /// Source of the MITRE data
        /// </summary>
        [StringLength(100)]
        public string? DataSource { get; set; }

        /// <summary>
        /// Difficulty level of detecting this technique
        /// </summary>
        public DetectionDifficulty DetectionDifficulty { get; set; } = DetectionDifficulty.Unknown;

        /// <summary>
        /// Data sources required for detection
        /// </summary>
        [StringLength(1000)]
        public string? DataRequired { get; set; }

        /// <summary>
        /// Platforms affected by this technique
        /// </summary>
        [StringLength(200)]
        public string? Platform { get; set; }

        /// <summary>
        /// Detailed description of the technique
        /// </summary>
        public string? Description { get; set; }

        /// <summary>
        /// External references and documentation
        /// </summary>
        public string? References { get; set; }

        /// <summary>
        /// Kill chain phase this technique belongs to
        /// </summary>
        [StringLength(100)]
        public string? KillChainPhase { get; set; }

        /// <summary>
        /// Confidence level in the technique mapping (0-100)
        /// </summary>
        [Range(0, 100)]
        public int MappingConfidence { get; set; } = 0;

        /// <summary>
        /// Supporting analysis for the technique mapping
        /// </summary>
        [StringLength(2000)]
        public string? AnalysisSupport { get; set; }

        /// <summary>
        /// Level of evidence supporting this technique mapping
        /// </summary>
        public EvidenceLevel EvidenceLevel { get; set; } = EvidenceLevel.Unknown;

        /// <summary>
        /// Threat groups known to use this technique
        /// </summary>
        [StringLength(1000)]
        public string? ThreatGroups { get; set; }

        /// <summary>
        /// Software/tools associated with this technique
        /// </summary>
        [StringLength(1000)]
        public string? Software { get; set; }

        /// <summary>
        /// Campaigns where this technique was observed
        /// </summary>
        [StringLength(1000)]
        public string? Campaigns { get; set; }

        /// <summary>
        /// Mitigation strategies for this technique
        /// </summary>
        [StringLength(2000)]
        public string? Mitigations { get; set; }

        /// <summary>
        /// Defense evasion methods related to this technique
        /// </summary>
        [StringLength(1000)]
        public string? DefenseEvasion { get; set; }

        /// <summary>
        /// Recommended countermeasures
        /// </summary>
        [StringLength(2000)]
        public string? CounterMeasures { get; set; }

        /// <summary>
        /// Log sources that can detect this technique
        /// </summary>
        [StringLength(1000)]
        public string? LogSources { get; set; }

        /// <summary>
        /// Monitoring capabilities required for detection
        /// </summary>
        [StringLength(1000)]
        public string? MonitoringCapability { get; set; }

        /// <summary>
        /// Detection coverage assessment
        /// </summary>
        public DetectionCoverage DetectionCoverage { get; set; } = DetectionCoverage.Unknown;

        /// <summary>
        /// Business impact of this technique
        /// </summary>
        [StringLength(500)]
        public string? BusinessImpact { get; set; }

        /// <summary>
        /// Technical impact assessment
        /// </summary>
        [StringLength(500)]
        public string? TechnicalImpact { get; set; }

        /// <summary>
        /// Scope of impact (local, network, organization)
        /// </summary>
        [StringLength(100)]
        public string? Scope { get; set; }

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
        /// Collection of analyses associated with this MITRE technique
        /// </summary>
        public virtual ICollection<Analysis> Analyses { get; set; } = new List<Analysis>();

        /// <summary>
        /// Collection of IOCs associated with this MITRE technique
        /// </summary>
        public virtual ICollection<IOC> IOCs { get; set; } = new List<IOC>();

        /// <summary>
        /// Validates that the technique ID follows MITRE format
        /// </summary>
        public bool ValidateTechniqueId()
        {
            if (string.IsNullOrWhiteSpace(TechniqueId))
                return false;

            // Main technique format: T#### (e.g., T1234)
            // Sub-technique format: T####.### (e.g., T1234.001)
            var pattern = @"^T\d{4}(\.\d{3})?$";
            return System.Text.RegularExpressions.Regex.IsMatch(TechniqueId, pattern);
        }

        /// <summary>
        /// Validates that tactic and technique combination is valid
        /// </summary>
        public bool ValidateTacticTechniqueMapping()
        {
            if (string.IsNullOrWhiteSpace(TacticName) || string.IsNullOrWhiteSpace(TechniqueName))
                return false;

            // Common MITRE ATT&CK tactics
            var validTactics = new[]
            {
                "Reconnaissance", "Resource Development", "Initial Access", "Execution",
                "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
                "Discovery", "Lateral Movement", "Collection", "Command and Control",
                "Exfiltration", "Impact"
            };

            return validTactics.Contains(TacticName, StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Extracts the main technique ID from a sub-technique
        /// </summary>
        public string GetMainTechniqueId()
        {
            if (string.IsNullOrWhiteSpace(TechniqueId))
                return string.Empty;

            var dotIndex = TechniqueId.IndexOf('.');
            return dotIndex > 0 ? TechniqueId.Substring(0, dotIndex) : TechniqueId;
        }

        /// <summary>
        /// Checks if this is a sub-technique
        /// </summary>
        public bool IsSubTechnique()
        {
            return !string.IsNullOrWhiteSpace(TechniqueId) && TechniqueId.Contains('.');
        }

        /// <summary>
        /// Updates the mapping confidence based on evidence
        /// </summary>
        public void UpdateConfidence(EvidenceLevel evidence, string? supportingAnalysis = null)
        {
            EvidenceLevel = evidence;
            
            if (!string.IsNullOrWhiteSpace(supportingAnalysis))
            {
                AnalysisSupport = supportingAnalysis;
            }

            MappingConfidence = evidence switch
            {
                EvidenceLevel.High => 90,
                EvidenceLevel.Medium => 70,
                EvidenceLevel.Low => 40,
                EvidenceLevel.Speculative => 20,
                _ => 0
            };

            UpdatedAt = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// Enumeration of detection difficulty levels
    /// </summary>
    public enum DetectionDifficulty
    {
        Unknown = 0,
        Easy = 1,
        Medium = 2,
        Hard = 3,
        VeryHard = 4
    }

    /// <summary>
    /// Enumeration of evidence levels for technique mapping
    /// </summary>
    public enum EvidenceLevel
    {
        Unknown = 0,
        Speculative = 1,
        Low = 2,
        Medium = 3,
        High = 4,
        Confirmed = 5
    }

    /// <summary>
    /// Enumeration of detection coverage levels
    /// </summary>
    public enum DetectionCoverage
    {
        Unknown = 0,
        None = 1,
        Minimal = 2,
        Partial = 3,
        Good = 4,
        Excellent = 5
    }
}