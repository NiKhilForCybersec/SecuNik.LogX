using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace SecuNikLogX.API.Models
{
    /// <summary>
    /// Represents an Indicator of Compromise with enrichment data and threat intelligence
    /// </summary>
    public class IOC
    {
        /// <summary>
        /// Unique identifier for the IOC
        /// </summary>
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        /// <summary>
        /// Type of IOC (IP, Domain, URL, Hash, Email, etc.)
        /// </summary>
        [Required]
        public IOCType Type { get; set; }

        /// <summary>
        /// The actual IOC value (IP address, domain name, hash, etc.)
        /// </summary>
        [Required]
        [StringLength(2000, MinimumLength = 1)]
        public required string Value { get; set; }

        /// <summary>
        /// Description of the IOC and its significance
        /// </summary>
        [StringLength(2000)]
        public string? Description { get; set; }

        /// <summary>
        /// Threat level assessment for this IOC
        /// </summary>
        public ThreatLevel ThreatLevel { get; set; } = ThreatLevel.Unknown;

        /// <summary>
        /// Confidence level in the IOC's malicious nature (0-100)
        /// </summary>
        [Range(0, 100)]
        public int Confidence { get; set; } = 0;

        /// <summary>
        /// When this IOC was first observed
        /// </summary>
        public DateTime? FirstSeen { get; set; }

        /// <summary>
        /// When this IOC was last observed
        /// </summary>
        public DateTime? LastSeen { get; set; }

        /// <summary>
        /// Source of the IOC information
        /// </summary>
        [StringLength(200)]
        public string? SourceName { get; set; }

        /// <summary>
        /// Reliability of the IOC source
        /// </summary>
        public SourceReliability SourceReliability { get; set; } = SourceReliability.Unknown;

        /// <summary>
        /// Method used to detect this IOC
        /// </summary>
        [StringLength(200)]
        public string? DetectionMethod { get; set; }

        /// <summary>
        /// Foreign key to the analysis that discovered this IOC
        /// </summary>
        public Guid? AnalysisId { get; set; }

        /// <summary>
        /// Navigation property to the analysis
        /// </summary>
        [ForeignKey(nameof(AnalysisId))]
        public virtual Analysis? Analysis { get; set; }

        /// <summary>
        /// Geographic location information for network-based IOCs
        /// </summary>
        [StringLength(200)]
        public string? GeoLocation { get; set; }

        /// <summary>
        /// Autonomous System Number for network IOCs
        /// </summary>
        [StringLength(20)]
        public string? ASN { get; set; }

        /// <summary>
        /// Internet Service Provider for network IOCs
        /// </summary>
        [StringLength(200)]
        public string? ISP { get; set; }

        /// <summary>
        /// Organization owning the network resource
        /// </summary>
        [StringLength(200)]
        public string? Organization { get; set; }

        /// <summary>
        /// Whether this IOC is currently active/valid
        /// </summary>
        public bool IsActive { get; set; } = true;

        /// <summary>
        /// Whether this IOC is whitelisted (false positive)
        /// </summary>
        public bool IsWhitelisted { get; set; } = false;

        /// <summary>
        /// Flag indicating if this is a known false positive
        /// </summary>
        public bool FalsePositiveFlag { get; set; } = false;

        /// <summary>
        /// Campaign or attack name associated with this IOC
        /// </summary>
        [StringLength(200)]
        public string? Campaign { get; set; }

        /// <summary>
        /// Threat actor or group associated with this IOC
        /// </summary>
        [StringLength(200)]
        public string? ThreatActor { get; set; }

        /// <summary>
        /// Malware family associated with this IOC
        /// </summary>
        [StringLength(200)]
        public string? Family { get; set; }

        /// <summary>
        /// Tags for categorization and search
        /// </summary>
        [StringLength(1000)]
        public string? Tags { get; set; }

        /// <summary>
        /// Network protocol for network-based IOCs
        /// </summary>
        [StringLength(20)]
        public string? Protocol { get; set; }

        /// <summary>
        /// Port number for network IOCs
        /// </summary>
        [Range(0, 65535)]
        public int? Port { get; set; }

        /// <summary>
        /// Network segment or VLAN information
        /// </summary>
        [StringLength(100)]
        public string? NetworkSegment { get; set; }

        /// <summary>
        /// File type for file-based IOCs
        /// </summary>
        [StringLength(50)]
        public string? FileType { get; set; }

        /// <summary>
        /// File size for file-based IOCs
        /// </summary>
        [Range(0, long.MaxValue)]
        public long? FileSize { get; set; }

        /// <summary>
        /// Digital signature information for file IOCs
        /// </summary>
        [StringLength(500)]
        public string? Signature { get; set; }

        /// <summary>
        /// When this IOC expires or becomes invalid
        /// </summary>
        public DateTime? ExpiryDate { get; set; }

        /// <summary>
        /// How long this IOC remains valid
        /// </summary>
        [StringLength(50)]
        public string? ValidityPeriod { get; set; }

        /// <summary>
        /// How often this IOC should be updated
        /// </summary>
        [StringLength(50)]
        public string? UpdateFrequency { get; set; }

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
        /// Collection of MITRE ATT&CK techniques associated with this IOC
        /// </summary>
        public virtual ICollection<MITRE> MITREMappings { get; set; } = new List<MITRE>();

        /// <summary>
        /// Validates the IOC value format based on its type
        /// </summary>
        public bool ValidateFormat()
        {
            if (string.IsNullOrWhiteSpace(Value))
                return false;

            return Type switch
            {
                IOCType.IP => ValidateIPAddress(),
                IOCType.Domain => ValidateDomain(),
                IOCType.URL => ValidateURL(),
                IOCType.Hash => ValidateHash(),
                IOCType.Email => ValidateEmail(),
                IOCType.Registry => ValidateRegistry(),
                IOCType.FilePath => ValidateFilePath(),
                _ => true // Unknown types pass through
            };
        }

        private bool ValidateIPAddress()
        {
            return System.Net.IPAddress.TryParse(Value, out _);
        }

        private bool ValidateDomain()
        {
            try
            {
                var uri = new Uri($"http://{Value}");
                return uri.Host == Value;
            }
            catch
            {
                return false;
            }
        }

        private bool ValidateURL()
        {
            return Uri.TryCreate(Value, UriKind.Absolute, out _);
        }

        private bool ValidateHash()
        {
            // Support MD5 (32), SHA1 (40), SHA256 (64) hashes
            var length = Value.Length;
            if (length != 32 && length != 40 && length != 64)
                return false;

            return System.Text.RegularExpressions.Regex.IsMatch(Value, @"^[a-fA-F0-9]+$");
        }

        private bool ValidateEmail()
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(Value);
                return addr.Address == Value;
            }
            catch
            {
                return false;
            }
        }

        private bool ValidateRegistry()
        {
            // Basic Windows registry path validation
            return Value.StartsWith("HKEY_") || Value.StartsWith("HKLM\\") || Value.StartsWith("HKCU\\");
        }

        private bool ValidateFilePath()
        {
            try
            {
                return !string.IsNullOrWhiteSpace(System.IO.Path.GetFileName(Value));
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Checks if the IOC has expired
        /// </summary>
        public bool IsExpired()
        {
            return ExpiryDate.HasValue && ExpiryDate.Value < DateTime.UtcNow;
        }

        /// <summary>
        /// Updates the last seen timestamp
        /// </summary>
        public void UpdateLastSeen()
        {
            LastSeen = DateTime.UtcNow;
            UpdatedAt = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// Enumeration of IOC types
    /// </summary>
    public enum IOCType
    {
        IP = 0,
        Domain = 1,
        URL = 2,
        Hash = 3,
        Email = 4,
        Registry = 5,
        FilePath = 6,
        Process = 7,
        Service = 8,
        Mutex = 9,
        UserAgent = 10,
        Certificate = 11
    }

    /// <summary>
    /// Enumeration of source reliability levels
    /// </summary>
    public enum SourceReliability
    {
        Unknown = 0,
        Unreliable = 1,
        UsuallyReliable = 2,
        Reliable = 3,
        VeryReliable = 4,
        CompletelyReliable = 5
    }
}