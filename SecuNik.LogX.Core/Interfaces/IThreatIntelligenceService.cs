namespace SecuNik.LogX.Core.Interfaces
{
    public interface IThreatIntelligenceService
    {
        Task<ThreatIntelligenceResult> AnalyzeIOCAsync(string iocValue, IOCType iocType, CancellationToken cancellationToken = default);
        Task<List<ThreatIntelligenceResult>> AnalyzeIOCsAsync(List<IOC> iocs, CancellationToken cancellationToken = default);
        Task<ReputationResult> CheckReputationAsync(string value, IOCType type, CancellationToken cancellationToken = default);
        Task<List<IOC>> ExtractIOCsAsync(string content, CancellationToken cancellationToken = default);
        Task<ThreatContextResult> GetThreatContextAsync(List<IOC> iocs, CancellationToken cancellationToken = default);
    }
    
    public class ThreatIntelligenceResult
    {
        public string IOCValue { get; set; } = string.Empty;
        public IOCType IOCType { get; set; }
        public bool IsMalicious { get; set; }
        public int ThreatScore { get; set; } // 0-100
        public string Source { get; set; } = string.Empty;
        public List<string> ThreatTypes { get; set; } = new();
        public Dictionary<string, object> Details { get; set; } = new();
        public DateTime LastSeen { get; set; }
        public List<string> AssociatedMalware { get; set; } = new();
        public List<string> References { get; set; } = new();
    }
    
    public class ReputationResult
    {
        public string Value { get; set; } = string.Empty;
        public IOCType Type { get; set; }
        public ReputationStatus Status { get; set; }
        public int Score { get; set; } // 0-100, higher = more malicious
        public string Provider { get; set; } = string.Empty;
        public DateTime CheckedAt { get; set; }
        public Dictionary<string, object> Metadata { get; set; } = new();
    }
    
    public class IOC
    {
        public string Value { get; set; } = string.Empty;
        public IOCType Type { get; set; }
        public string Context { get; set; } = string.Empty;
        public DateTime? FirstSeen { get; set; }
        public int Confidence { get; set; } = 100; // 0-100
        public Dictionary<string, object> Metadata { get; set; } = new();
    }
    
    public class ThreatContextResult
    {
        public List<string> CampaignNames { get; set; } = new();
        public List<string> ThreatActors { get; set; } = new();
        public List<string> MalwareFamilies { get; set; } = new();
        public List<string> AttackPatterns { get; set; } = new();
        public Dictionary<string, object> Context { get; set; } = new();
    }
    
    public enum IOCType
    {
        IPAddress,
        Domain,
        URL,
        FileHash,
        Email,
        FilePath,
        RegistryKey,
        Mutex,
        UserAgent,
        Certificate,
        Other
    }
    
    public enum ReputationStatus
    {
        Unknown,
        Clean,
        Suspicious,
        Malicious,
        Error
    }
}