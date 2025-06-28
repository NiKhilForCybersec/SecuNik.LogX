namespace SecuNik.LogX.Core.DTOs
{
    public class ThreatIntelligenceDto
    {
        public string IOCValue { get; set; } = string.Empty;
        
        public string IOCType { get; set; } = string.Empty;
        
        public bool IsMalicious { get; set; }
        
        public int ThreatScore { get; set; } // 0-100
        
        public string Source { get; set; } = string.Empty;
        
        public List<string> ThreatTypes { get; set; } = new();
        
        public Dictionary<string, object> Details { get; set; } = new();
        
        public DateTime LastSeen { get; set; }
        
        public List<string> AssociatedMalware { get; set; } = new();
        
        public List<string> References { get; set; } = new();
        
        public List<string> CampaignNames { get; set; } = new();
        
        public List<string> ThreatActors { get; set; } = new();
        
        public List<string> MalwareFamilies { get; set; } = new();
        
        public VirusTotalResultDto? VirusTotalResult { get; set; }
        
        public Dictionary<string, ReputationResultDto> ReputationResults { get; set; } = new();
    }
    
    public class VirusTotalResultDto
    {
        public string Resource { get; set; } = string.Empty;
        
        public string ScanId { get; set; } = string.Empty;
        
        public string Permalink { get; set; } = string.Empty;
        
        public int Positives { get; set; }
        
        public int Total { get; set; }
        
        public DateTime ScanDate { get; set; }
        
        public Dictionary<string, ScanResultDto> Scans { get; set; } = new();
        
        public string? AdditionalInfo { get; set; }
    }
    
    public class ScanResultDto
    {
        public bool Detected { get; set; }
        
        public string? Result { get; set; }
        
        public string? Version { get; set; }
        
        public DateTime? Update { get; set; }
    }
    
    public class ReputationResultDto
    {
        public string Value { get; set; } = string.Empty;
        
        public string Type { get; set; } = string.Empty;
        
        public string Status { get; set; } = string.Empty; // clean, suspicious, malicious, unknown
        
        public int Score { get; set; } // 0-100
        
        public string Provider { get; set; } = string.Empty;
        
        public DateTime CheckedAt { get; set; }
        
        public Dictionary<string, object> Metadata { get; set; } = new();
    }
    
    public class ThreatContextDto
    {
        public List<string> CampaignNames { get; set; } = new();
        
        public List<string> ThreatActors { get; set; } = new();
        
        public List<string> MalwareFamilies { get; set; } = new();
        
        public List<string> AttackPatterns { get; set; } = new();
        
        public Dictionary<string, object> Context { get; set; } = new();
        
        public List<RelatedThreatDto> RelatedThreats { get; set; } = new();
    }
    
    public class RelatedThreatDto
    {
        public string Name { get; set; } = string.Empty;
        
        public string Type { get; set; } = string.Empty;
        
        public string Description { get; set; } = string.Empty;
        
        public double Similarity { get; set; }
        
        public List<string> SharedIOCs { get; set; } = new();
        
        public Dictionary<string, object> Metadata { get; set; } = new();
    }
}