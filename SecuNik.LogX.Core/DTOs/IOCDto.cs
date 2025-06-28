namespace SecuNik.LogX.Core.DTOs
{
    public class IOCDto
    {
        public string Value { get; set; } = string.Empty;
        
        public string Type { get; set; } = string.Empty; // ip, domain, hash, email, etc.
        
        public string Context { get; set; } = string.Empty;
        
        public DateTime? FirstSeen { get; set; }
        
        public DateTime? LastSeen { get; set; }
        
        public int Confidence { get; set; } = 100; // 0-100
        
        public string Source { get; set; } = string.Empty;
        
        public bool IsMalicious { get; set; }
        
        public int ThreatScore { get; set; } // 0-100
        
        public List<string> ThreatTypes { get; set; } = new();
        
        public List<string> AssociatedMalware { get; set; } = new();
        
        public List<string> References { get; set; } = new();
        
        public Dictionary<string, object> Metadata { get; set; } = new();
        
        public ThreatIntelligenceDto? ThreatIntelligence { get; set; }
    }
    
    public class IOCExtractionResultDto
    {
        public List<IOCDto> IOCs { get; set; } = new();
        
        public int TotalFound { get; set; }
        
        public Dictionary<string, int> CountByType { get; set; } = new();
        
        public TimeSpan ProcessingTime { get; set; }
        
        public List<string> Warnings { get; set; } = new();
    }
}