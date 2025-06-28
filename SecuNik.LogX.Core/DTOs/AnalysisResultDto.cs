namespace SecuNik.LogX.Core.DTOs
{
    public class AnalysisResultDto
    {
        public Guid Id { get; set; }
        
        public string FileName { get; set; } = string.Empty;
        
        public string FileHash { get; set; } = string.Empty;
        
        public long FileSize { get; set; }
        
        public string FileType { get; set; } = string.Empty;
        
        public DateTime UploadTime { get; set; }
        
        public DateTime? StartTime { get; set; }
        
        public DateTime? CompletionTime { get; set; }
        
        public string Status { get; set; } = string.Empty;
        
        public int Progress { get; set; }
        
        public int ThreatScore { get; set; }
        
        public string Severity { get; set; } = string.Empty;
        
        public string? Summary { get; set; }
        
        public string? AISummary { get; set; }
        
        public string? ErrorMessage { get; set; }
        
        public TimeSpan? Duration { get; set; }
        
        public ParserInfoDto? Parser { get; set; }
        
        public List<RuleMatchDto> RuleMatches { get; set; } = new();
        
        public List<IOCDto> IOCs { get; set; } = new();
        
        public List<TimelineEventDto> Timeline { get; set; } = new();
        
        public MitreAttackDto? MitreResults { get; set; }
        
        public ThreatIntelligenceDto? ThreatIntelligence { get; set; }
        
        public List<string> Tags { get; set; } = new();
        
        public string? Notes { get; set; }
        
        public AnalysisStatisticsDto Statistics { get; set; } = new();
    }
    
    public class ParserInfoDto
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
    }
    
    public class AnalysisStatisticsDto
    {
        public int TotalEvents { get; set; }
        public int TotalRuleMatches { get; set; }
        public int TotalIOCs { get; set; }
        public int CriticalFindings { get; set; }
        public int HighFindings { get; set; }
        public int MediumFindings { get; set; }
        public int LowFindings { get; set; }
        public Dictionary<string, int> EventsByLevel { get; set; } = new();
        public Dictionary<string, int> MatchesByRuleType { get; set; } = new();
        public Dictionary<string, int> IOCsByType { get; set; } = new();
    }
}