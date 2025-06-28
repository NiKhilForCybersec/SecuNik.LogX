using SecuNik.LogX.Core.Entities;

namespace SecuNik.LogX.Core.DTOs
{
    public class RuleDto
    {
        public Guid Id { get; set; }
        
        public string Name { get; set; } = string.Empty;
        
        public string Description { get; set; } = string.Empty;
        
        public string Type { get; set; } = string.Empty;
        
        public string Category { get; set; } = string.Empty;
        
        public string Severity { get; set; } = string.Empty;
        
        public string Content { get; set; } = string.Empty;
        
        public string Author { get; set; } = string.Empty;
        
        public DateTime CreatedAt { get; set; }
        
        public DateTime UpdatedAt { get; set; }
        
        public bool IsEnabled { get; set; }
        
        public bool IsBuiltIn { get; set; }
        
        public List<string> Tags { get; set; } = new();
        
        public List<string> References { get; set; } = new();
        
        public Dictionary<string, object> Metadata { get; set; } = new();
        
        public string? RuleId { get; set; }
        
        public int Priority { get; set; }
        
        public long MatchCount { get; set; }
        
        public DateTime? LastMatched { get; set; }
        
        public bool IsValidated { get; set; }
        
        public string? ValidationError { get; set; }
        
        public RuleStatisticsDto Statistics { get; set; } = new();
    }
    
    public class RuleStatisticsDto
    {
        public long TotalMatches { get; set; }
        
        public long MatchesLast24Hours { get; set; }
        
        public long MatchesLast7Days { get; set; }
        
        public long MatchesLast30Days { get; set; }
        
        public DateTime? FirstMatch { get; set; }
        
        public DateTime? LastMatch { get; set; }
        
        public double AverageConfidence { get; set; }
        
        public Dictionary<string, long> MatchesByAnalysis { get; set; } = new();
    }
    
    public class CreateRuleDto
    {
        public string Name { get; set; } = string.Empty;
        
        public string Description { get; set; } = string.Empty;
        
        public RuleType Type { get; set; }
        
        public string Category { get; set; } = string.Empty;
        
        public ThreatLevel Severity { get; set; }
        
        public string Content { get; set; } = string.Empty;
        
        public string Author { get; set; } = string.Empty;
        
        public List<string> Tags { get; set; } = new();
        
        public List<string> References { get; set; } = new();
        
        public Dictionary<string, object> Metadata { get; set; } = new();
        
        public string? RuleId { get; set; }
        
        public int Priority { get; set; } = 100;
    }
    
    public class UpdateRuleDto
    {
        public string? Description { get; set; }
        
        public string? Category { get; set; }
        
        public ThreatLevel? Severity { get; set; }
        
        public string? Content { get; set; }
        
        public bool? IsEnabled { get; set; }
        
        public List<string>? Tags { get; set; }
        
        public List<string>? References { get; set; }
        
        public Dictionary<string, object>? Metadata { get; set; }
        
        public int? Priority { get; set; }
    }
    
    public class RuleTestDto
    {
        public string TestContent { get; set; } = string.Empty;
        
        public Dictionary<string, object> TestOptions { get; set; } = new();
    }
    
    public class RuleTestResultDto
    {
        public bool Success { get; set; }
        
        public string? ErrorMessage { get; set; }
        
        public List<RuleMatchDto> Matches { get; set; } = new();
        
        public TimeSpan ProcessingTime { get; set; }
        
        public List<string> Warnings { get; set; } = new();
        
        public Dictionary<string, object> Details { get; set; } = new();
    }
}