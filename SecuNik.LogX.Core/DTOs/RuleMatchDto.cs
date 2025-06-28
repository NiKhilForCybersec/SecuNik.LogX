using SecuNik.LogX.Core.Entities;

namespace SecuNik.LogX.Core.DTOs
{
    public class RuleMatchDto
    {
        public Guid Id { get; set; }
        
        public Guid RuleId { get; set; }
        
        public string RuleName { get; set; } = string.Empty;
        
        public string RuleType { get; set; } = string.Empty;
        
        public string Severity { get; set; } = string.Empty;
        
        public int MatchCount { get; set; }
        
        public DateTime MatchedAt { get; set; }
        
        public string? MatchedContent { get; set; }
        
        public long? FileOffset { get; set; }
        
        public int? LineNumber { get; set; }
        
        public double Confidence { get; set; }
        
        public string? Context { get; set; }
        
        public List<string> MitreAttackIds { get; set; } = new();
        
        public bool IsFalsePositive { get; set; }
        
        public string? AnalystNotes { get; set; }
        
        public Dictionary<string, object> MatchDetails { get; set; } = new();
        
        public List<MatchDetailDto> Matches { get; set; } = new();
        
        public RuleInfoDto Rule { get; set; } = new();
    }
    
    public class MatchDetailDto
    {
        public string MatchedContent { get; set; } = string.Empty;
        
        public long? FileOffset { get; set; }
        
        public int? LineNumber { get; set; }
        
        public string Context { get; set; } = string.Empty;
        
        public Dictionary<string, object> Fields { get; set; } = new();
        
        public DateTime? Timestamp { get; set; }
        
        public double Confidence { get; set; } = 1.0;
    }
    
    public class RuleInfoDto
    {
        public Guid Id { get; set; }
        
        public string Name { get; set; } = string.Empty;
        
        public string Description { get; set; } = string.Empty;
        
        public string Type { get; set; } = string.Empty;
        
        public string Category { get; set; } = string.Empty;
        
        public string Severity { get; set; } = string.Empty;
        
        public string Author { get; set; } = string.Empty;
        
        public List<string> Tags { get; set; } = new();
        
        public List<string> References { get; set; } = new();
    }
}