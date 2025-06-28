using SecuNik.LogX.Core.Entities;

namespace SecuNik.LogX.Core.Interfaces
{
    public interface IRuleEngine
    {
        Task<List<RuleMatchResult>> ProcessAsync(Guid analysisId, List<LogEvent> events, string rawContent, CancellationToken cancellationToken = default);
        Task<List<RuleMatchResult>> ProcessWithRulesAsync(Guid analysisId, List<LogEvent> events, string rawContent, List<Rule> rules, CancellationToken cancellationToken = default);
        Task<ValidationResult> ValidateRuleAsync(Rule rule, CancellationToken cancellationToken = default);
        Task<TestResult> TestRuleAsync(Rule rule, string testContent, CancellationToken cancellationToken = default);
        Task LoadRulesAsync(CancellationToken cancellationToken = default);
        Task<List<Rule>> GetActiveRulesAsync(RuleType? ruleType = null, CancellationToken cancellationToken = default);
    }
    
    public class RuleMatchResult
    {
        public Guid RuleId { get; set; }
        public string RuleName { get; set; } = string.Empty;
        public RuleType RuleType { get; set; }
        public ThreatLevel Severity { get; set; }
        public int MatchCount { get; set; }
        public List<MatchDetail> Matches { get; set; } = new();
        public double Confidence { get; set; } = 1.0;
        public List<string> MitreAttackIds { get; set; } = new();
        public Dictionary<string, object> Metadata { get; set; } = new();
    }
    
    public class MatchDetail
    {
        public string MatchedContent { get; set; } = string.Empty;
        public long? FileOffset { get; set; }
        public int? LineNumber { get; set; }
        public string Context { get; set; } = string.Empty;
        public Dictionary<string, object> Fields { get; set; } = new();
        public DateTime? Timestamp { get; set; }
    }
    
    public class TestResult
    {
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
        public List<RuleMatchResult> Matches { get; set; } = new();
        public TimeSpan ProcessingTime { get; set; }
        public List<string> Warnings { get; set; } = new();
    }
}