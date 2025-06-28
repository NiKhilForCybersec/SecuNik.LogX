using System.ComponentModel.DataAnnotations;

namespace SecuNik.LogX.Core.Entities
{
    public class RuleMatch
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();
        
        [Required]
        public Guid AnalysisId { get; set; }
        
        [Required]
        public Guid RuleId { get; set; }
        
        [Required]
        [MaxLength(200)]
        public string RuleName { get; set; } = string.Empty;
        
        [Required]
        public RuleType RuleType { get; set; }
        
        [Required]
        public ThreatLevel Severity { get; set; }
        
        public int MatchCount { get; set; } = 1;
        
        public DateTime MatchedAt { get; set; } = DateTime.UtcNow;
        
        public string? MatchDetails { get; set; } // JSON details of the match
        
        public string? MatchedContent { get; set; } // The actual content that matched
        
        public long? FileOffset { get; set; } // Offset in file where match occurred
        
        public int? LineNumber { get; set; } // Line number where match occurred
        
        public double Confidence { get; set; } = 1.0; // 0.0 to 1.0
        
        public string? Context { get; set; } // Additional context information
        
        public string? MitreAttackIds { get; set; } // JSON array of MITRE ATT&CK technique IDs
        
        public bool IsFalsePositive { get; set; } = false;
        
        public string? AnalystNotes { get; set; }
        
        // Navigation properties
        public Analysis Analysis { get; set; } = null!;
        public Rule Rule { get; set; } = null!;
        
        // Helper methods
        public List<string> GetMitreAttackIds()
        {
            try
            {
                return string.IsNullOrEmpty(MitreAttackIds) 
                    ? new List<string>() 
                    : System.Text.Json.JsonSerializer.Deserialize<List<string>>(MitreAttackIds) ?? new List<string>();
            }
            catch
            {
                return new List<string>();
            }
        }
        
        public void SetMitreAttackIds(List<string> ids)
        {
            MitreAttackIds = System.Text.Json.JsonSerializer.Serialize(ids);
        }
        
        public T? GetMatchDetails<T>() where T : class
        {
            try
            {
                return string.IsNullOrEmpty(MatchDetails) 
                    ? null 
                    : System.Text.Json.JsonSerializer.Deserialize<T>(MatchDetails);
            }
            catch
            {
                return null;
            }
        }
        
        public void SetMatchDetails<T>(T details) where T : class
        {
            MatchDetails = System.Text.Json.JsonSerializer.Serialize(details);
        }
    }
}