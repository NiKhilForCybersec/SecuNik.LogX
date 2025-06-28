using System.ComponentModel.DataAnnotations;

namespace SecuNik.LogX.Core.Entities
{
    public class Rule
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();
        
        [Required]
        [MaxLength(200)]
        public string Name { get; set; } = string.Empty;
        
        [MaxLength(1000)]
        public string Description { get; set; } = string.Empty;
        
        [Required]
        public RuleType Type { get; set; }
        
        [MaxLength(100)]
        public string Category { get; set; } = string.Empty;
        
        [Required]
        public ThreatLevel Severity { get; set; } = ThreatLevel.Medium;
        
        [Required]
        public string Content { get; set; } = string.Empty;
        
        [MaxLength(100)]
        public string Author { get; set; } = string.Empty;
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
        
        public bool IsEnabled { get; set; } = true;
        
        public bool IsBuiltIn { get; set; } = false;
        
        public string? Tags { get; set; } // JSON array of tags
        
        public string? References { get; set; } // JSON array of references
        
        public string? Metadata { get; set; } // JSON metadata
        
        [MaxLength(50)]
        public string? RuleId { get; set; } // External rule ID (e.g., YARA rule name)
        
        public int Priority { get; set; } = 100;
        
        public long MatchCount { get; set; } = 0;
        
        public DateTime? LastMatched { get; set; }
        
        public bool IsValidated { get; set; } = false;
        
        public string? ValidationError { get; set; }
        
        // Navigation properties
        public ICollection<RuleMatch> RuleMatches { get; set; } = new List<RuleMatch>();
        
        // Helper methods
        public List<string> GetTags()
        {
            try
            {
                return string.IsNullOrEmpty(Tags) 
                    ? new List<string>() 
                    : System.Text.Json.JsonSerializer.Deserialize<List<string>>(Tags) ?? new List<string>();
            }
            catch
            {
                return new List<string>();
            }
        }
        
        public void SetTags(List<string> tags)
        {
            Tags = System.Text.Json.JsonSerializer.Serialize(tags);
        }
        
        public List<string> GetReferences()
        {
            try
            {
                return string.IsNullOrEmpty(References) 
                    ? new List<string>() 
                    : System.Text.Json.JsonSerializer.Deserialize<List<string>>(References) ?? new List<string>();
            }
            catch
            {
                return new List<string>();
            }
        }
        
        public void SetReferences(List<string> references)
        {
            References = System.Text.Json.JsonSerializer.Serialize(references);
        }
    }
}