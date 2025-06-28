using System.ComponentModel.DataAnnotations;

namespace SecuNik.LogX.Core.Entities
{
    public class Analysis
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();
        
        [Required]
        [MaxLength(255)]
        public string FileName { get; set; } = string.Empty;
        
        [Required]
        [MaxLength(64)]
        public string FileHash { get; set; } = string.Empty;
        
        public long FileSize { get; set; }
        
        [Required]
        [MaxLength(100)]
        public string FileType { get; set; } = string.Empty;
        
        public DateTime UploadTime { get; set; } = DateTime.UtcNow;
        
        public DateTime? StartTime { get; set; }
        
        public DateTime? CompletionTime { get; set; }
        
        [Required]
        [MaxLength(50)]
        public string Status { get; set; } = "queued"; // queued, processing, completed, failed, cancelled
        
        public Guid? ParserId { get; set; }
        
        public int Progress { get; set; } = 0;
        
        public int ThreatScore { get; set; } = 0;
        
        [MaxLength(20)]
        public string Severity { get; set; } = "low"; // low, medium, high, critical
        
        public string? Summary { get; set; }
        
        public string? AISummary { get; set; }
        
        public string? ErrorMessage { get; set; }
        
        public string? ParsedDataJson { get; set; }
        
        public string? TimelineJson { get; set; }
        
        public string? IOCsJson { get; set; }
        
        public string? MitreResultsJson { get; set; }
        
        public string? ThreatIntelligenceJson { get; set; }
        
        public string? Tags { get; set; } // JSON array of tags
        
        public string? Notes { get; set; }
        
        // Navigation properties
        public Parser? Parser { get; set; }
        public ICollection<RuleMatch> RuleMatches { get; set; } = new List<RuleMatch>();
        
        // Computed properties
        public TimeSpan? Duration => CompletionTime.HasValue && StartTime.HasValue 
            ? CompletionTime.Value - StartTime.Value 
            : null;
            
        public bool IsCompleted => Status == "completed";
        public bool IsFailed => Status == "failed";
        public bool IsProcessing => Status == "processing";
    }
}