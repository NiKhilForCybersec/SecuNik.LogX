using System.ComponentModel.DataAnnotations;

namespace SecuNik.LogX.Core.DTOs
{
    public class AnalysisRequestDto
    {
        [Required]
        public Guid UploadId { get; set; }
        
        public List<string> Analyzers { get; set; } = new() { "yara", "sigma", "mitre", "ai", "patterns" };
        
        public AnalysisOptionsDto Options { get; set; } = new();
        
        public int Priority { get; set; } = 100; // Lower number = higher priority
        
        public List<string> Tags { get; set; } = new();
        
        public string? Notes { get; set; }
    }
    
    public class AnalysisOptionsDto
    {
        public bool DeepScan { get; set; } = true;
        
        public bool ExtractIOCs { get; set; } = true;
        
        public bool CheckVirusTotal { get; set; } = true;
        
        public bool EnableAI { get; set; } = false;
        
        public bool GenerateTimeline { get; set; } = true;
        
        public bool MapToMitre { get; set; } = true;
        
        public int MaxEvents { get; set; } = 100000;
        
        public int TimeoutMinutes { get; set; } = 30;
        
        public List<string> IncludeRuleTypes { get; set; } = new() { "yara", "sigma" };
        
        public List<string> ExcludeRuleCategories { get; set; } = new();
        
        public Dictionary<string, object> CustomOptions { get; set; } = new();
    }
}