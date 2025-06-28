namespace SecuNik.LogX.Core.DTOs
{
    public class ParserDto
    {
        public Guid Id { get; set; }
        
        public string Name { get; set; } = string.Empty;
        
        public string Description { get; set; } = string.Empty;
        
        public string Type { get; set; } = string.Empty;
        
        public string Version { get; set; } = string.Empty;
        
        public string Author { get; set; } = string.Empty;
        
        public DateTime CreatedAt { get; set; }
        
        public DateTime UpdatedAt { get; set; }
        
        public bool IsEnabled { get; set; }
        
        public bool IsBuiltIn { get; set; }
        
        public List<string> SupportedExtensions { get; set; } = new();
        
        public Dictionary<string, object> Configuration { get; set; } = new();
        
        public string? CodeContent { get; set; }
        
        public int Priority { get; set; }
        
        public long UsageCount { get; set; }
        
        public DateTime? LastUsed { get; set; }
        
        public ParserValidationDto? Validation { get; set; }
        
        public ParserStatisticsDto Statistics { get; set; } = new();
    }
    
    public class ParserValidationDto
    {
        public bool IsValid { get; set; }
        
        public List<string> Errors { get; set; } = new();
        
        public List<string> Warnings { get; set; } = new();
        
        public DateTime ValidatedAt { get; set; }
    }
    
    public class ParserStatisticsDto
    {
        public long TotalFilesProcessed { get; set; }
        
        public long TotalEventsExtracted { get; set; }
        
        public TimeSpan AverageProcessingTime { get; set; }
        
        public DateTime? LastUsed { get; set; }
        
        public Dictionary<string, long> ProcessedByFileType { get; set; } = new();
    }
    
    public class CreateParserDto
    {
        public string Name { get; set; } = string.Empty;
        
        public string Description { get; set; } = string.Empty;
        
        public string Type { get; set; } = string.Empty;
        
        public string Version { get; set; } = "1.0.0";
        
        public string Author { get; set; } = string.Empty;
        
        public List<string> SupportedExtensions { get; set; } = new();
        
        public Dictionary<string, object> Configuration { get; set; } = new();
        
        public string? CodeContent { get; set; }
        
        public int Priority { get; set; } = 100;
    }
    
    public class UpdateParserDto
    {
        public string? Description { get; set; }
        
        public string? Version { get; set; }
        
        public bool? IsEnabled { get; set; }
        
        public List<string>? SupportedExtensions { get; set; }
        
        public Dictionary<string, object>? Configuration { get; set; }
        
        public string? CodeContent { get; set; }
        
        public int? Priority { get; set; }
    }
}