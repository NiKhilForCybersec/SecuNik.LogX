namespace SecuNik.LogX.Core.DTOs
{
    public class TimelineEventDto
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        
        public string EventType { get; set; } = string.Empty;
        
        public string Title { get; set; } = string.Empty;
        
        public string Description { get; set; } = string.Empty;
        
        public string Severity { get; set; } = "info";
        
        public string Source { get; set; } = string.Empty;
        
        public string Category { get; set; } = string.Empty;
        
        public Dictionary<string, object> Details { get; set; } = new();
        
        public List<string> Tags { get; set; } = new();
        
        public List<string> RelatedIOCs { get; set; } = new();
        
        public List<string> MitreAttackIds { get; set; } = new();
        
        public long? FileOffset { get; set; }
        
        public int? LineNumber { get; set; }
        
        public string? RawData { get; set; }
        
        public double Confidence { get; set; } = 1.0;
        
        public bool IsAnomalous { get; set; }
        
        public string? AnalystNotes { get; set; }
    }
    
    public class TimelineFilterDto
    {
        public DateTime? StartTime { get; set; }
        
        public DateTime? EndTime { get; set; }
        
        public List<string> EventTypes { get; set; } = new();
        
        public List<string> Severities { get; set; } = new();
        
        public List<string> Sources { get; set; } = new();
        
        public List<string> Categories { get; set; } = new();
        
        public List<string> Tags { get; set; } = new();
        
        public bool? IsAnomalous { get; set; }
        
        public string? SearchText { get; set; }
        
        public int Skip { get; set; } = 0;
        
        public int Take { get; set; } = 100;
        
        public string SortBy { get; set; } = "timestamp";
        
        public bool SortDescending { get; set; } = true;
    }
    
    public class TimelineStatisticsDto
    {
        public int TotalEvents { get; set; }
        
        public DateTime FirstEvent { get; set; } = DateTime.MinValue;
        
        public DateTime LastEvent { get; set; } = DateTime.MinValue;
        
        public TimeSpan TimeRange { get; set; }
        
        public Dictionary<string, int> EventsByType { get; set; } = new();
        
        public Dictionary<string, int> EventsBySeverity { get; set; } = new();
        
        public Dictionary<string, int> EventsBySource { get; set; } = new();
        
        public Dictionary<string, int> EventsByCategory { get; set; } = new();
        
        public Dictionary<DateTime, int> EventsByHour { get; set; } = new();
        
        public List<string> TopTags { get; set; } = new();
        
        public int AnomalousEvents { get; set; }
    }
}