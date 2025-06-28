namespace SecuNik.LogX.Core.Interfaces
{
    public interface IParser
    {
        string Name { get; }
        string Description { get; }
        string Version { get; }
        string[] SupportedExtensions { get; }
        
        Task<bool> CanParseAsync(string filePath, string content);
        Task<ParseResult> ParseAsync(string filePath, string content, CancellationToken cancellationToken = default);
        Task<ValidationResult> ValidateAsync(string content);
        Dictionary<string, object> GetMetadata();
    }
    
    public class ParseResult
    {
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
        public List<LogEvent> Events { get; set; } = new();
        public Dictionary<string, object> Metadata { get; set; } = new();
        public string ParserUsed { get; set; } = string.Empty;
        public int EventsCount { get; set; }
        public TimeSpan ProcessingTime { get; set; }
        public List<string> Warnings { get; set; } = new();
        
        public static ParseResult Success(List<LogEvent> events, string parserName)
        {
            return new ParseResult
            {
                Success = true,
                Events = events,
                EventsCount = events.Count,
                ParserUsed = parserName
            };
        }
        
        public static ParseResult Failure(string errorMessage, string parserName)
        {
            return new ParseResult
            {
                Success = false,
                ErrorMessage = errorMessage,
                ParserUsed = parserName
            };
        }
    }
    
    public class LogEvent
    {
        public DateTime Timestamp { get; set; }
        public string Level { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public Dictionary<string, object> Fields { get; set; } = new();
        public string RawData { get; set; } = string.Empty;
        public long? Offset { get; set; }
        public int? LineNumber { get; set; }
    }
    
    public class ValidationResult
    {
        public bool IsValid { get; set; }
        public List<string> Errors { get; set; } = new();
        public List<string> Warnings { get; set; } = new();
        public Dictionary<string, object> Suggestions { get; set; } = new();
        public Dictionary<string, object> Metadata { get; set; } = new();
    }
}