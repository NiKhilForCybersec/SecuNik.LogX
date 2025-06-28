using SecuNik.LogX.Core.Interfaces;
using System.Diagnostics;

namespace SecuNik.LogX.Api.Services.Parsers
{
    public abstract class BaseParser : IParser
    {
        public abstract string Name { get; }
        public abstract string Description { get; }
        public abstract string Version { get; }
        public abstract string[] SupportedExtensions { get; }
        
        protected readonly ILogger _logger;
        
        protected BaseParser(ILogger logger)
        {
            _logger = logger;
        }
        
        public virtual async Task<bool> CanParseAsync(string filePath, string content)
        {
            try
            {
                if (string.IsNullOrEmpty(filePath) || string.IsNullOrEmpty(content))
                    return false;
                
                var extension = Path.GetExtension(filePath).ToLowerInvariant();
                if (!SupportedExtensions.Contains(extension))
                    return false;
                
                return await CanParseContentAsync(content);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking if parser {ParserName} can parse file {FilePath}", Name, filePath);
                return false;
            }
        }
        
        public async Task<ParseResult> ParseAsync(string filePath, string content, CancellationToken cancellationToken = default)
        {
            var stopwatch = Stopwatch.StartNew();
            var result = new ParseResult
            {
                ParserUsed = Name
            };
            
            try
            {
                _logger.LogInformation("Starting parsing with {ParserName} for file {FilePath}", Name, filePath);
                
                if (string.IsNullOrEmpty(content))
                {
                    result.Success = false;
                    result.ErrorMessage = "Content is empty";
                    return result;
                }
                
                var events = await ParseContentAsync(filePath, content, cancellationToken);
                
                result.Success = true;
                result.Events = events;
                result.EventsCount = events.Count;
                result.Metadata = GetParsingMetadata(filePath, content);
                
                _logger.LogInformation("Successfully parsed {EventCount} events with {ParserName}", 
                    events.Count, Name);
            }
            catch (OperationCanceledException)
            {
                result.Success = false;
                result.ErrorMessage = "Parsing was cancelled";
                _logger.LogWarning("Parsing cancelled for {ParserName}", Name);
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                _logger.LogError(ex, "Error parsing with {ParserName} for file {FilePath}", Name, filePath);
            }
            finally
            {
                stopwatch.Stop();
                result.ProcessingTime = stopwatch.Elapsed;
            }
            
            return result;
        }
        
        public virtual async Task<ValidationResult> ValidateAsync(string content)
        {
            var result = new ValidationResult();
            
            try
            {
                if (string.IsNullOrEmpty(content))
                {
                    result.IsValid = false;
                    result.Errors.Add("Content is empty");
                    return result;
                }
                
                result = await ValidateContentAsync(content);
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.Errors.Add($"Validation error: {ex.Message}");
                _logger.LogError(ex, "Error validating content with {ParserName}", Name);
            }
            
            return result;
        }
        
        public virtual Dictionary<string, object> GetMetadata()
        {
            return new Dictionary<string, object>
            {
                ["name"] = Name,
                ["description"] = Description,
                ["version"] = Version,
                ["supported_extensions"] = SupportedExtensions,
                ["parser_type"] = GetType().Name,
                ["capabilities"] = GetCapabilities()
            };
        }
        
        // Abstract methods to be implemented by derived classes
        protected abstract Task<bool> CanParseContentAsync(string content);
        protected abstract Task<List<LogEvent>> ParseContentAsync(string filePath, string content, CancellationToken cancellationToken);
        protected abstract Task<ValidationResult> ValidateContentAsync(string content);
        
        // Virtual methods that can be overridden
        protected virtual Dictionary<string, object> GetParsingMetadata(string filePath, string content)
        {
            return new Dictionary<string, object>
            {
                ["file_path"] = filePath,
                ["file_size"] = content.Length,
                ["parser_name"] = Name,
                ["parser_version"] = Version,
                ["parsed_at"] = DateTime.UtcNow
            };
        }
        
        protected virtual List<string> GetCapabilities()
        {
            return new List<string> { "basic_parsing", "validation" };
        }
        
        // Helper methods
        protected DateTime ParseTimestamp(string timestampStr, string[] formats = null)
        {
            if (string.IsNullOrEmpty(timestampStr))
                return DateTime.UtcNow;
            
            var defaultFormats = new[]
            {
                "yyyy-MM-dd HH:mm:ss",
                "yyyy-MM-ddTHH:mm:ss",
                "yyyy-MM-ddTHH:mm:ssZ",
                "yyyy-MM-ddTHH:mm:ss.fffZ",
                "MM/dd/yyyy HH:mm:ss",
                "dd/MM/yyyy HH:mm:ss",
                "yyyy/MM/dd HH:mm:ss"
            };
            
            var formatsToTry = formats ?? defaultFormats;
            
            foreach (var format in formatsToTry)
            {
                if (DateTime.TryParseExact(timestampStr, format, null, 
                    System.Globalization.DateTimeStyles.AssumeUniversal, out var result))
                {
                    return result.ToUniversalTime();
                }
            }
            
            // Fallback to general parsing
            if (DateTime.TryParse(timestampStr, out var fallbackResult))
            {
                return fallbackResult.ToUniversalTime();
            }
            
            return DateTime.UtcNow;
        }
        
        protected string ExtractLogLevel(string line)
        {
            var levels = new[] { "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "CRITICAL" };
            var upperLine = line.ToUpperInvariant();
            
            foreach (var level in levels)
            {
                if (upperLine.Contains($"[{level}]") || upperLine.Contains($" {level} ") || 
                    upperLine.Contains($"{level}:") || upperLine.Contains($"<{level}>"))
                {
                    return level;
                }
            }
            
            return "INFO"; // Default level
        }
        
        protected Dictionary<string, object> ExtractFields(string line, string pattern = null)
        {
            var fields = new Dictionary<string, object>();
            
            if (string.IsNullOrEmpty(pattern))
            {
                // Basic field extraction
                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                for (int i = 0; i < parts.Length; i++)
                {
                    if (parts[i].Contains('='))
                    {
                        var keyValue = parts[i].Split('=', 2);
                        if (keyValue.Length == 2)
                        {
                            fields[keyValue[0]] = keyValue[1];
                        }
                    }
                }
            }
            else
            {
                // Pattern-based extraction (could be enhanced with regex)
                // This is a simplified implementation
                fields["raw_line"] = line;
            }
            
            return fields;
        }
        
        protected bool IsValidLogLine(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
                return false;
            
            // Skip comment lines
            if (line.TrimStart().StartsWith("#") || line.TrimStart().StartsWith("//"))
                return false;
            
            return true;
        }
        
        protected string CleanLogLine(string line)
        {
            if (string.IsNullOrEmpty(line))
                return string.Empty;
            
            // Remove common log prefixes/suffixes that might interfere with parsing
            return line.Trim();
        }
    }
}