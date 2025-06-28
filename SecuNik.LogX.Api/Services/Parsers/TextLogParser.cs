using SecuNik.LogX.Core.Interfaces;
using System.Text.RegularExpressions;

namespace SecuNik.LogX.Api.Services.Parsers
{
    public class TextLogParser : BaseParser
    {
        public override string Name => "Text Log Parser";
        public override string Description => "Parses plain text log files with common patterns including syslog, Apache, IIS, and custom formats";
        public override string Version => "1.0.0";
        public override string[] SupportedExtensions => new[] { ".log", ".txt", ".syslog" };
        
        private readonly Dictionary<string, Regex> _logPatterns;
        
        public TextLogParser(ILogger<TextLogParser> logger) : base(logger)
        {
            _logPatterns = InitializeLogPatterns();
        }
        
        protected override async Task<bool> CanParseContentAsync(string content)
        {
            try
            {
                var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                if (lines.Length == 0) return false;
                
                // Check if at least some lines match common log patterns
                var matchingLines = 0;
                var linesToCheck = Math.Min(10, lines.Length);
                
                for (int i = 0; i < linesToCheck; i++)
                {
                    var line = lines[i].Trim();
                    if (string.IsNullOrEmpty(line)) continue;
                    
                    if (MatchesAnyPattern(line))
                    {
                        matchingLines++;
                    }
                }
                
                // If at least 30% of checked lines match patterns, consider it parseable
                return matchingLines >= linesToCheck * 0.3;
            }
            catch
            {
                return false;
            }
        }
        
        protected override async Task<List<LogEvent>> ParseContentAsync(string filePath, string content, CancellationToken cancellationToken)
        {
            var events = new List<LogEvent>();
            var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            
            try
            {
                for (int i = 0; i < lines.Length; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    var line = lines[i].Trim();
                    if (!IsValidLogLine(line)) continue;
                    
                    var logEvent = await ParseLogLineAsync(line, i + 1);
                    if (logEvent != null)
                    {
                        events.Add(logEvent);
                    }
                }
                
                _logger.LogInformation("Parsed {EventCount} text log events from {FilePath}", events.Count, filePath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing text log content from {FilePath}", filePath);
                throw;
            }
            
            return events;
        }
        
        protected override async Task<ValidationResult> ValidateContentAsync(string content)
        {
            var result = new ValidationResult { IsValid = true };
            
            try
            {
                var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                
                if (lines.Length == 0)
                {
                    result.IsValid = false;
                    result.Errors.Add("Content is empty");
                    return result;
                }
                
                var validLines = 0;
                var totalLines = 0;
                var patternMatches = new Dictionary<string, int>();
                
                foreach (var pattern in _logPatterns.Keys)
                {
                    patternMatches[pattern] = 0;
                }
                
                for (int i = 0; i < lines.Length; i++)
                {
                    var line = lines[i].Trim();
                    if (!IsValidLogLine(line)) continue;
                    
                    totalLines++;
                    
                    var matchedPattern = GetMatchingPattern(line);
                    if (matchedPattern != null)
                    {
                        validLines++;
                        patternMatches[matchedPattern]++;
                    }
                }
                
                var validPercentage = totalLines > 0 ? (double)validLines / totalLines * 100 : 0;
                
                if (validPercentage < 30)
                {
                    result.Warnings.Add($"Only {validPercentage:F1}% of lines match known log patterns");
                }
                
                result.Suggestions["total_lines"] = totalLines;
                result.Suggestions["valid_lines"] = validLines;
                result.Suggestions["valid_percentage"] = validPercentage;
                result.Suggestions["pattern_matches"] = patternMatches;
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.Errors.Add($"Validation error: {ex.Message}");
            }
            
            return await Task.FromResult(result);
        }
        
        private async Task<LogEvent?> ParseLogLineAsync(string line, int lineNumber)
        {
            try
            {
                var logEvent = new LogEvent
                {
                    LineNumber = lineNumber,
                    RawData = line,
                    Timestamp = DateTime.UtcNow, // Default, will be overridden if timestamp found
                    Level = "INFO", // Default, will be overridden if level found
                    Message = line, // Default, will be overridden if message extracted
                    Source = string.Empty
                };
                
                // Try to match against known patterns
                var matchedPattern = GetMatchingPattern(line);
                if (matchedPattern != null)
                {
                    ParseWithPattern(logEvent, line, matchedPattern);
                }
                else
                {
                    // Fallback to basic parsing
                    ParseBasicLogLine(logEvent, line);
                }
                
                return await Task.FromResult(logEvent);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error parsing log line {LineNumber}: {Line}", lineNumber, line);
                return null;
            }
        }
        
        private Dictionary<string, Regex> InitializeLogPatterns()
        {
            var patterns = new Dictionary<string, Regex>();
            
            // Syslog pattern (RFC3164)
            patterns["syslog"] = new Regex(
                @"^(?<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?<hostname>\S+)\s+(?<process>\S+?)(\[(?<pid>\d+)\])?\s*:\s*(?<message>.*)$",
                RegexOptions.Compiled);
            
            // Apache Common Log Format
            patterns["apache_common"] = new Regex(
                @"^(?<ip>\S+)\s+\S+\s+\S+\s+\[(?<timestamp>[^\]]+)\]\s+""(?<method>\S+)\s+(?<url>\S+)\s+(?<protocol>\S+)""\s+(?<status>\d+)\s+(?<size>\S+)$",
                RegexOptions.Compiled);
            
            // Apache Combined Log Format
            patterns["apache_combined"] = new Regex(
                @"^(?<ip>\S+)\s+\S+\s+\S+\s+\[(?<timestamp>[^\]]+)\]\s+""(?<method>\S+)\s+(?<url>\S+)\s+(?<protocol>\S+)""\s+(?<status>\d+)\s+(?<size>\S+)\s+""(?<referer>[^""]*)""\s+""(?<useragent>[^""]*)""",
                RegexOptions.Compiled);
            
            // IIS Log Format
            patterns["iis"] = new Regex(
                @"^(?<date>\d{4}-\d{2}-\d{2})\s+(?<time>\d{2}:\d{2}:\d{2})\s+(?<ip>\S+)\s+(?<method>\S+)\s+(?<uri>\S+)\s+(?<query>\S+)\s+(?<port>\d+)\s+(?<username>\S+)\s+(?<clientip>\S+)\s+(?<useragent>\S+)\s+(?<referer>\S+)\s+(?<status>\d+)\s+(?<substatus>\d+)\s+(?<win32status>\d+)\s+(?<timetaken>\d+)$",
                RegexOptions.Compiled);
            
            // Generic timestamp + level + message pattern
            patterns["generic_level"] = new Regex(
                @"^(?<timestamp>\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:\d{2})?)\s*[\[\(]?(?<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)[\]\)]?\s*(?<message>.*)$",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);
            
            // Simple timestamp + message pattern
            patterns["generic_timestamp"] = new Regex(
                @"^(?<timestamp>\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:\d{2})?)\s+(?<message>.*)$",
                RegexOptions.Compiled);
            
            // Level + message pattern (no timestamp)
            patterns["level_only"] = new Regex(
                @"^[\[\(]?(?<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)[\]\)]?\s*[:\-]?\s*(?<message>.*)$",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);
            
            return patterns;
        }
        
        private bool MatchesAnyPattern(string line)
        {
            return _logPatterns.Values.Any(pattern => pattern.IsMatch(line));
        }
        
        private string? GetMatchingPattern(string line)
        {
            foreach (var kvp in _logPatterns)
            {
                if (kvp.Value.IsMatch(line))
                {
                    return kvp.Key;
                }
            }
            return null;
        }
        
        private void ParseWithPattern(LogEvent logEvent, string line, string patternName)
        {
            var pattern = _logPatterns[patternName];
            var match = pattern.Match(line);
            
            if (!match.Success) return;
            
            // Extract fields based on pattern
            foreach (Group group in match.Groups)
            {
                if (group.Success && !string.IsNullOrEmpty(group.Name) && group.Name != "0")
                {
                    logEvent.Fields[group.Name] = group.Value;
                }
            }
            
            // Set common fields
            if (match.Groups["timestamp"].Success)
            {
                logEvent.Timestamp = ParseTimestamp(match.Groups["timestamp"].Value, GetTimestampFormats(patternName));
            }
            
            if (match.Groups["level"].Success)
            {
                logEvent.Level = match.Groups["level"].Value.ToUpperInvariant();
            }
            
            if (match.Groups["message"].Success)
            {
                logEvent.Message = match.Groups["message"].Value;
            }
            
            if (match.Groups["hostname"].Success)
            {
                logEvent.Source = match.Groups["hostname"].Value;
            }
            else if (match.Groups["ip"].Success)
            {
                logEvent.Source = match.Groups["ip"].Value;
            }
            
            // Add pattern information
            logEvent.Fields["pattern_matched"] = patternName;
        }
        
        private void ParseBasicLogLine(LogEvent logEvent, string line)
        {
            // Try to extract timestamp from the beginning of the line
            var timestampMatch = Regex.Match(line, @"^(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:\d{2})?)");
            if (timestampMatch.Success)
            {
                logEvent.Timestamp = ParseTimestamp(timestampMatch.Groups[1].Value);
                logEvent.Fields["extracted_timestamp"] = timestampMatch.Groups[1].Value;
            }
            
            // Try to extract log level
            logEvent.Level = ExtractLogLevel(line);
            
            // Use the entire line as message
            logEvent.Message = line;
            
            // Try to extract key-value pairs
            var fields = ExtractFields(line);
            foreach (var field in fields)
            {
                logEvent.Fields[field.Key] = field.Value;
            }
        }
        
        private string[] GetTimestampFormats(string patternName)
        {
            return patternName switch
            {
                "syslog" => new[] { "MMM dd HH:mm:ss", "MMM  d HH:mm:ss" },
                "apache_common" or "apache_combined" => new[] { "dd/MMM/yyyy:HH:mm:ss zzz" },
                "iis" => new[] { "yyyy-MM-dd HH:mm:ss" },
                _ => new[]
                {
                    "yyyy-MM-ddTHH:mm:ss.fffZ",
                    "yyyy-MM-ddTHH:mm:ssZ",
                    "yyyy-MM-ddTHH:mm:ss.fff",
                    "yyyy-MM-ddTHH:mm:ss",
                    "yyyy-MM-dd HH:mm:ss.fff",
                    "yyyy-MM-dd HH:mm:ss"
                }
            };
        }
        
        protected override Dictionary<string, object> GetParsingMetadata(string filePath, string content)
        {
            var metadata = base.GetParsingMetadata(filePath, content);
            
            try
            {
                var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                var patternMatches = new Dictionary<string, int>();
                
                foreach (var pattern in _logPatterns.Keys)
                {
                    patternMatches[pattern] = 0;
                }
                
                var validLines = 0;
                foreach (var line in lines.Take(100)) // Sample first 100 lines
                {
                    if (!IsValidLogLine(line)) continue;
                    
                    var matchedPattern = GetMatchingPattern(line);
                    if (matchedPattern != null)
                    {
                        patternMatches[matchedPattern]++;
                        validLines++;
                    }
                }
                
                metadata["total_lines"] = lines.Length;
                metadata["valid_lines"] = validLines;
                metadata["pattern_matches"] = patternMatches;
                metadata["primary_pattern"] = patternMatches.OrderByDescending(kvp => kvp.Value).FirstOrDefault().Key;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error extracting text log metadata");
            }
            
            return metadata;
        }
        
        protected override List<string> GetCapabilities()
        {
            var capabilities = base.GetCapabilities();
            capabilities.AddRange(new[] 
            { 
                "text_parsing", 
                "pattern_matching", 
                "syslog_parsing", 
                "apache_parsing", 
                "iis_parsing", 
                "generic_parsing",
                "timestamp_extraction",
                "level_extraction",
                "field_extraction"
            });
            return capabilities;
        }
    }
}