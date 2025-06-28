using SecuNik.LogX.Core.Interfaces;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SecuNik.LogX.Api.Services.Parsers
{
    public class JsonParser : BaseParser
    {
        public override string Name => "JSON Log Parser";
        public override string Description => "Parses structured JSON log files including JSONL format";
        public override string Version => "1.0.0";
        public override string[] SupportedExtensions => new[] { ".json", ".jsonl", ".ndjson" };
        
        private readonly JsonSerializerOptions _jsonOptions;
        
        public JsonParser(ILogger<JsonParser> logger) : base(logger)
        {
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                AllowTrailingCommas = true,
                ReadCommentHandling = JsonCommentHandling.Skip
            };
        }
        
        protected override async Task<bool> CanParseContentAsync(string content)
        {
            try
            {
                var trimmedContent = content.Trim();
                
                // Check for JSON array format
                if (trimmedContent.StartsWith("[") && trimmedContent.EndsWith("]"))
                {
                    return await Task.FromResult(true);
                }
                
                // Check for JSONL format (each line is a JSON object)
                var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                if (lines.Length > 0)
                {
                    var firstLine = lines[0].Trim();
                    if (firstLine.StartsWith("{") && firstLine.EndsWith("}"))
                    {
                        try
                        {
                            JsonDocument.Parse(firstLine);
                            return await Task.FromResult(true);
                        }
                        catch
                        {
                            // Not valid JSON
                        }
                    }
                }
                
                // Check for single JSON object
                if (trimmedContent.StartsWith("{") && trimmedContent.EndsWith("}"))
                {
                    try
                    {
                        JsonDocument.Parse(trimmedContent);
                        return await Task.FromResult(true);
                    }
                    catch
                    {
                        // Not valid JSON
                    }
                }
                
                return await Task.FromResult(false);
            }
            catch
            {
                return await Task.FromResult(false);
            }
        }
        
        protected override async Task<List<LogEvent>> ParseContentAsync(string filePath, string content, CancellationToken cancellationToken)
        {
            var events = new List<LogEvent>();
            var trimmedContent = content.Trim();
            
            try
            {
                // Handle JSON array format
                if (trimmedContent.StartsWith("[") && trimmedContent.EndsWith("]"))
                {
                    events.AddRange(await ParseJsonArrayAsync(trimmedContent, cancellationToken));
                }
                // Handle JSONL format (each line is a JSON object)
                else if (IsJsonLinesFormat(content))
                {
                    events.AddRange(await ParseJsonLinesAsync(content, cancellationToken));
                }
                // Handle single JSON object
                else if (trimmedContent.StartsWith("{") && trimmedContent.EndsWith("}"))
                {
                    var logEvent = await ParseSingleJsonObjectAsync(trimmedContent, 0);
                    if (logEvent != null)
                    {
                        events.Add(logEvent);
                    }
                }
                
                _logger.LogInformation("Parsed {EventCount} JSON events from {FilePath}", events.Count, filePath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing JSON content from {FilePath}", filePath);
                throw;
            }
            
            return events;
        }
        
        protected override async Task<ValidationResult> ValidateContentAsync(string content)
        {
            var result = new ValidationResult { IsValid = true };
            
            try
            {
                var trimmedContent = content.Trim();
                
                if (trimmedContent.StartsWith("[") && trimmedContent.EndsWith("]"))
                {
                    // Validate JSON array
                    JsonDocument.Parse(trimmedContent);
                }
                else if (IsJsonLinesFormat(content))
                {
                    // Validate JSONL format
                    var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    var lineNumber = 0;
                    
                    foreach (var line in lines)
                    {
                        lineNumber++;
                        var trimmedLine = line.Trim();
                        
                        if (string.IsNullOrEmpty(trimmedLine))
                            continue;
                        
                        try
                        {
                            JsonDocument.Parse(trimmedLine);
                        }
                        catch (JsonException ex)
                        {
                            result.Errors.Add($"Invalid JSON on line {lineNumber}: {ex.Message}");
                        }
                    }
                }
                else if (trimmedContent.StartsWith("{") && trimmedContent.EndsWith("}"))
                {
                    // Validate single JSON object
                    JsonDocument.Parse(trimmedContent);
                }
                else
                {
                    result.IsValid = false;
                    result.Errors.Add("Content does not appear to be valid JSON format");
                }
                
                if (result.Errors.Count > 0)
                {
                    result.IsValid = false;
                }
            }
            catch (JsonException ex)
            {
                result.IsValid = false;
                result.Errors.Add($"JSON validation error: {ex.Message}");
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.Errors.Add($"Validation error: {ex.Message}");
            }
            
            return await Task.FromResult(result);
        }
        
        private async Task<List<LogEvent>> ParseJsonArrayAsync(string content, CancellationToken cancellationToken)
        {
            var events = new List<LogEvent>();
            
            using var document = JsonDocument.Parse(content);
            var array = document.RootElement;
            
            if (array.ValueKind != JsonValueKind.Array)
            {
                throw new InvalidOperationException("Expected JSON array");
            }
            
            var index = 0;
            foreach (var element in array.EnumerateArray())
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                var logEvent = await ParseJsonElementAsync(element, index);
                if (logEvent != null)
                {
                    events.Add(logEvent);
                }
                index++;
            }
            
            return events;
        }
        
        private async Task<List<LogEvent>> ParseJsonLinesAsync(string content, CancellationToken cancellationToken)
        {
            var events = new List<LogEvent>();
            var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            
            for (int i = 0; i < lines.Length; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                var line = lines[i].Trim();
                if (string.IsNullOrEmpty(line))
                    continue;
                
                var logEvent = await ParseSingleJsonObjectAsync(line, i + 1);
                if (logEvent != null)
                {
                    events.Add(logEvent);
                }
            }
            
            return events;
        }
        
        private async Task<LogEvent?> ParseSingleJsonObjectAsync(string jsonString, int lineNumber)
        {
            try
            {
                using var document = JsonDocument.Parse(jsonString);
                return await ParseJsonElementAsync(document.RootElement, lineNumber);
            }
            catch (JsonException ex)
            {
                _logger.LogWarning("Failed to parse JSON on line {LineNumber}: {Error}", lineNumber, ex.Message);
                return null;
            }
        }
        
        private async Task<LogEvent?> ParseJsonElementAsync(JsonElement element, int index)
        {
            try
            {
                var logEvent = new LogEvent
                {
                    LineNumber = index + 1,
                    RawData = element.GetRawText()
                };
                
                // Extract common fields
                if (element.TryGetProperty("timestamp", out var timestampProp) ||
                    element.TryGetProperty("time", out timestampProp) ||
                    element.TryGetProperty("@timestamp", out timestampProp))
                {
                    logEvent.Timestamp = ParseTimestampFromJson(timestampProp);
                }
                else
                {
                    logEvent.Timestamp = DateTime.UtcNow;
                }
                
                if (element.TryGetProperty("level", out var levelProp) ||
                    element.TryGetProperty("severity", out levelProp) ||
                    element.TryGetProperty("loglevel", out levelProp))
                {
                    logEvent.Level = levelProp.GetString() ?? "INFO";
                }
                else
                {
                    logEvent.Level = "INFO";
                }
                
                if (element.TryGetProperty("message", out var messageProp) ||
                    element.TryGetProperty("msg", out messageProp) ||
                    element.TryGetProperty("text", out messageProp))
                {
                    logEvent.Message = messageProp.GetString() ?? string.Empty;
                }
                else
                {
                    logEvent.Message = element.GetRawText();
                }
                
                if (element.TryGetProperty("source", out var sourceProp) ||
                    element.TryGetProperty("logger", out sourceProp) ||
                    element.TryGetProperty("component", out sourceProp))
                {
                    logEvent.Source = sourceProp.GetString() ?? string.Empty;
                }
                
                // Extract all properties as fields
                foreach (var property in element.EnumerateObject())
                {
                    logEvent.Fields[property.Name] = ExtractJsonValue(property.Value);
                }
                
                return await Task.FromResult(logEvent);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to parse JSON element at index {Index}", index);
                return null;
            }
        }
        
        private DateTime ParseTimestampFromJson(JsonElement timestampElement)
        {
            try
            {
                switch (timestampElement.ValueKind)
                {
                    case JsonValueKind.String:
                        var timestampStr = timestampElement.GetString();
                        return ParseTimestamp(timestampStr, new[]
                        {
                            "yyyy-MM-ddTHH:mm:ss.fffZ",
                            "yyyy-MM-ddTHH:mm:ssZ",
                            "yyyy-MM-ddTHH:mm:ss.fff",
                            "yyyy-MM-ddTHH:mm:ss",
                            "yyyy-MM-dd HH:mm:ss.fff",
                            "yyyy-MM-dd HH:mm:ss"
                        });
                        
                    case JsonValueKind.Number:
                        // Unix timestamp
                        var unixTimestamp = timestampElement.GetInt64();
                        return DateTimeOffset.FromUnixTimeSeconds(unixTimestamp).UtcDateTime;
                        
                    default:
                        return DateTime.UtcNow;
                }
            }
            catch
            {
                return DateTime.UtcNow;
            }
        }
        
        private object ExtractJsonValue(JsonElement element)
        {
            return element.ValueKind switch
            {
                JsonValueKind.String => element.GetString() ?? string.Empty,
                JsonValueKind.Number => element.TryGetInt64(out var longVal) ? longVal : element.GetDouble(),
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                JsonValueKind.Null => null,
                JsonValueKind.Array => element.EnumerateArray().Select(ExtractJsonValue).ToArray(),
                JsonValueKind.Object => element.EnumerateObject().ToDictionary(p => p.Name, p => ExtractJsonValue(p.Value)),
                _ => element.GetRawText()
            };
        }
        
        private bool IsJsonLinesFormat(string content)
        {
            var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            if (lines.Length == 0) return false;
            
            // Check first few lines to determine if it's JSONL format
            var linesToCheck = Math.Min(5, lines.Length);
            var validJsonLines = 0;
            
            for (int i = 0; i < linesToCheck; i++)
            {
                var line = lines[i].Trim();
                if (string.IsNullOrEmpty(line)) continue;
                
                if (line.StartsWith("{") && line.EndsWith("}"))
                {
                    try
                    {
                        JsonDocument.Parse(line);
                        validJsonLines++;
                    }
                    catch
                    {
                        // Not valid JSON
                    }
                }
            }
            
            return validJsonLines > 0 && validJsonLines >= linesToCheck * 0.8; // At least 80% valid JSON lines
        }
        
        protected override List<string> GetCapabilities()
        {
            var capabilities = base.GetCapabilities();
            capabilities.AddRange(new[] { "json_parsing", "jsonl_parsing", "structured_data", "field_extraction" });
            return capabilities;
        }
    }
}