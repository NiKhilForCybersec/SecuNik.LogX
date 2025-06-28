using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using SecuNik.LogX.Core.Interfaces;
using Microsoft.Extensions.Logging;

namespace SecuNik.LogX.Api.Services.Parsers
{
    /// <summary>
    /// Template for creating custom parsers
    /// This is a reference implementation that can be used as a starting point
    /// </summary>
    public class CustomParserTemplate : IParser
    {
        private readonly ILogger<CustomParserTemplate> _logger;
        
        // Constructor with logger dependency injection
        public CustomParserTemplate(ILogger<CustomParserTemplate> logger)
        {
            _logger = logger;
        }
        
        // Required interface properties
        public string Name => "Custom Parser Template";
        public string Description => "Template for creating custom parsers";
        public string Version => "1.0.0";
        public string[] SupportedExtensions => new[] { ".log", ".txt" };
        
        // Implement CanParseAsync to determine if this parser can handle the content
        public async Task<bool> CanParseAsync(string filePath, string content)
        {
            try
            {
                // Check if content matches expected format
                // This is where you would add your custom logic to detect if this parser can handle the content
                
                // Example: Check if content contains specific markers
                bool containsMarkers = content.Contains("[INFO]") || 
                                      content.Contains("[ERROR]") || 
                                      content.Contains("[WARN]");
                
                return containsMarkers;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking if parser can parse file {FilePath}", filePath);
                return false;
            }
        }
        
        // Implement ParseAsync to parse the content into log events
        public async Task<ParseResult> ParseAsync(string filePath, string content, CancellationToken cancellationToken = default)
        {
            var events = new List<LogEvent>();
            var result = new ParseResult
            {
                Success = false,
                Events = events,
                ParserUsed = Name
            };
            
            try
            {
                // Split content into lines
                var lines = content.Split('\n');
                
                // Process each line
                for (int i = 0; i < lines.Length; i++)
                {
                    // Check for cancellation
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    var line = lines[i].Trim();
                    if (string.IsNullOrEmpty(line)) continue;
                    
                    // Parse line into log event
                    // This is where you would add your custom parsing logic
                    
                    // Example: Parse log line with regex
                    var match = Regex.Match(line, @"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (.+)");
                    
                    if (match.Success)
                    {
                        var logEvent = new LogEvent
                        {
                            Timestamp = DateTime.Parse(match.Groups[1].Value),
                            Level = match.Groups[2].Value,
                            Message = match.Groups[3].Value,
                            RawData = line,
                            LineNumber = i + 1,
                            Source = "custom_parser"
                        };
                        
                        // Add any additional fields
                        logEvent.Fields["parser"] = Name;
                        logEvent.Fields["file"] = Path.GetFileName(filePath);
                        
                        events.Add(logEvent);
                    }
                }
                
                // Set success and metadata
                result.Success = true;
                result.EventsCount = events.Count;
                result.Metadata = new Dictionary<string, object>
                {
                    ["file_path"] = filePath,
                    ["file_size"] = content.Length,
                    ["parser_name"] = Name,
                    ["parser_version"] = Version,
                    ["parsed_at"] = DateTime.UtcNow,
                    ["events_count"] = events.Count
                };
                
                _logger.LogInformation("Successfully parsed {EventCount} events from {FilePath}", events.Count, filePath);
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Parsing was cancelled for {FilePath}", filePath);
                result.ErrorMessage = "Parsing was cancelled";
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing file {FilePath}", filePath);
                result.ErrorMessage = ex.Message;
            }
            
            return result;
        }
        
        // Implement ValidateAsync to validate the content
        public async Task<ValidationResult> ValidateAsync(string content)
        {
            var result = new ValidationResult { IsValid = true };
            
            try
            {
                if (string.IsNullOrEmpty(content))
                {
                    result.IsValid = false;
                    result.Errors.Add("Content is empty");
                    return result;
                }
                
                // Validate content format
                // This is where you would add your custom validation logic
                
                // Example: Check if content contains expected log format
                var lines = content.Split('\n');
                int validLines = 0;
                int totalLines = 0;
                
                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    totalLines++;
                    
                    var match = Regex.Match(line, @"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (.+)");
                    if (match.Success)
                    {
                        validLines++;
                    }
                }
                
                if (totalLines == 0)
                {
                    result.IsValid = false;
                    result.Errors.Add("No valid content found");
                    return result;
                }
                
                double validPercentage = (double)validLines / totalLines * 100;
                if (validPercentage < 50)
                {
                    result.IsValid = false;
                    result.Errors.Add($"Only {validPercentage:F1}% of lines match expected format");
                }
                else if (validPercentage < 80)
                {
                    result.Warnings.Add($"Only {validPercentage:F1}% of lines match expected format");
                }
                
                result.Suggestions["valid_lines_percentage"] = validPercentage;
                result.Suggestions["valid_lines"] = validLines;
                result.Suggestions["total_lines"] = totalLines;
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.Errors.Add($"Validation error: {ex.Message}");
            }
            
            return result;
        }
        
        // Implement GetMetadata to provide information about the parser
        public Dictionary<string, object> GetMetadata()
        {
            return new Dictionary<string, object>
            {
                ["name"] = Name,
                ["description"] = Description,
                ["version"] = Version,
                ["supported_extensions"] = SupportedExtensions,
                ["parser_type"] = "CustomParserTemplate",
                ["capabilities"] = new[] { "custom_logs", "basic_parsing" }
            };
        }
    }
}