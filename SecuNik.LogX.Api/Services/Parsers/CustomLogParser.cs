using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using SecuNik.LogX.Core.Interfaces;
using Microsoft.Extensions.Logging;

namespace SecuNik.LogX.Api.Services.Parsers
{
    public class CustomLogParser : IParser
    {
        private readonly ILogger<CustomLogParser> _logger;

        public CustomLogParser(ILogger<CustomLogParser> logger)
        {
            _logger = logger;
        }

        public string Name => "Custom Log Parser";
        public string Description => "Parses custom application logs";
        public string Version => "1.0.0";
        public string[] SupportedExtensions => new[] { ".log", ".txt" };

        public async Task<bool> CanParseAsync(string filePath, string content)
        {
            try
            {
                // Check if content matches expected format
                return content.Contains("[INFO]") || content.Contains("[ERROR]") || content.Contains("[WARN]");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking if parser can parse file {FilePath}", filePath);
                return false;
            }
        }

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
                var lines = content.Split('\n');
                
                for (int i = 0; i < lines.Length; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    var line = lines[i].Trim();
                    if (string.IsNullOrEmpty(line)) continue;
                    
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
                            Source = "application"
                        };
                        
                        events.Add(logEvent);
                    }
                }
                
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

        public Dictionary<string, object> GetMetadata()
        {
            return new Dictionary<string, object>
            {
                ["name"] = Name,
                ["description"] = Description,
                ["version"] = Version,
                ["supported_extensions"] = SupportedExtensions,
                ["parser_type"] = "CustomLogParser",
                ["capabilities"] = new[] { "application_logs", "basic_parsing" }
            };
        }
    }
}