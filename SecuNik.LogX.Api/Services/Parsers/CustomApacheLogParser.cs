using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using SecuNik.LogX.Core.Interfaces;
using Microsoft.Extensions.Logging;

namespace SecuNik.LogX.Api.Services.Parsers
{
    public class CustomApacheLogParser : IParser
    {
        private readonly ILogger<CustomApacheLogParser> _logger;

        public CustomApacheLogParser(ILogger<CustomApacheLogParser> logger)
        {
            _logger = logger;
        }

        public string Name => "Apache Access Log Parser";
        public string Description => "Parses Apache/Nginx access logs";
        public string Version => "1.0.0";
        public string[] SupportedExtensions => new[] { ".log", ".access" };

        public async Task<bool> CanParseAsync(string filePath, string content)
        {
            try {
                // Check for common Apache log patterns
                var pattern = @"\d+\.\d+\.\d+\.\d+.*\[.*\].*HTTP";
                return Regex.IsMatch(content, pattern);
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
                
                // Apache combined log format regex
                var regex = new Regex(@"^(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] ""(\S+) (\S+) (\S+)"" (\d{3}) (\d+|-) ""([^""]*)"" ""([^""]*)""");
                
                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    var match = regex.Match(line);
                    if (match.Success)
                    {
                        var logEvent = new LogEvent
                        {
                            Timestamp = ParseApacheDate(match.Groups[2].Value),
                            Source = match.Groups[1].Value, // IP address
                            Level = GetLogLevel(match.Groups[6].Value), // HTTP status
                            Message = $"{match.Groups[3].Value} {match.Groups[4].Value}",
                            RawData = line,
                            Fields = new Dictionary<string, object>
                            {
                                ["ip"] = match.Groups[1].Value,
                                ["method"] = match.Groups[3].Value,
                                ["url"] = match.Groups[4].Value,
                                ["protocol"] = match.Groups[5].Value,
                                ["status"] = match.Groups[6].Value,
                                ["size"] = match.Groups[7].Value,
                                ["referrer"] = match.Groups[8].Value,
                                ["user_agent"] = match.Groups[9].Value
                            }
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
                var regex = new Regex(@"^(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] ""(\S+) (\S+) (\S+)"" (\d{3}) (\d+|-) ""([^""]*)"" ""([^""]*)""");
                
                int validLines = 0;
                int totalLines = 0;
                
                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    totalLines++;
                    
                    if (regex.IsMatch(line))
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
                    result.Errors.Add($"Only {validPercentage:F1}% of lines match Apache log format");
                }
                else if (validPercentage < 80)
                {
                    result.Warnings.Add($"Only {validPercentage:F1}% of lines match Apache log format");
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
                ["parser_type"] = "CustomApacheLogParser",
                ["capabilities"] = new[] { "apache_logs", "nginx_logs", "web_server_logs" }
            };
        }

        private DateTime ParseApacheDate(string dateStr)
        {
            // Parse Apache date format: 10/Oct/2000:13:55:36 -0700
            try
            {
                return DateTime.ParseExact(dateStr, "dd/MMM/yyyy:HH:mm:ss zzz", System.Globalization.CultureInfo.InvariantCulture);
            }
            catch
            {
                return DateTime.UtcNow;
            }
        }

        private string GetLogLevel(string statusCode)
        {
            return statusCode.StartsWith("2") ? "INFO" :
                   statusCode.StartsWith("3") ? "INFO" :
                   statusCode.StartsWith("4") ? "WARN" :
                   statusCode.StartsWith("5") ? "ERROR" : "INFO";
        }
    }
}