using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using SecuNik.LogX.Core.Interfaces;
using Microsoft.Extensions.Logging;

namespace SecuNik.LogX.Api.Services.Parsers
{
    public class SyslogParser : BaseParser
    {
        public override string Name => "Syslog Parser";
        public override string Description => "Parses standard syslog format logs";
        public override string Version => "1.0.0";
        public override string[] SupportedExtensions => new[] { ".log", ".syslog" };
        
        private readonly Regex _rfc3164Regex = new Regex(
            @"^(?<pri><\d+>)?(?<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?<hostname>\S+)\s+(?<process>\S+?)(?:\[(?<pid>\d+)\])?\s*:\s*(?<message>.*)$",
            RegexOptions.Compiled);
            
        private readonly Regex _rfc5424Regex = new Regex(
            @"^(?<pri><\d+>)(?<version>\d+)\s+(?<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+(?<hostname>\S+)\s+(?<app>\S+)\s+(?<procid>\S+)\s+(?<msgid>\S+)\s+(?<sd>-|\[.*\])\s+(?<message>.*)$",
            RegexOptions.Compiled);
        
        public SyslogParser(ILogger<SyslogParser> logger) : base(logger)
        {
        }
        
        protected override async Task<bool> CanParseContentAsync(string content)
        {
            try
            {
                var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                if (lines.Length == 0) return false;
                
                // Check first few lines
                var linesToCheck = Math.Min(5, lines.Length);
                var matchCount = 0;
                
                for (int i = 0; i < linesToCheck; i++)
                {
                    var line = lines[i].Trim();
                    if (_rfc3164Regex.IsMatch(line) || _rfc5424Regex.IsMatch(line))
                    {
                        matchCount++;
                    }
                }
                
                // If at least 60% of checked lines match, consider it parseable
                return matchCount >= linesToCheck * 0.6;
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
                    if (string.IsNullOrEmpty(line)) continue;
                    
                    var logEvent = ParseSyslogLine(line, i + 1);
                    if (logEvent != null)
                    {
                        events.Add(logEvent);
                    }
                }
                
                _logger.LogInformation("Parsed {EventCount} syslog events from {FilePath}", events.Count, filePath);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Parsing cancelled for {FilePath}", filePath);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing syslog content from {FilePath}", filePath);
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
                
                int rfc3164Count = 0;
                int rfc5424Count = 0;
                int invalidCount = 0;
                
                foreach (var line in lines)
                {
                    var trimmedLine = line.Trim();
                    if (string.IsNullOrEmpty(trimmedLine)) continue;
                    
                    if (_rfc3164Regex.IsMatch(trimmedLine))
                    {
                        rfc3164Count++;
                    }
                    else if (_rfc5424Regex.IsMatch(trimmedLine))
                    {
                        rfc5424Count++;
                    }
                    else
                    {
                        invalidCount++;
                    }
                }
                
                int totalLines = rfc3164Count + rfc5424Count + invalidCount;
                double validPercentage = totalLines > 0 ? (double)(rfc3164Count + rfc5424Count) / totalLines * 100 : 0;
                
                if (validPercentage < 50)
                {
                    result.IsValid = false;
                    result.Errors.Add($"Only {validPercentage:F1}% of lines match syslog format");
                }
                else if (validPercentage < 80)
                {
                    result.Warnings.Add($"Only {validPercentage:F1}% of lines match syslog format");
                }
                
                result.Suggestions["rfc3164_count"] = rfc3164Count;
                result.Suggestions["rfc5424_count"] = rfc5424Count;
                result.Suggestions["invalid_count"] = invalidCount;
                result.Suggestions["valid_percentage"] = validPercentage;
                
                if (rfc3164Count > 0 && rfc5424Count > 0)
                {
                    result.Warnings.Add("Mixed syslog formats detected (RFC3164 and RFC5424)");
                }
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.Errors.Add($"Validation error: {ex.Message}");
            }
            
            return result;
        }
        
        private LogEvent ParseSyslogLine(string line, int lineNumber)
        {
            try
            {
                // Try RFC3164 format first (older BSD-style syslog)
                var match3164 = _rfc3164Regex.Match(line);
                if (match3164.Success)
                {
                    return ParseRfc3164(match3164, line, lineNumber);
                }
                
                // Try RFC5424 format (newer structured syslog)
                var match5424 = _rfc5424Regex.Match(line);
                if (match5424.Success)
                {
                    return ParseRfc5424(match5424, line, lineNumber);
                }
                
                // If no match, try basic parsing
                return ParseBasicSyslog(line, lineNumber);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error parsing syslog line {LineNumber}: {Line}", lineNumber, line);
                return null;
            }
        }
        
        private LogEvent ParseRfc3164(Match match, string line, int lineNumber)
        {
            var logEvent = new LogEvent
            {
                LineNumber = lineNumber,
                RawData = line,
                Source = match.Groups["hostname"].Value
            };
            
            // Parse timestamp
            var timestampStr = match.Groups["timestamp"].Value;
            logEvent.Timestamp = ParseSyslogTimestamp(timestampStr);
            
            // Extract process and PID
            var process = match.Groups["process"].Value;
            var pid = match.Groups["pid"].Success ? match.Groups["pid"].Value : null;
            
            // Extract message
            logEvent.Message = match.Groups["message"].Value;
            
            // Extract severity/level from message or use default
            logEvent.Level = ExtractLogLevel(logEvent.Message);
            
            // Add fields
            logEvent.Fields["hostname"] = match.Groups["hostname"].Value;
            logEvent.Fields["process"] = process;
            if (pid != null) logEvent.Fields["pid"] = pid;
            
            // Parse priority if present
            if (match.Groups["pri"].Success)
            {
                var priStr = match.Groups["pri"].Value.Trim('<', '>');
                if (int.TryParse(priStr, out int pri))
                {
                    int facility = pri / 8;
                    int severity = pri % 8;
                    
                    logEvent.Fields["priority"] = pri;
                    logEvent.Fields["facility"] = facility;
                    logEvent.Fields["severity_code"] = severity;
                    
                    // Override level based on syslog severity
                    logEvent.Level = GetSyslogSeverityName(severity);
                }
            }
            
            return logEvent;
        }
        
        private LogEvent ParseRfc5424(Match match, string line, int lineNumber)
        {
            var logEvent = new LogEvent
            {
                LineNumber = lineNumber,
                RawData = line,
                Source = match.Groups["hostname"].Value
            };
            
            // Parse timestamp
            var timestampStr = match.Groups["timestamp"].Value;
            logEvent.Timestamp = DateTime.Parse(timestampStr);
            
            // Extract app and procid
            var app = match.Groups["app"].Value;
            var procid = match.Groups["procid"].Value;
            var msgid = match.Groups["msgid"].Value;
            
            // Extract message
            logEvent.Message = match.Groups["message"].Value;
            
            // Extract severity/level from message or use default
            logEvent.Level = ExtractLogLevel(logEvent.Message);
            
            // Add fields
            logEvent.Fields["hostname"] = match.Groups["hostname"].Value;
            logEvent.Fields["app"] = app;
            logEvent.Fields["procid"] = procid;
            logEvent.Fields["msgid"] = msgid;
            
            // Parse structured data if present
            var sd = match.Groups["sd"].Value;
            if (sd != "-")
            {
                logEvent.Fields["structured_data"] = sd;
                // In a real implementation, we would parse the structured data elements
            }
            
            // Parse priority if present
            if (match.Groups["pri"].Success)
            {
                var priStr = match.Groups["pri"].Value.Trim('<', '>');
                if (int.TryParse(priStr, out int pri))
                {
                    int facility = pri / 8;
                    int severity = pri % 8;
                    
                    logEvent.Fields["priority"] = pri;
                    logEvent.Fields["facility"] = facility;
                    logEvent.Fields["severity_code"] = severity;
                    
                    // Override level based on syslog severity
                    logEvent.Level = GetSyslogSeverityName(severity);
                }
            }
            
            return logEvent;
        }
        
        private LogEvent ParseBasicSyslog(string line, int lineNumber)
        {
            // Basic fallback parsing for syslog-like lines
            var logEvent = new LogEvent
            {
                LineNumber = lineNumber,
                RawData = line,
                Timestamp = DateTime.UtcNow, // Default timestamp
                Level = ExtractLogLevel(line),
                Message = line
            };
            
            // Try to extract timestamp from beginning of line
            var timestampMatch = Regex.Match(line, @"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})");
            if (timestampMatch.Success)
            {
                logEvent.Timestamp = ParseSyslogTimestamp(timestampMatch.Groups[1].Value);
                logEvent.Message = line.Substring(timestampMatch.Length).Trim();
            }
            
            // Try to extract hostname
            var parts = logEvent.Message.Split(new[] { ' ' }, 2);
            if (parts.Length == 2 && !string.IsNullOrEmpty(parts[0]))
            {
                logEvent.Source = parts[0];
                logEvent.Message = parts[1];
                logEvent.Fields["hostname"] = parts[0];
            }
            
            return logEvent;
        }
        
        private DateTime ParseSyslogTimestamp(string timestamp)
        {
            try
            {
                // Add current year since syslog timestamps often omit the year
                var currentYear = DateTime.UtcNow.Year;
                var withYear = $"{timestamp} {currentYear}";
                
                return DateTime.ParseExact(withYear, "MMM d HH:mm:ss yyyy", System.Globalization.CultureInfo.InvariantCulture);
            }
            catch
            {
                return DateTime.UtcNow;
            }
        }
        
        private string GetSyslogSeverityName(int severity)
        {
            return severity switch
            {
                0 => "EMERGENCY",
                1 => "ALERT",
                2 => "CRITICAL",
                3 => "ERROR",
                4 => "WARNING",
                5 => "NOTICE",
                6 => "INFO",
                7 => "DEBUG",
                _ => "INFO"
            };
        }
        
        protected override Dictionary<string, object> GetParsingMetadata(string filePath, string content)
        {
            var metadata = base.GetParsingMetadata(filePath, content);
            
            try
            {
                var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                
                int rfc3164Count = 0;
                int rfc5424Count = 0;
                
                foreach (var line in lines.Take(100)) // Sample first 100 lines
                {
                    if (_rfc3164Regex.IsMatch(line)) rfc3164Count++;
                    else if (_rfc5424Regex.IsMatch(line)) rfc5424Count++;
                }
                
                metadata["rfc3164_count"] = rfc3164Count;
                metadata["rfc5424_count"] = rfc5424Count;
                metadata["format"] = rfc3164Count >= rfc5424Count ? "RFC3164" : "RFC5424";
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error extracting syslog metadata");
            }
            
            return metadata;
        }
        
        protected override List<string> GetCapabilities()
        {
            var capabilities = base.GetCapabilities();
            capabilities.AddRange(new[] 
            { 
                "syslog_parsing", 
                "rfc3164_parsing", 
                "rfc5424_parsing", 
                "priority_extraction",
                "facility_extraction"
            });
            return capabilities;
        }
    }
}