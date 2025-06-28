using SecuNik.LogX.Core.Interfaces;
using System.Text.Json;
using System.Xml;

namespace SecuNik.LogX.Api.Services.Parsers
{
    public class WindowsEventLogParser : BaseParser
    {
        public override string Name => "Windows Event Log Parser";
        public override string Description => "Parses Windows Event Log files (EVTX/EVT) and XML event data";
        public override string Version => "1.0.0";
        public override string[] SupportedExtensions => new[] { ".evtx", ".evt", ".xml" };
        
        public WindowsEventLogParser(ILogger<WindowsEventLogParser> logger) : base(logger)
        {
        }
        
        protected override async Task<bool> CanParseContentAsync(string content)
        {
            try
            {
                // Check for Windows Event Log XML format
                if (content.TrimStart().StartsWith("<Event") || content.Contains("<Event xmlns="))
                {
                    return true;
                }
                
                // Check for exported event log format
                if (content.Contains("Event ID") && content.Contains("Source") && content.Contains("Log Name"))
                {
                    return true;
                }
                
                // Check for CSV export format from Event Viewer
                if (content.Contains("Level,Date and Time,Source,Event ID,Task Category"))
                {
                    return true;
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }
        
        protected override async Task<List<LogEvent>> ParseContentAsync(string filePath, string content, CancellationToken cancellationToken)
        {
            var events = new List<LogEvent>();
            
            try
            {
                var trimmedContent = content.Trim();
                
                if (trimmedContent.StartsWith("<Event") || content.Contains("<Event xmlns="))
                {
                    // Parse XML format
                    events.AddRange(await ParseXmlEventsAsync(content, cancellationToken));
                }
                else if (content.Contains("Event ID") && content.Contains("Source"))
                {
                    // Parse text export format
                    events.AddRange(await ParseTextExportAsync(content, cancellationToken));
                }
                else if (content.Contains("Level,Date and Time,Source,Event ID"))
                {
                    // Parse CSV export format
                    events.AddRange(await ParseCsvExportAsync(content, cancellationToken));
                }
                
                _logger.LogInformation("Parsed {EventCount} Windows Event Log events from {FilePath}", 
                    events.Count, filePath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing Windows Event Log content from {FilePath}", filePath);
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
                
                if (trimmedContent.StartsWith("<Event") || content.Contains("<Event xmlns="))
                {
                    // Validate XML format
                    try
                    {
                        var doc = new XmlDocument();
                        doc.LoadXml(content);
                        
                        var eventNodes = doc.SelectNodes("//Event");
                        if (eventNodes?.Count == 0)
                        {
                            result.Warnings.Add("No Event nodes found in XML");
                        }
                    }
                    catch (XmlException ex)
                    {
                        result.IsValid = false;
                        result.Errors.Add($"Invalid XML format: {ex.Message}");
                    }
                }
                else if (content.Contains("Event ID") && content.Contains("Source"))
                {
                    // Validate text export format
                    var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    if (lines.Length < 5)
                    {
                        result.Warnings.Add("Text export appears to have very few events");
                    }
                }
                else if (content.Contains("Level,Date and Time,Source,Event ID"))
                {
                    // Validate CSV export format
                    var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    if (lines.Length < 2)
                    {
                        result.IsValid = false;
                        result.Errors.Add("CSV export must have at least header and one data row");
                    }
                }
                else
                {
                    result.IsValid = false;
                    result.Errors.Add("Content does not appear to be a valid Windows Event Log format");
                }
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.Errors.Add($"Validation error: {ex.Message}");
            }
            
            return await Task.FromResult(result);
        }
        
        private async Task<List<LogEvent>> ParseXmlEventsAsync(string content, CancellationToken cancellationToken)
        {
            var events = new List<LogEvent>();
            
            try
            {
                var doc = new XmlDocument();
                doc.LoadXml(content);
                
                var eventNodes = doc.SelectNodes("//Event");
                if (eventNodes == null) return events;
                
                for (int i = 0; i < eventNodes.Count; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    var eventNode = eventNodes[i];
                    var logEvent = await ParseXmlEventNodeAsync(eventNode, i + 1);
                    if (logEvent != null)
                    {
                        events.Add(logEvent);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing XML events");
                throw;
            }
            
            return events;
        }
        
        private async Task<LogEvent?> ParseXmlEventNodeAsync(XmlNode eventNode, int index)
        {
            try
            {
                var logEvent = new LogEvent
                {
                    LineNumber = index,
                    RawData = eventNode.OuterXml
                };
                
                // Extract System information
                var systemNode = eventNode.SelectSingleNode("System");
                if (systemNode != null)
                {
                    var eventIdNode = systemNode.SelectSingleNode("EventID");
                    if (eventIdNode != null)
                    {
                        logEvent.Fields["EventID"] = eventIdNode.InnerText;
                    }
                    
                    var levelNode = systemNode.SelectSingleNode("Level");
                    if (levelNode != null)
                    {
                        var levelValue = levelNode.InnerText;
                        logEvent.Level = MapEventLevel(levelValue);
                        logEvent.Fields["Level"] = levelValue;
                    }
                    
                    var timeCreatedNode = systemNode.SelectSingleNode("TimeCreated");
                    if (timeCreatedNode?.Attributes?["SystemTime"] != null)
                    {
                        var timeStr = timeCreatedNode.Attributes["SystemTime"].Value;
                        logEvent.Timestamp = ParseTimestamp(timeStr);
                        logEvent.Fields["TimeCreated"] = timeStr;
                    }
                    
                    var providerNode = systemNode.SelectSingleNode("Provider");
                    if (providerNode?.Attributes?["Name"] != null)
                    {
                        logEvent.Source = providerNode.Attributes["Name"].Value;
                        logEvent.Fields["Provider"] = logEvent.Source;
                    }
                    
                    var computerNode = systemNode.SelectSingleNode("Computer");
                    if (computerNode != null)
                    {
                        logEvent.Fields["Computer"] = computerNode.InnerText;
                    }
                    
                    var channelNode = systemNode.SelectSingleNode("Channel");
                    if (channelNode != null)
                    {
                        logEvent.Fields["Channel"] = channelNode.InnerText;
                    }
                }
                
                // Extract EventData
                var eventDataNode = eventNode.SelectSingleNode("EventData");
                if (eventDataNode != null)
                {
                    var dataNodes = eventDataNode.SelectNodes("Data");
                    if (dataNodes != null)
                    {
                        foreach (XmlNode dataNode in dataNodes)
                        {
                            var name = dataNode.Attributes?["Name"]?.Value ?? $"Data{dataNodes.Count}";
                            logEvent.Fields[name] = dataNode.InnerText;
                        }
                    }
                }
                
                // Extract UserData
                var userDataNode = eventNode.SelectSingleNode("UserData");
                if (userDataNode != null)
                {
                    logEvent.Fields["UserData"] = userDataNode.InnerXml;
                }
                
                // Create message from available data
                logEvent.Message = CreateEventMessage(logEvent.Fields);
                
                return await Task.FromResult(logEvent);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error parsing XML event node at index {Index}", index);
                return null;
            }
        }
        
        private async Task<List<LogEvent>> ParseTextExportAsync(string content, CancellationToken cancellationToken)
        {
            var events = new List<LogEvent>();
            var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            
            var currentEvent = new Dictionary<string, string>();
            var lineNumber = 0;
            
            foreach (var line in lines)
            {
                cancellationToken.ThrowIfCancellationRequested();
                lineNumber++;
                
                var trimmedLine = line.Trim();
                if (string.IsNullOrEmpty(trimmedLine)) continue;
                
                // Check if this is a new event (starts with "Event Type:" or similar)
                if (trimmedLine.StartsWith("Event Type:") || trimmedLine.StartsWith("Log Name:"))
                {
                    // Process previous event if exists
                    if (currentEvent.Count > 0)
                    {
                        var logEvent = CreateLogEventFromTextExport(currentEvent, events.Count + 1);
                        if (logEvent != null)
                        {
                            events.Add(logEvent);
                        }
                        currentEvent.Clear();
                    }
                }
                
                // Parse key-value pairs
                var colonIndex = trimmedLine.IndexOf(':');
                if (colonIndex > 0 && colonIndex < trimmedLine.Length - 1)
                {
                    var key = trimmedLine.Substring(0, colonIndex).Trim();
                    var value = trimmedLine.Substring(colonIndex + 1).Trim();
                    currentEvent[key] = value;
                }
            }
            
            // Process the last event
            if (currentEvent.Count > 0)
            {
                var logEvent = CreateLogEventFromTextExport(currentEvent, events.Count + 1);
                if (logEvent != null)
                {
                    events.Add(logEvent);
                }
            }
            
            return events;
        }
        
        private async Task<List<LogEvent>> ParseCsvExportAsync(string content, CancellationToken cancellationToken)
        {
            var events = new List<LogEvent>();
            var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            
            if (lines.Length < 2) return events;
            
            var headers = lines[0].Split(',');
            
            for (int i = 1; i < lines.Length; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                var values = ParseCsvLine(lines[i]);
                if (values.Length != headers.Length) continue;
                
                var logEvent = new LogEvent
                {
                    LineNumber = i + 1,
                    RawData = lines[i]
                };
                
                for (int j = 0; j < headers.Length && j < values.Length; j++)
                {
                    var header = headers[j].Trim().Trim('"');
                    var value = values[j].Trim().Trim('"');
                    logEvent.Fields[header] = value;
                    
                    // Map common fields
                    switch (header.ToLowerInvariant())
                    {
                        case "level":
                            logEvent.Level = MapEventLevel(value);
                            break;
                        case "date and time":
                        case "datetime":
                            logEvent.Timestamp = ParseTimestamp(value);
                            break;
                        case "source":
                            logEvent.Source = value;
                            break;
                        case "event id":
                            logEvent.Fields["EventID"] = value;
                            break;
                    }
                }
                
                logEvent.Message = CreateEventMessage(logEvent.Fields);
                events.Add(logEvent);
            }
            
            return events;
        }
        
        private LogEvent? CreateLogEventFromTextExport(Dictionary<string, string> eventData, int lineNumber)
        {
            try
            {
                var logEvent = new LogEvent
                {
                    LineNumber = lineNumber,
                    RawData = string.Join(Environment.NewLine, eventData.Select(kvp => $"{kvp.Key}: {kvp.Value}"))
                };
                
                foreach (var kvp in eventData)
                {
                    logEvent.Fields[kvp.Key] = kvp.Value;
                    
                    // Map common fields
                    switch (kvp.Key.ToLowerInvariant())
                    {
                        case "event type":
                        case "level":
                            logEvent.Level = MapEventLevel(kvp.Value);
                            break;
                        case "date":
                        case "time generated":
                            logEvent.Timestamp = ParseTimestamp(kvp.Value);
                            break;
                        case "source":
                            logEvent.Source = kvp.Value;
                            break;
                    }
                }
                
                logEvent.Message = CreateEventMessage(logEvent.Fields);
                return logEvent;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error creating log event from text export");
                return null;
            }
        }
        
        private string MapEventLevel(string level)
        {
            return level.ToLowerInvariant() switch
            {
                "0" or "information" => "INFO",
                "1" or "critical" => "CRITICAL",
                "2" or "error" => "ERROR",
                "3" or "warning" => "WARN",
                "4" or "information" => "INFO",
                "5" or "verbose" => "DEBUG",
                _ => level.ToUpperInvariant()
            };
        }
        
        private string CreateEventMessage(Dictionary<string, object> fields)
        {
            var messageParts = new List<string>();
            
            if (fields.ContainsKey("EventID"))
            {
                messageParts.Add($"Event ID: {fields["EventID"]}");
            }
            
            if (fields.ContainsKey("Provider"))
            {
                messageParts.Add($"Source: {fields["Provider"]}");
            }
            
            if (fields.ContainsKey("Description"))
            {
                messageParts.Add($"Description: {fields["Description"]}");
            }
            
            return messageParts.Count > 0 ? string.Join(" | ", messageParts) : "Windows Event";
        }
        
        private string[] ParseCsvLine(string line)
        {
            var values = new List<string>();
            var current = new System.Text.StringBuilder();
            var inQuotes = false;
            
            for (int i = 0; i < line.Length; i++)
            {
                var c = line[i];
                
                if (c == '"')
                {
                    inQuotes = !inQuotes;
                }
                else if (c == ',' && !inQuotes)
                {
                    values.Add(current.ToString());
                    current.Clear();
                }
                else
                {
                    current.Append(c);
                }
            }
            
            values.Add(current.ToString());
            return values.ToArray();
        }
        
        protected override List<string> GetCapabilities()
        {
            var capabilities = base.GetCapabilities();
            capabilities.AddRange(new[] 
            { 
                "windows_event_parsing", 
                "xml_parsing", 
                "csv_parsing", 
                "text_export_parsing",
                "event_id_extraction",
                "provider_extraction",
                "system_data_extraction"
            });
            return capabilities;
        }
    }
}