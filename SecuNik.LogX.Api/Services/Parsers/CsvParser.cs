using SecuNik.LogX.Core.Interfaces;
using CsvHelper;
using CsvHelper.Configuration;
using System.Globalization;
using System.Text;

namespace SecuNik.LogX.Api.Services.Parsers
{
    public class CsvParser : BaseParser
    {
        public override string Name => "CSV Parser";
        public override string Description => "Parses comma-separated value files and tab-separated files";
        public override string Version => "1.0.0";
        public override string[] SupportedExtensions => new[] { ".csv", ".tsv", ".tab" };
        
        public CsvParser(ILogger<CsvParser> logger) : base(logger)
        {
        }
        
        protected override async Task<bool> CanParseContentAsync(string content)
        {
            try
            {
                var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                if (lines.Length < 2) return false; // Need at least header and one data row
                
                var firstLine = lines[0].Trim();
                
                // Check for common CSV patterns
                var hasCommas = firstLine.Contains(',');
                var hasTabs = firstLine.Contains('\t');
                var hasSemicolons = firstLine.Contains(';');
                
                if (!hasCommas && !hasTabs && !hasSemicolons)
                    return false;
                
                // Try to parse the first few lines to validate CSV structure
                var delimiter = DetermineDelimiter(firstLine);
                var config = new CsvConfiguration(CultureInfo.InvariantCulture)
                {
                    Delimiter = delimiter,
                    HasHeaderRecord = true,
                    BadDataFound = null, // Ignore bad data for validation
                    MissingFieldFound = null // Ignore missing fields for validation
                };
                
                using var reader = new StringReader(string.Join('\n', lines.Take(5)));
                using var csv = new CsvReader(reader, config);
                
                try
                {
                    csv.Read();
                    csv.ReadHeader();
                    return csv.HeaderRecord?.Length > 0;
                }
                catch
                {
                    return false;
                }
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
                var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                if (lines.Length < 2)
                {
                    _logger.LogWarning("CSV file {FilePath} has insufficient data (less than 2 lines)", filePath);
                    return events;
                }
                
                var delimiter = DetermineDelimiter(lines[0]);
                var config = new CsvConfiguration(CultureInfo.InvariantCulture)
                {
                    Delimiter = delimiter,
                    HasHeaderRecord = true,
                    BadDataFound = args => _logger.LogWarning("Bad CSV data at row {RowNumber}: {RawRecord}", 
                        args.Context.Parser.Row, args.RawRecord),
                    MissingFieldFound = null // Allow missing fields
                };
                
                using var reader = new StringReader(content);
                using var csv = new CsvReader(reader, config);
                
                // Read header
                csv.Read();
                csv.ReadHeader();
                var headers = csv.HeaderRecord;
                
                if (headers == null || headers.Length == 0)
                {
                    throw new InvalidOperationException("No headers found in CSV file");
                }
                
                _logger.LogInformation("CSV headers: {Headers}", string.Join(", ", headers));
                
                var rowNumber = 1; // Start from 1 since header is row 0
                
                while (csv.Read())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    try
                    {
                        var logEvent = await ParseCsvRowAsync(csv, headers, rowNumber);
                        if (logEvent != null)
                        {
                            events.Add(logEvent);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error parsing CSV row {RowNumber}", rowNumber);
                        // Continue with next row
                    }
                    
                    rowNumber++;
                }
                
                _logger.LogInformation("Parsed {EventCount} CSV events from {FilePath}", events.Count, filePath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing CSV content from {FilePath}", filePath);
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
                
                if (lines.Length < 2)
                {
                    result.IsValid = false;
                    result.Errors.Add("CSV file must have at least a header row and one data row");
                    return result;
                }
                
                var delimiter = DetermineDelimiter(lines[0]);
                var config = new CsvConfiguration(CultureInfo.InvariantCulture)
                {
                    Delimiter = delimiter,
                    HasHeaderRecord = true,
                    BadDataFound = args => result.Warnings.Add($"Bad data at row {args.Context.Parser.Row}: {args.RawRecord}"),
                    MissingFieldFound = null
                };
                
                using var reader = new StringReader(content);
                using var csv = new CsvReader(reader, config);
                
                // Validate header
                csv.Read();
                csv.ReadHeader();
                var headers = csv.HeaderRecord;
                
                if (headers == null || headers.Length == 0)
                {
                    result.IsValid = false;
                    result.Errors.Add("No valid headers found");
                    return result;
                }
                
                // Check for duplicate headers
                var duplicateHeaders = headers.GroupBy(h => h).Where(g => g.Count() > 1).Select(g => g.Key);
                foreach (var duplicate in duplicateHeaders)
                {
                    result.Warnings.Add($"Duplicate header found: {duplicate}");
                }
                
                // Validate data rows
                var rowNumber = 1;
                var headerCount = headers.Length;
                
                while (csv.Read())
                {
                    try
                    {
                        var fieldCount = csv.Parser.Count;
                        if (fieldCount != headerCount)
                        {
                            result.Warnings.Add($"Row {rowNumber} has {fieldCount} fields but expected {headerCount}");
                        }
                    }
                    catch (Exception ex)
                    {
                        result.Warnings.Add($"Error validating row {rowNumber}: {ex.Message}");
                    }
                    
                    rowNumber++;
                }
                
                if (result.Errors.Count > 0)
                {
                    result.IsValid = false;
                }
                
                result.Suggestions["total_rows"] = rowNumber - 1;
                result.Suggestions["header_count"] = headerCount;
                result.Suggestions["delimiter"] = delimiter;
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.Errors.Add($"CSV validation error: {ex.Message}");
            }
            
            return await Task.FromResult(result);
        }
        
        private async Task<LogEvent?> ParseCsvRowAsync(CsvReader csv, string[] headers, int rowNumber)
        {
            try
            {
                var logEvent = new LogEvent
                {
                    LineNumber = rowNumber + 1, // +1 because header is row 0
                    RawData = csv.Parser.RawRecord
                };
                
                // Extract all fields
                for (int i = 0; i < headers.Length; i++)
                {
                    var header = headers[i];
                    var value = csv.GetField(i);
                    
                    if (!string.IsNullOrEmpty(value))
                    {
                        logEvent.Fields[header] = value;
                    }
                }
                
                // Try to extract common log fields
                ExtractCommonFields(logEvent, headers);
                
                return await Task.FromResult(logEvent);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error parsing CSV row {RowNumber}", rowNumber);
                return null;
            }
        }
        
        private void ExtractCommonFields(LogEvent logEvent, string[] headers)
        {
            // Try to identify timestamp field
            var timestampFields = new[] { "timestamp", "time", "datetime", "date", "created", "occurred" };
            var timestampField = headers.FirstOrDefault(h => 
                timestampFields.Any(tf => h.ToLowerInvariant().Contains(tf)));
            
            if (timestampField != null && logEvent.Fields.ContainsKey(timestampField))
            {
                var timestampValue = logEvent.Fields[timestampField]?.ToString();
                if (!string.IsNullOrEmpty(timestampValue))
                {
                    logEvent.Timestamp = ParseTimestamp(timestampValue);
                }
            }
            else
            {
                logEvent.Timestamp = DateTime.UtcNow;
            }
            
            // Try to identify level field
            var levelFields = new[] { "level", "severity", "priority", "type", "category" };
            var levelField = headers.FirstOrDefault(h => 
                levelFields.Any(lf => h.ToLowerInvariant().Contains(lf)));
            
            if (levelField != null && logEvent.Fields.ContainsKey(levelField))
            {
                logEvent.Level = logEvent.Fields[levelField]?.ToString() ?? "INFO";
            }
            else
            {
                logEvent.Level = "INFO";
            }
            
            // Try to identify message field
            var messageFields = new[] { "message", "msg", "description", "text", "content", "details" };
            var messageField = headers.FirstOrDefault(h => 
                messageFields.Any(mf => h.ToLowerInvariant().Contains(mf)));
            
            if (messageField != null && logEvent.Fields.ContainsKey(messageField))
            {
                logEvent.Message = logEvent.Fields[messageField]?.ToString() ?? string.Empty;
            }
            else
            {
                // Use the raw data as message if no specific message field found
                logEvent.Message = logEvent.RawData;
            }
            
            // Try to identify source field
            var sourceFields = new[] { "source", "host", "hostname", "server", "application", "service" };
            var sourceField = headers.FirstOrDefault(h => 
                sourceFields.Any(sf => h.ToLowerInvariant().Contains(sf)));
            
            if (sourceField != null && logEvent.Fields.ContainsKey(sourceField))
            {
                logEvent.Source = logEvent.Fields[sourceField]?.ToString() ?? string.Empty;
            }
        }
        
        private string DetermineDelimiter(string firstLine)
        {
            var delimiters = new[] { ",", "\t", ";", "|" };
            var delimiterCounts = delimiters.ToDictionary(d => d, d => firstLine.Count(c => c.ToString() == d));
            
            // Return the delimiter with the highest count
            var bestDelimiter = delimiterCounts.OrderByDescending(kvp => kvp.Value).First();
            
            // Default to comma if no clear winner
            return bestDelimiter.Value > 0 ? bestDelimiter.Key : ",";
        }
        
        protected override Dictionary<string, object> GetParsingMetadata(string filePath, string content)
        {
            var metadata = base.GetParsingMetadata(filePath, content);
            
            try
            {
                var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                if (lines.Length > 0)
                {
                    var delimiter = DetermineDelimiter(lines[0]);
                    metadata["delimiter"] = delimiter;
                    metadata["total_lines"] = lines.Length;
                    
                    if (lines.Length > 1)
                    {
                        var headerCount = lines[0].Split(delimiter).Length;
                        metadata["column_count"] = headerCount;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error extracting CSV metadata");
            }
            
            return metadata;
        }
        
        protected override List<string> GetCapabilities()
        {
            var capabilities = base.GetCapabilities();
            capabilities.AddRange(new[] { "csv_parsing", "tsv_parsing", "structured_data", "field_mapping", "delimiter_detection" });
            return capabilities;
        }
    }
}