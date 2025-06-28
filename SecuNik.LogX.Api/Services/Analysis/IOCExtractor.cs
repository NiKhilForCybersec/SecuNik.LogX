using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Core.DTOs;
using System.Text.RegularExpressions;

namespace SecuNik.LogX.Api.Services.Analysis
{
    public class IOCExtractor
    {
        private readonly ILogger<IOCExtractor> _logger;
        
        // Regex patterns for different IOC types
        private static readonly Regex IpRegex = new Regex(@"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", RegexOptions.Compiled);
        private static readonly Regex DomainRegex = new Regex(@"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex UrlRegex = new Regex(@"\b(?:https?|ftp)://[-A-Z0-9+&@#/%?=~_|!:,.;]*[-A-Z0-9+&@#/%=~_|]\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex EmailRegex = new Regex(@"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex Md5Regex = new Regex(@"\b[A-F0-9]{32}\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex Sha1Regex = new Regex(@"\b[A-F0-9]{40}\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex Sha256Regex = new Regex(@"\b[A-F0-9]{64}\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex FilePathRegex = new Regex(@"\b(?:[A-Z]:\\(?:[^\\/:*?""<>|\r\n]+\\)*[^\\/:*?""<>|\r\n]*|/(?:[^/\\:*?""<>|\r\n]+/)*[^/\\:*?""<>|\r\n]*)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex RegistryKeyRegex = new Regex(@"\b(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_CLASSES_ROOT|HKCR|HKEY_USERS|HKU|HKEY_CURRENT_CONFIG|HKCC)\\[A-Z0-9\\]+\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        
        public IOCExtractor(ILogger<IOCExtractor> logger)
        {
            _logger = logger;
        }
        
        public async Task<List<IOCDto>> ExtractIOCsAsync(
            List<LogEvent> events, 
            string rawContent,
            CancellationToken cancellationToken = default)
        {
            var iocs = new List<IOCDto>();
            var uniqueIocs = new HashSet<string>();
            
            try
            {
                _logger.LogInformation("Starting IOC extraction from {EventCount} events", events.Count);
                
                // Extract from raw content first
                ExtractFromContent(rawContent, uniqueIocs, iocs);
                
                // Then extract from each event
                foreach (var logEvent in events)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    // Extract from raw data
                    if (!string.IsNullOrEmpty(logEvent.RawData))
                    {
                        ExtractFromContent(logEvent.RawData, uniqueIocs, iocs, logEvent);
                    }
                    
                    // Extract from message
                    if (!string.IsNullOrEmpty(logEvent.Message))
                    {
                        ExtractFromContent(logEvent.Message, uniqueIocs, iocs, logEvent);
                    }
                    
                    // Extract from fields
                    foreach (var field in logEvent.Fields)
                    {
                        if (field.Value != null && field.Value is string fieldValue)
                        {
                            ExtractFromContent(fieldValue, uniqueIocs, iocs, logEvent);
                        }
                    }
                }
                
                _logger.LogInformation("Extracted {IocCount} unique IOCs", iocs.Count);
                return iocs;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting IOCs");
                throw;
            }
        }
        
        private void ExtractFromContent(
            string content, 
            HashSet<string> uniqueIocs, 
            List<IOCDto> iocs, 
            LogEvent? sourceEvent = null)
        {
            // IP addresses
            foreach (Match match in IpRegex.Matches(content))
            {
                AddIOC(match.Value, "ip", uniqueIocs, iocs, content, sourceEvent);
            }
            
            // Domains
            foreach (Match match in DomainRegex.Matches(content))
            {
                // Skip common false positives
                var domain = match.Value.ToLower();
                if (!domain.Contains('.') || 
                    domain.EndsWith(".local") || 
                    domain.EndsWith(".internal") ||
                    domain.EndsWith(".lan") ||
                    domain.EndsWith(".example") ||
                    domain.EndsWith(".test") ||
                    domain.EndsWith(".invalid"))
                {
                    continue;
                }
                
                AddIOC(match.Value, "domain", uniqueIocs, iocs, content, sourceEvent);
            }
            
            // URLs
            foreach (Match match in UrlRegex.Matches(content))
            {
                AddIOC(match.Value, "url", uniqueIocs, iocs, content, sourceEvent);
            }
            
            // Email addresses
            foreach (Match match in EmailRegex.Matches(content))
            {
                AddIOC(match.Value, "email", uniqueIocs, iocs, content, sourceEvent);
            }
            
            // MD5 hashes
            foreach (Match match in Md5Regex.Matches(content))
            {
                AddIOC(match.Value, "hash", uniqueIocs, iocs, content, sourceEvent);
            }
            
            // SHA1 hashes
            foreach (Match match in Sha1Regex.Matches(content))
            {
                AddIOC(match.Value, "hash", uniqueIocs, iocs, content, sourceEvent);
            }
            
            // SHA256 hashes
            foreach (Match match in Sha256Regex.Matches(content))
            {
                AddIOC(match.Value, "hash", uniqueIocs, iocs, content, sourceEvent);
            }
            
            // File paths
            foreach (Match match in FilePathRegex.Matches(content))
            {
                AddIOC(match.Value, "file_path", uniqueIocs, iocs, content, sourceEvent);
            }
            
            // Registry keys
            foreach (Match match in RegistryKeyRegex.Matches(content))
            {
                AddIOC(match.Value, "registry_key", uniqueIocs, iocs, content, sourceEvent);
            }
        }
        
        private void AddIOC(
            string value, 
            string type, 
            HashSet<string> uniqueIocs, 
            List<IOCDto> iocs, 
            string sourceContent, 
            LogEvent? sourceEvent = null)
        {
            // Create a unique key for deduplication
            var key = $"{type}:{value}";
            
            if (uniqueIocs.Contains(key))
            {
                // Update existing IOC
                var existingIoc = iocs.FirstOrDefault(i => i.Type == type && i.Value == value);
                if (existingIoc != null)
                {
                    // Update first/last seen if we have a timestamp
                    if (sourceEvent?.Timestamp != null)
                    {
                        if (existingIoc.FirstSeen == null || sourceEvent.Timestamp < existingIoc.FirstSeen)
                        {
                            existingIoc.FirstSeen = sourceEvent.Timestamp;
                        }
                        
                        if (existingIoc.LastSeen == null || sourceEvent.Timestamp > existingIoc.LastSeen)
                        {
                            existingIoc.LastSeen = sourceEvent.Timestamp;
                        }
                    }
                }
                return;
            }
            
            // Add to unique set
            uniqueIocs.Add(key);
            
            // Extract context (text around the IOC)
            var context = ExtractContext(sourceContent, value);
            
            // Create new IOC
            var ioc = new IOCDto
            {
                Value = value,
                Type = type,
                Context = context,
                Source = sourceEvent?.Source ?? "content_analysis",
                Confidence = 100, // Default high confidence
                FirstSeen = sourceEvent?.Timestamp,
                LastSeen = sourceEvent?.Timestamp
            };
            
            iocs.Add(ioc);
        }
        
        private string ExtractContext(string content, string value)
        {
            try
            {
                var index = content.IndexOf(value);
                if (index < 0) return string.Empty;
                
                var startIndex = Math.Max(0, index - 50);
                var endIndex = Math.Min(content.Length, index + value.Length + 50);
                var length = endIndex - startIndex;
                
                var context = content.Substring(startIndex, length);
                
                // Add ellipsis if we truncated
                if (startIndex > 0) context = "..." + context;
                if (endIndex < content.Length) context = context + "...";
                
                return context;
            }
            catch
            {
                return string.Empty;
            }
        }
    }
}