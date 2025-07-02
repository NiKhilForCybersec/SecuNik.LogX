using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using SecuNik.LogX.Domain.Entities;

namespace SecuNik.LogX.API.Services
{
    public class IOCExtractor
    {
        private readonly ILogger<IOCExtractor> _logger;
        private readonly IConfiguration _configuration;
        private readonly Dictionary<string, Regex> _patterns;
        private readonly HashSet<string> _whitelistedDomains;
        private readonly HashSet<string> _commonFalsePositives;
        private readonly int _minConfidenceThreshold;

        public IOCExtractor(ILogger<IOCExtractor> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
            _minConfidenceThreshold = configuration.GetValue<int>("IOCExtractor:MinConfidenceThreshold", 30);
            
            _patterns = InitializePatterns();
            _whitelistedDomains = InitializeWhitelist();
            _commonFalsePositives = InitializeFalsePositives();
        }

        public async Task<List<IOC>> ExtractIOCsAsync(string content, Guid analysisId, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(content))
                return new List<IOC>();

            var iocs = new List<IOC>();
            var uniqueIOCs = new HashSet<string>();

            // Extract different types of IOCs in parallel
            var extractionTasks = new[]
            {
                Task.Run(() => ExtractIPAddresses(content, analysisId, uniqueIOCs)),
                Task.Run(() => ExtractDomains(content, analysisId, uniqueIOCs)),
                Task.Run(() => ExtractURLs(content, analysisId, uniqueIOCs)),
                Task.Run(() => ExtractHashes(content, analysisId, uniqueIOCs)),
                Task.Run(() => ExtractEmails(content, analysisId, uniqueIOCs)),
                Task.Run(() => ExtractFilePaths(content, analysisId, uniqueIOCs)),
                Task.Run(() => ExtractRegistryKeys(content, analysisId, uniqueIOCs)),
                Task.Run(() => ExtractNetworkArtifacts(content, analysisId, uniqueIOCs)),
                Task.Run(() => ExtractCryptocurrencyAddresses(content, analysisId, uniqueIOCs))
            };

            var results = await Task.WhenAll(extractionTasks);
            
            foreach (var result in results)
            {
                iocs.AddRange(result);
            }

            // Validate and enrich IOCs
            foreach (var ioc in iocs)
            {
                await ValidateAndEnrichIOCAsync(ioc, content);
            }

            // Filter out low confidence IOCs
            iocs = iocs.Where(i => i.Confidence >= _minConfidenceThreshold).ToList();

            _logger.LogInformation("Extracted {Count} IOCs from analysis {AnalysisId}", iocs.Count, analysisId);
            
            return iocs;
        }

        public async Task<bool> ValidateIOCAsync(IOC ioc, CancellationToken cancellationToken = default)
        {
            switch (ioc.Type.ToLower())
            {
                case "ipv4":
                    return ValidateIPv4(ioc.Value);
                case "ipv6":
                    return ValidateIPv6(ioc.Value);
                case "domain":
                    return ValidateDomain(ioc.Value);
                case "url":
                    return ValidateURL(ioc.Value);
                case "md5":
                    return ValidateMD5(ioc.Value);
                case "sha1":
                    return ValidateSHA1(ioc.Value);
                case "sha256":
                    return ValidateSHA256(ioc.Value);
                case "sha512":
                    return ValidateSHA512(ioc.Value);
                case "email":
                    return ValidateEmail(ioc.Value);
                case "file_path":
                    return ValidateFilePath(ioc.Value);
                case "registry_key":
                    return ValidateRegistryKey(ioc.Value);
                case "bitcoin_address":
                    return ValidateBitcoinAddress(ioc.Value);
                case "ethereum_address":
                    return ValidateEthereumAddress(ioc.Value);
                default:
                    return true;
            }
        }

        private Dictionary<string, Regex> InitializePatterns()
        {
            return new Dictionary<string, Regex>
            {
                // IP Addresses
                ["IPv4"] = new Regex(@"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", RegexOptions.Compiled),
                ["IPv6"] = new Regex(@"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b|\b[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b", RegexOptions.Compiled),
                
                // Domain Names
                ["Domain"] = new Regex(@"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b", RegexOptions.Compiled),
                
                // URLs
                ["URL"] = new Regex(@"(?:https?|ftp|ftps)://(?:[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%])+", RegexOptions.Compiled),
                
                // File Hashes
                ["MD5"] = new Regex(@"\b[a-fA-F0-9]{32}\b", RegexOptions.Compiled),
                ["SHA1"] = new Regex(@"\b[a-fA-F0-9]{40}\b", RegexOptions.Compiled),
                ["SHA256"] = new Regex(@"\b[a-fA-F0-9]{64}\b", RegexOptions.Compiled),
                ["SHA512"] = new Regex(@"\b[a-fA-F0-9]{128}\b", RegexOptions.Compiled),
                
                // Email Addresses
                ["Email"] = new Regex(@"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", RegexOptions.Compiled),
                
                // File Paths
                ["WindowsPath"] = new Regex(@"[a-zA-Z]:\\(?:[^\\/:*?""<>|\r\n]+\\)*[^\\/:*?""<>|\r\n]*", RegexOptions.Compiled),
                ["UnixPath"] = new Regex(@"(?:/[^/\0]+)+/?", RegexOptions.Compiled),
                
                // Registry Keys
                ["RegistryKey"] = new Regex(@"(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)(?:\\[^\\]+)*", RegexOptions.Compiled),
                
                // Network Ports
                ["Port"] = new Regex(@"\b(?:port\s*[:\s]?\s*)?([1-9][0-9]{0,4})\b", RegexOptions.Compiled | RegexOptions.IgnoreCase),
                
                // Cryptocurrency Addresses
                ["BitcoinAddress"] = new Regex(@"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-z0-9]{39,59}", RegexOptions.Compiled),
                ["EthereumAddress"] = new Regex(@"\b0x[a-fA-F0-9]{40}\b", RegexOptions.Compiled),
                
                // CVE IDs
                ["CVE"] = new Regex(@"\bCVE-\d{4}-\d{4,}\b", RegexOptions.Compiled),
                
                // User Agents
                ["UserAgent"] = new Regex(@"User-Agent:\s*([^\r\n]+)", RegexOptions.Compiled | RegexOptions.IgnoreCase),
                
                // Base64 Encoded Content (minimum 20 chars)
                ["Base64"] = new Regex(@"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", RegexOptions.Compiled)
            };
        }

        private HashSet<string> InitializeWhitelist()
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                // Common legitimate domains
                "microsoft.com", "windows.com", "apple.com", "google.com", "googleapis.com",
                "amazon.com", "amazonaws.com", "cloudflare.com", "akamai.com", "azure.com",
                "github.com", "stackoverflow.com", "wikipedia.org", "w3.org", "mozilla.org",
                
                // Common internal domains
                "localhost", "local", "internal", "corp", "lan",
                
                // Common file extensions that appear as domains
                "exe", "dll", "sys", "dat", "log", "txt", "tmp"
            };
        }

        private HashSet<string> InitializeFalsePositives()
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                // Common false positive IPs
                "0.0.0.0", "127.0.0.1", "255.255.255.255", "10.0.0.0", "192.168.0.0",
                "::1", "::", "ff02::1", "ff02::2",
                
                // Version numbers that look like IPs
                "1.0.0.0", "2.0.0.0", "1.1.1.1",
                
                // Common hash-like strings that aren't IOCs
                "00000000000000000000000000000000", // 32 zeros (MD5)
                "0000000000000000000000000000000000000000", // 40 zeros (SHA1)
                "da39a3ee5e6b4b0d3255bfef95601890afd80709", // SHA1 of empty string
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // SHA256 of empty string
            };
        }

        private async Task<List<IOC>> ExtractIPAddresses(string content, Guid analysisId, HashSet<string> uniqueIOCs)
        {
            var iocs = new List<IOC>();
            
            // Extract IPv4 addresses
            var ipv4Matches = _patterns["IPv4"].Matches(content);
            foreach (Match match in ipv4Matches)
            {
                var ip = match.Value;
                if (!uniqueIOCs.Contains(ip) && !_commonFalsePositives.Contains(ip))
                {
                    uniqueIOCs.Add(ip);
                    
                    var ioc = new IOC
                    {
                        Id = Guid.NewGuid(),
                        AnalysisId = analysisId,
                        Type = "IPv4",
                        Value = ip,
                        Confidence = CalculateIPConfidence(ip, content),
                        Context = ExtractContext(content, match.Index, 50),
                        FirstSeen = DateTime.UtcNow,
                        LastSeen = DateTime.UtcNow,
                        CreatedAt = DateTime.UtcNow
                    };
                    
                    if (IsPrivateIP(ip))
                    {
                        ioc.Confidence = Math.Min(ioc.Confidence, 40);
                        ioc.Tags = new List<string> { "internal", "private_ip" };
                    }
                    
                    iocs.Add(ioc);
                }
            }
            
            // Extract IPv6 addresses
            var ipv6Matches = _patterns["IPv6"].Matches(content);
            foreach (Match match in ipv6Matches)
            {
                var ip = match.Value;
                if (!uniqueIOCs.Contains(ip) && !_commonFalsePositives.Contains(ip))
                {
                    uniqueIOCs.Add(ip);
                    
                    iocs.Add(new IOC
                    {
                        Id = Guid.NewGuid(),
                        AnalysisId = analysisId,
                        Type = "IPv6",
                        Value = ip,
                        Confidence = CalculateIPConfidence(ip, content),
                        Context = ExtractContext(content, match.Index, 50),
                        FirstSeen = DateTime.UtcNow,
                        LastSeen = DateTime.UtcNow,
                        CreatedAt = DateTime.UtcNow
                    });
                }
            }
            
            return iocs;
        }

        private async Task<List<IOC>> ExtractDomains(string content, Guid analysisId, HashSet<string> uniqueIOCs)
        {
            var iocs = new List<IOC>();
            var domainMatches = _patterns["Domain"].Matches(content);
            
            foreach (Match match in domainMatches)
            {
                var domain = match.Value.ToLower();
                
                // Skip if already processed or whitelisted
                if (uniqueIOCs.Contains(domain) || IsWhitelistedDomain(domain))
                    continue;
                
                // Skip if it's actually an IP address
                if (_patterns["IPv4"].IsMatch(domain))
                    continue;
                
                // Skip common file extensions
                var parts = domain.Split('.');
                if (parts.Length == 2 && _whitelistedDomains.Contains(parts[1]))
                    continue;
                
                uniqueIOCs.Add(domain);
                
                var ioc = new IOC
                {
                    Id = Guid.NewGuid(),
                    AnalysisId = analysisId,
                    Type = "Domain",
                    Value = domain,
                    Confidence = CalculateDomainConfidence(domain, content),
                    Context = ExtractContext(content, match.Index, 50),
                    FirstSeen = DateTime.UtcNow,
                    LastSeen = DateTime.UtcNow,
                    CreatedAt = DateTime.UtcNow
                };
                
                // Check for suspicious patterns
                if (IsSuspiciousDomain(domain))
                {
                    ioc.Confidence = Math.Min(100, ioc.Confidence + 20);
                    ioc.Tags = new List<string> { "suspicious" };
                }
                
                iocs.Add(ioc);
            }
            
            return iocs;
        }

        private async Task<List<IOC>> ExtractURLs(string content, Guid analysisId, HashSet<string> uniqueIOCs)
        {
            var iocs = new List<IOC>();
            var urlMatches = _patterns["URL"].Matches(content);
            
            foreach (Match match in urlMatches)
            {
                var url = match.Value;
                
                if (uniqueIOCs.Contains(url))
                    continue;
                
                uniqueIOCs.Add(url);
                
                try
                {
                    var uri = new Uri(url);
                    var domain = uri.Host.ToLower();
                    
                    if (IsWhitelistedDomain(domain))
                        continue;
                    
                    var ioc = new IOC
                    {
                        Id = Guid.NewGuid(),
                        AnalysisId = analysisId,
                        Type = "URL",
                        Value = url,
                        Confidence = CalculateURLConfidence(url, content),
                        Context = ExtractContext(content, match.Index, 50),
                        FirstSeen = DateTime.UtcNow,
                        LastSeen = DateTime.UtcNow,
                        CreatedAt = DateTime.UtcNow
                    };
                    
                    // Check for suspicious URL patterns
                    if (IsSuspiciousURL(url))
                    {
                        ioc.Confidence = Math.Min(100, ioc.Confidence + 25);
                        ioc.Tags = new List<string> { "suspicious_url" };
                    }
                    
                    iocs.Add(ioc);
                }
                catch (UriFormatException)
                {
                    // Invalid URL, skip
                }
            }
            
            return iocs;
        }

        private async Task<List<IOC>> ExtractHashes(string content, Guid analysisId, HashSet<string> uniqueIOCs)
        {
            var iocs = new List<IOC>();
            
            // Extract different hash types
            var hashTypes = new[] { "MD5", "SHA1", "SHA256", "SHA512" };
            
            foreach (var hashType in hashTypes)
            {
                var matches = _patterns[hashType].Matches(content);
                
                foreach (Match match in matches)
                {
                    var hash = match.Value.ToLower();
                    
                    if (uniqueIOCs.Contains(hash) || _commonFalsePositives.Contains(hash))
                        continue;
                    
                    // Validate hash format
                    if (!IsValidHash(hash, hashType))
                        continue;
                    
                    uniqueIOCs.Add(hash);
                    
                    var ioc = new IOC
                    {
                        Id = Guid.NewGuid(),
                        AnalysisId = analysisId,
                        Type = hashType,
                        Value = hash,
                        Confidence = CalculateHashConfidence(hash, hashType, content),
                        Context = ExtractContext(content, match.Index, 50),
                        FirstSeen = DateTime.UtcNow,
                        LastSeen = DateTime.UtcNow,
                        CreatedAt = DateTime.UtcNow
                    };
                    
                    iocs.Add(ioc);
                }
            }
            
            return iocs;
        }

        private async Task<List<IOC>> ExtractEmails(string content, Guid analysisId, HashSet<string> uniqueIOCs)
        {
            var iocs = new List<IOC>();
            var emailMatches = _patterns["Email"].Matches(content);
            
            foreach (Match match in emailMatches)
            {
                var email = match.Value.ToLower();
                
                if (uniqueIOCs.Contains(email))
                    continue;
                
                var domain = email.Split('@')[1];
                if (IsWhitelistedDomain(domain))
                    continue;
                
                uniqueIOCs.Add(email);
                
                var ioc = new IOC
                {
                    Id = Guid.NewGuid(),
                    AnalysisId = analysisId,
                    Type = "Email",
                    Value = email,
                    Confidence = CalculateEmailConfidence(email, content),
                    Context = ExtractContext(content, match.Index, 50),
                    FirstSeen = DateTime.UtcNow,
                    LastSeen = DateTime.UtcNow,
                    CreatedAt = DateTime.UtcNow
                };
                
                if (IsSuspiciousEmail(email))
                {
                    ioc.Confidence = Math.Min(100, ioc.Confidence + 15);
                    ioc.Tags = new List<string> { "suspicious_email" };
                }
                
                iocs.Add(ioc);
            }
            
            return iocs;
        }

        private async Task<List<IOC>> ExtractFilePaths(string content, Guid analysisId, HashSet<string> uniqueIOCs)
        {
            var iocs = new List<IOC>();
            
            // Windows paths
            var windowsMatches = _patterns["WindowsPath"].Matches(content);
            foreach (Match match in windowsMatches)
            {
                var path = match.Value;
                if (!uniqueIOCs.Contains(path) && IsSuspiciousFilePath(path))
                {
                    uniqueIOCs.Add(path);
                    
                    iocs.Add(new IOC
                    {
                        Id = Guid.NewGuid(),
                        AnalysisId = analysisId,
                        Type = "File_Path",
                        Value = path,
                        Confidence = CalculateFilePathConfidence(path, content),
                        Context = ExtractContext(content, match.Index, 50),
                        FirstSeen = DateTime.UtcNow,
                        LastSeen = DateTime.UtcNow,
                        CreatedAt = DateTime.UtcNow,
                        Tags = new List<string> { "windows_path" }
                    });
                }
            }
            
            // Unix paths
            var unixMatches = _patterns["UnixPath"].Matches(content);
            foreach (Match match in unixMatches)
            {
                var path = match.Value;
                if (!uniqueIOCs.Contains(path) && IsSuspiciousFilePath(path) && path.Length > 5)
                {
                    uniqueIOCs.Add(path);
                    
                    iocs.Add(new IOC
                    {
                        Id = Guid.NewGuid(),
                        AnalysisId = analysisId,
                        Type = "File_Path",
                        Value = path,
                        Confidence = CalculateFilePathConfidence(path, content),
                        Context = ExtractContext(content, match.Index, 50),
                        FirstSeen = DateTime.UtcNow,
                        LastSeen = DateTime.UtcNow,
                        CreatedAt = DateTime.UtcNow,
                        Tags = new List<string> { "unix_path" }
                    });
                }
            }
            
            return iocs;
        }

        private async Task<List<IOC>> ExtractRegistryKeys(string content, Guid analysisId, HashSet<string> uniqueIOCs)
        {
            var iocs = new List<IOC>();
            var registryMatches = _patterns["RegistryKey"].Matches(content);
            
            foreach (Match match in registryMatches)
            {
                var key = match.Value;
                if (!uniqueIOCs.Contains(key))
                {
                    uniqueIOCs.Add(key);
                    
                    var ioc = new IOC
                    {
                        Id = Guid.NewGuid(),
                        AnalysisId = analysisId,
                        Type = "Registry_Key",
                        Value = key,
                        Confidence = CalculateRegistryKeyConfidence(key, content),
                        Context = ExtractContext(content, match.Index, 50),
                        FirstSeen = DateTime.UtcNow,
                        LastSeen = DateTime.UtcNow,
                        CreatedAt = DateTime.UtcNow
                    };
                    
                    if (IsSuspiciousRegistryKey(key))
                    {
                        ioc.Confidence = Math.Min(100, ioc.Confidence + 20);
                        ioc.Tags = new List<string> { "suspicious_registry" };
                    }
                    
                    iocs.Add(ioc);
                }
            }
            
            return iocs;
        }

        private async Task<List<IOC>> ExtractNetworkArtifacts(string content, Guid analysisId, HashSet<string> uniqueIOCs)
        {
            var iocs = new List<IOC>();
            
            // Extract port numbers
            var portMatches = _patterns["Port"].Matches(content);
            foreach (Match match in portMatches)
            {
                if (int.TryParse(match.Groups[1].Value, out var port) && port > 0 && port <= 65535)
                {
                    var portStr = port.ToString();
                    if (!uniqueIOCs.Contains($"port:{portStr}") && IsInterestingPort(port))
                    {
                        uniqueIOCs.Add($"port:{portStr}");
                        
                        iocs.Add(new IOC
                        {
                            Id = Guid.NewGuid(),
                            AnalysisId = analysisId,
                            Type = "Network_Port",
                            Value = portStr,
                            Confidence = CalculatePortConfidence(port, content),
                            Context = ExtractContext(content, match.Index, 50),
                            FirstSeen = DateTime.UtcNow,
                            LastSeen = DateTime.UtcNow,
                            CreatedAt = DateTime.UtcNow,
                            Tags = GetPortTags(port)
                        });
                    }
                }
            }
            
            // Extract CVE IDs
            var cveMatches = _patterns["CVE"].Matches(content);
            foreach (Match match in cveMatches)
            {
                var cve = match.Value;
                if (!uniqueIOCs.Contains(cve))
                {
                    uniqueIOCs.Add(cve);
                    
                    iocs.Add(new IOC
                    {
                        Id = Guid.NewGuid(),
                        AnalysisId = analysisId,
                        Type = "CVE",
                        Value = cve,
                        Confidence = 95, // CVEs are highly specific
                        Context = ExtractContext(content, match.Index, 50),
                        FirstSeen = DateTime.UtcNow,
                        LastSeen = DateTime.UtcNow,
                        CreatedAt = DateTime.UtcNow,
                        Tags = new List<string> { "vulnerability" }
                    });
                }
            }
            
            return iocs;
        }

        private async Task<List<IOC>> ExtractCryptocurrencyAddresses(string content, Guid analysisId, HashSet<string> uniqueIOCs)
        {
            var iocs = new List<IOC>();
            
            // Bitcoin addresses
            var btcMatches = _patterns["BitcoinAddress"].Matches(content);
            foreach (Match match in btcMatches)
            {
                var address = match.Value;
                if (!uniqueIOCs.Contains(address) && ValidateBitcoinAddress(address))
                {
                    uniqueIOCs.Add(address);
                    
                    iocs.Add(new IOC
                    {
                        Id = Guid.NewGuid(),
                        AnalysisId = analysisId,
                        Type = "Bitcoin_Address",
                        Value = address,
                        Confidence = 90,
                        Context = ExtractContext(content, match.Index, 50),
                        FirstSeen = DateTime.UtcNow,
                        LastSeen = DateTime.UtcNow,
                        CreatedAt = DateTime.UtcNow,
                        Tags = new List<string> { "cryptocurrency", "bitcoin" }
                    });
                }
            }
            
            // Ethereum addresses
            var ethMatches = _patterns["EthereumAddress"].Matches(content);
            foreach (Match match in ethMatches)
            {
                var address = match.Value.ToLower();
                if (!uniqueIOCs.Contains(address))
                {
                    uniqueIOCs.Add(address);
                    
                    iocs.Add(new IOC
                    {
                        Id = Guid.NewGuid(),
                        AnalysisId = analysisId,
                        Type = "Ethereum_Address",
                        Value = address,
                        Confidence = 85,
                        Context = ExtractContext(content, match.Index, 50),
                        FirstSeen = DateTime.UtcNow,
                        LastSeen = DateTime.UtcNow,
                        CreatedAt = DateTime.UtcNow,
                        Tags = new List<string> { "cryptocurrency", "ethereum" }
                    });
                }
            }
            
            return iocs;
        }

        private async Task ValidateAndEnrichIOCAsync(IOC ioc, string content)
        {
            // Adjust confidence based on context
            var contextLower = ioc.Context?.ToLower() ?? "";
            
            // Increase confidence for security-related context
            if (contextLower.Contains("malware") || contextLower.Contains("virus") || 
                contextLower.Contains("trojan") || contextLower.Contains("backdoor") ||
                contextLower.Contains("exploit") || contextLower.Contains("payload"))
            {
                ioc.Confidence = Math.Min(100, ioc.Confidence + 15);
            }
            
            // Decrease confidence for documentation/example context
            if (contextLower.Contains("example") || contextLower.Contains("sample") || 
                contextLower.Contains("test") || contextLower.Contains("documentation"))
            {
                ioc.Confidence = Math.Max(10, ioc.Confidence - 20);
            }
            
            // Add metadata
            ioc.Metadata = new Dictionary<string, object>
            {
                ["extraction_timestamp"] = DateTime.UtcNow,
                ["content_length"] = content.Length,
                ["pattern_matches"] = Regex.Matches(content, Regex.Escape(ioc.Value)).Count
            };
        }

        // Validation methods
        private bool ValidateIPv4(string ip)
        {
            return IPAddress.TryParse(ip, out var address) && 
                   address.AddressFamily == AddressFamily.InterNetwork;
        }

        private bool ValidateIPv6(string ip)
        {
            return IPAddress.TryParse(ip, out var address) && 
                   address.AddressFamily == AddressFamily.InterNetworkV6;
        }

        private bool ValidateDomain(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain) || domain.Length > 253)
                return false;
            
            var labels = domain.Split('.');
            if (labels.Length < 2)
                return false;
            
            foreach (var label in labels)
            {
                if (string.IsNullOrEmpty(label) || label.Length > 63)
                    return false;
                
                if (!Regex.IsMatch(label, @"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$"))
                    return false;
            }
            
            return true;
        }

        private bool ValidateURL(string url)
        {
            return Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
                   (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps || 
                    uri.Scheme == Uri.UriSchemeFtp);
        }

        private bool ValidateMD5(string hash)
        {
            return hash.Length == 32 && Regex.IsMatch(hash, @"^[a-fA-F0-9]{32}$");
        }

        private bool ValidateSHA1(string hash)
        {
            return hash.Length == 40 && Regex.IsMatch(hash, @"^[a-fA-F0-9]{40}$");
        }

        private bool ValidateSHA256(string hash)
        {
            return hash.Length == 64 && Regex.IsMatch(hash, @"^[a-fA-F0-9]{64}$");
        }

        private bool ValidateSHA512(string hash)
        {
            return hash.Length == 128 && Regex.IsMatch(hash, @"^[a-fA-F0-9]{128}$");
        }

        private bool ValidateEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }

        private bool ValidateFilePath(string path)
        {
            // Basic validation - paths should have some structure
            return path.Length > 3 && (path.Contains('\\') || path.Contains('/'));
        }

        private bool ValidateRegistryKey(string key)
        {
            return key.StartsWith("HKEY_") || key.StartsWith("HK");
        }

        private bool ValidateBitcoinAddress(string address)
        {
            if (string.IsNullOrEmpty(address))
                return false;
            
            // Basic Bitcoin address validation
            if (address.StartsWith("1") || address.StartsWith("3"))
                return address.Length >= 26 && address.Length <= 35;
            
            if (address.StartsWith("bc1"))
                return address.Length >= 42 && address.Length <= 62;
            
            return false;
        }

        private bool ValidateEthereumAddress(string address)
        {
            return address.StartsWith("0x") && address.Length == 42 && 
                   Regex.IsMatch(address.Substring(2), @"^[a-fA-F0-9]{40}$");
        }

        // Helper methods
        private string ExtractContext(string content, int position, int contextLength)
        {
            var start = Math.Max(0, position - contextLength);
            var end = Math.Min(content.Length, position + contextLength);
            var context = content.Substring(start, end - start);
            
            // Clean up the context
            context = Regex.Replace(context, @"\s+", " ").Trim();
            
            if (start > 0)
                context = "..." + context;
            if (end < content.Length)
                context = context + "...";
            
            return context;
        }

        private bool IsPrivateIP(string ip)
        {
            if (!IPAddress.TryParse(ip, out var address))
                return false;
            
            var bytes = address.GetAddressBytes();
            
            // Check for private IP ranges
            return (bytes[0] == 10) ||
                   (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                   (bytes[0] == 192 && bytes[1] == 168) ||
                   (bytes[0] == 127); // Loopback
        }

        private bool IsWhitelistedDomain(string domain)
        {
            if (_whitelistedDomains.Contains(domain))
                return true;
            
            // Check parent domains
            var parts = domain.Split('.');
            for (int i = 1; i < parts.Length; i++)
            {
                var parentDomain = string.Join(".", parts.Skip(i));
                if (_whitelistedDomains.Contains(parentDomain))
                    return true;
            }
            
            return false;
        }

        private bool IsSuspiciousDomain(string domain)
        {
            // Check for suspicious patterns
            var suspiciousPatterns = new[]
            {
                @"\d{4,}", // Many consecutive digits
                @"[a-z]{20,}", // Very long strings
                @"^[0-9]+\.", // Starts with numbers
                @"-{2,}", // Multiple hyphens
                @"[^a-z0-9.-]", // Unusual characters
            };
            
            foreach (var pattern in suspiciousPatterns)
            {
                if (Regex.IsMatch(domain, pattern, RegexOptions.IgnoreCase))
                    return true;
            }
            
            // Check for DGA-like patterns
            var consonants = domain.Count(c => "bcdfghjklmnpqrstvwxyz".Contains(char.ToLower(c)));
            var vowels = domain.Count(c => "aeiou".Contains(char.ToLower(c)));
            
            if (consonants > 0 && vowels > 0)
            {
                var ratio = (double)consonants / vowels;
                if (ratio > 4 || ratio < 0.25)
                    return true;
            }
            
            return false;
        }

        private bool IsSuspiciousURL(string url)
        {
            var suspicious = new[]
            {
                "bit.ly", "tinyurl", "goo.gl", "ow.ly", "short.link",
                "download.php", "setup.exe", "install.exe",
                "phishing", "malware", "virus"
            };
            
            var urlLower = url.ToLower();
            return suspicious.Any(s => urlLower.Contains(s));
        }

        private bool IsSuspiciousEmail(string email)
        {
            var suspicious = new[]
            {
                "noreply", "no-reply", "donotreply", "mailer-daemon",
                "postmaster", "abuse", "admin@", "root@"
            };
            
            var emailLower = email.ToLower();
            return suspicious.Any(s => emailLower.Contains(s));
        }

        private bool IsSuspiciousFilePath(string path)
        {
            var suspicious = new[]
            {
                @"\temp\", @"\tmp\", @"\appdata\", @"\programdata\",
                @"\system32\", @"\syswow64\", @"\windows\temp\",
                "/tmp/", "/var/tmp/", "/dev/shm/",
                ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js"
            };
            
            var pathLower = path.ToLower();
            return suspicious.Any(s => pathLower.Contains(s));
        }

        private bool IsSuspiciousRegistryKey(string key)
        {
            var suspicious = new[]
            {
                @"currentversion\run", @"currentversion\runonce",
                @"currentcontrolset\services", @"software\classes",
                @"software\microsoft\windows\currentversion\explorer\shell",
                "userinit", "winlogon", "startup"
            };
            
            var keyLower = key.ToLower();
            return suspicious.Any(s => keyLower.Contains(s));
        }

        private bool IsValidHash(string hash, string hashType)
        {
            // Check if all zeros or common empty hashes
            if (_commonFalsePositives.Contains(hash))
                return false;
            
            // Check for repeating patterns
            if (hash.Length > 8)
            {
                var firstChars = hash.Substring(0, 4);
                var allSame = hash.All(c => c == hash[0]);
                var repeating = hash.Replace(firstChars, "").Length < hash.Length / 4;
                
                if (allSame || repeating)
                    return false;
            }
            
            return true;
        }

        private bool IsInterestingPort(int port)
        {
            // Common interesting ports for security analysis
            var interestingPorts = new HashSet<int>
            {
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                512, 513, 514, 1080, 1433, 1521, 2049, 2121, 3128, 3306, 3389,
                4444, 5432, 5900, 5985, 6379, 7001, 8000, 8008, 8080, 8443,
                8888, 9200, 9300, 27017, 27018, 27019
            };
            
            return interestingPorts.Contains(port) || port >= 30000;
        }

        private List<string> GetPortTags(int port)
        {
            var tags = new List<string>();
            
            var portServices = new Dictionary<int, string>
            {
                {21, "ftp"}, {22, "ssh"}, {23, "telnet"}, {25, "smtp"},
                {53, "dns"}, {80, "http"}, {110, "pop3"}, {135, "rpc"},
                {139, "netbios"}, {143, "imap"}, {443, "https"}, {445, "smb"},
                {1433, "mssql"}, {3306, "mysql"}, {3389, "rdp"}, {5432, "postgresql"},
                {6379, "redis"}, {8080, "http-alt"}, {27017, "mongodb"}
            };
            
            if (portServices.TryGetValue(port, out var service))
            {
                tags.Add(service);
            }
            
            if (port >= 30000)
            {
                tags.Add("high_port");
            }
            
            return tags;
        }

        // Confidence calculation methods
        private int CalculateIPConfidence(string ip, string content)
        {
            var confidence = 70;
            
            // Increase confidence if appears multiple times
            var occurrences = Regex.Matches(content, Regex.Escape(ip)).Count;
            confidence += Math.Min(occurrences * 3, 15);
            
            // Decrease for private IPs
            if (IsPrivateIP(ip))
                confidence -= 30;
            
            // Check context
            var contextWords = new[] { "attack", "malicious", "blocked", "threat", "suspicious" };
            foreach (var word in contextWords)
            {
                if (content.IndexOf(word, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    confidence += 5;
                    break;
                }
            }
            
            return Math.Max(10, Math.Min(100, confidence));
        }

        private int CalculateDomainConfidence(string domain, string content)
        {
            var confidence = 60;
            
            // Check TLD
            var tld = domain.Split('.').Last();
            var suspiciousTlds = new[] { "tk", "ml", "ga", "cf", "click", "download", "top" };
            if (suspiciousTlds.Contains(tld))
                confidence += 20;
            
            // Check if suspicious
            if (IsSuspiciousDomain(domain))
                confidence += 15;
            
            // Check occurrences
            var occurrences = Regex.Matches(content, Regex.Escape(domain)).Count;
            confidence += Math.Min(occurrences * 2, 10);
            
            return Math.Max(10, Math.Min(100, confidence));
        }

        private int CalculateURLConfidence(string url, string content)
        {
            var confidence = 65;
            
            if (IsSuspiciousURL(url))
                confidence += 20;
            
            // Check for URL shorteners
            if (url.Length < 30 && url.Contains("://"))
                confidence += 10;
            
            return Math.Max(10, Math.Min(100, confidence));
        }

        private int CalculateHashConfidence(string hash, string hashType, string content)
        {
            var confidence = 80; // Hashes are generally high confidence
            
            // Check context for malware indicators
            var malwareKeywords = new[] { "malware", "virus", "trojan", "detected", "malicious" };
            foreach (var keyword in malwareKeywords)
            {
                if (content.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    confidence += 10;
                    break;
                }
            }
            
            return Math.Min(100, confidence);
        }

        private int CalculateEmailConfidence(string email, string content)
        {
            var confidence = 50;
            
            if (IsSuspiciousEmail(email))
                confidence += 20;
            
            // Check domain
            var domain = email.Split('@')[1];
            if (IsSuspiciousDomain(domain))
                confidence += 15;
            
            return Math.Max(10, Math.Min(100, confidence));
        }

        private int CalculateFilePathConfidence(string path, string content)
        {
            var confidence = 60;
            
            if (IsSuspiciousFilePath(path))
                confidence += 25;
            
            // Check for executable extensions
            var execExtensions = new[] { ".exe", ".dll", ".bat", ".ps1", ".vbs" };
            if (execExtensions.Any(ext => path.EndsWith(ext, StringComparison.OrdinalIgnoreCase)))
                confidence += 15;
            
            return Math.Max(10, Math.Min(100, confidence));
        }

        private int CalculateRegistryKeyConfidence(string key, string content)
        {
            var confidence = 70;
            
            if (IsSuspiciousRegistryKey(key))
                confidence += 20;
            
            return Math.Min(100, confidence);
        }

        private int CalculatePortConfidence(int port, string content)
        {
            var confidence = 50;
            
            if (IsInterestingPort(port))
                confidence += 30;
            
            // Well-known malicious ports
            var maliciousPorts = new[] { 4444, 1337, 31337, 12345, 54321 };
            if (maliciousPorts.Contains(port))
                confidence += 20;
            
            return Math.Min(100, confidence);
        }
    }
}