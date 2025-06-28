namespace SecuNik.LogX.Core.Constants
{
    public static class FileConstants
    {
        // File size limits
        public const long MaxFileSize = 1073741824; // 1GB
        public const long MaxTotalStorage = 53687091200; // 50GB
        
        // Supported file extensions
        public static readonly string[] LogFileExtensions = { ".log", ".txt", ".syslog" };
        public static readonly string[] WindowsEventExtensions = { ".evtx", ".evt" };
        public static readonly string[] NetworkCaptureExtensions = { ".pcap", ".pcapng", ".cap" };
        public static readonly string[] ArchiveExtensions = { ".zip", ".rar", ".7z", ".tar", ".gz" };
        public static readonly string[] EmailExtensions = { ".eml", ".msg", ".mbox" };
        public static readonly string[] DatabaseExtensions = { ".sql", ".db", ".sqlite" };
        public static readonly string[] StructuredDataExtensions = { ".json", ".xml", ".csv", ".yaml", ".yml" };
        public static readonly string[] DocumentExtensions = { ".pdf", ".doc", ".docx", ".xls", ".xlsx" };
        public static readonly string[] CodeExtensions = { ".js", ".py", ".sh", ".ps1", ".bat" };
        public static readonly string[] BinaryExtensions = { ".exe", ".dll", ".so" };
        
        // All supported extensions
        public static readonly string[] AllSupportedExtensions = LogFileExtensions
            .Concat(WindowsEventExtensions)
            .Concat(NetworkCaptureExtensions)
            .Concat(ArchiveExtensions)
            .Concat(EmailExtensions)
            .Concat(DatabaseExtensions)
            .Concat(StructuredDataExtensions)
            .Concat(DocumentExtensions)
            .Concat(CodeExtensions)
            .Concat(BinaryExtensions)
            .ToArray();
        
        // Blocked extensions for security
        public static readonly string[] BlockedExtensions = { ".scr", ".pif", ".com", ".vbs", ".jar" };
        
        // MIME types
        public static readonly Dictionary<string, string> MimeTypes = new()
        {
            { ".log", "text/plain" },
            { ".txt", "text/plain" },
            { ".json", "application/json" },
            { ".xml", "application/xml" },
            { ".csv", "text/csv" },
            { ".evtx", "application/octet-stream" },
            { ".evt", "application/octet-stream" },
            { ".pcap", "application/vnd.tcpdump.pcap" },
            { ".pcapng", "application/octet-stream" },
            { ".zip", "application/zip" },
            { ".rar", "application/x-rar-compressed" },
            { ".7z", "application/x-7z-compressed" },
            { ".eml", "message/rfc822" },
            { ".msg", "application/vnd.ms-outlook" },
            { ".pdf", "application/pdf" },
            { ".exe", "application/x-msdownload" },
            { ".dll", "application/x-msdownload" }
        };
        
        // File type categories
        public static readonly Dictionary<string, string> FileCategories = new()
        {
            { ".log", "System Log" },
            { ".txt", "Text File" },
            { ".syslog", "Syslog" },
            { ".evtx", "Windows Event Log" },
            { ".evt", "Windows Event Log" },
            { ".pcap", "Network Capture" },
            { ".pcapng", "Network Capture" },
            { ".cap", "Network Capture" },
            { ".zip", "Archive" },
            { ".rar", "Archive" },
            { ".7z", "Archive" },
            { ".tar", "Archive" },
            { ".gz", "Archive" },
            { ".eml", "Email" },
            { ".msg", "Email" },
            { ".mbox", "Email" },
            { ".sql", "Database" },
            { ".db", "Database" },
            { ".sqlite", "Database" },
            { ".json", "Structured Data" },
            { ".xml", "Structured Data" },
            { ".csv", "Structured Data" },
            { ".yaml", "Structured Data" },
            { ".yml", "Structured Data" },
            { ".pdf", "Document" },
            { ".doc", "Document" },
            { ".docx", "Document" },
            { ".xls", "Document" },
            { ".xlsx", "Document" },
            { ".js", "Code" },
            { ".py", "Code" },
            { ".sh", "Code" },
            { ".ps1", "Code" },
            { ".bat", "Code" },
            { ".exe", "Executable" },
            { ".dll", "Library" },
            { ".so", "Library" }
        };
        
        // Analysis result file names
        public const string ParsedDataFileName = "parsed_data.json";
        public const string TimelineFileName = "timeline.json";
        public const string IOCsFileName = "iocs.json";
        public const string RuleMatchesFileName = "rule_matches.json";
        public const string MitreResultsFileName = "mitre_results.json";
        public const string ThreatIntelligenceFileName = "threat_intelligence.json";
        public const string AISummaryFileName = "ai_summary.json";
        public const string MetadataFileName = "metadata.json";
        
        // Directory names
        public const string UploadsDirectory = "Uploads";
        public const string ParsersDirectory = "Parsers";
        public const string RulesDirectory = "Rules";
        public const string ResultsDirectory = "Results";
        public const string TempDirectory = "Temp";
        public const string BuiltInDirectory = "BuiltIn";
        public const string UserDefinedDirectory = "UserDefined";
        public const string YaraDirectory = "YARA";
        public const string SigmaDirectory = "Sigma";
        public const string CustomDirectory = "Custom";
        
        // File validation
        public static bool IsExtensionSupported(string extension)
        {
            if (string.IsNullOrEmpty(extension)) return false;
            return AllSupportedExtensions.Contains(extension.ToLowerInvariant());
        }
        
        public static bool IsExtensionBlocked(string extension)
        {
            if (string.IsNullOrEmpty(extension)) return false;
            return BlockedExtensions.Contains(extension.ToLowerInvariant());
        }
        
        public static string GetMimeType(string extension)
        {
            if (string.IsNullOrEmpty(extension)) return "application/octet-stream";
            return MimeTypes.GetValueOrDefault(extension.ToLowerInvariant(), "application/octet-stream");
        }
        
        public static string GetFileCategory(string extension)
        {
            if (string.IsNullOrEmpty(extension)) return "Unknown";
            return FileCategories.GetValueOrDefault(extension.ToLowerInvariant(), "Unknown");
        }
        
        public static bool IsLogFile(string extension)
        {
            if (string.IsNullOrEmpty(extension)) return false;
            return LogFileExtensions.Contains(extension.ToLowerInvariant()) ||
                   WindowsEventExtensions.Contains(extension.ToLowerInvariant()) ||
                   StructuredDataExtensions.Contains(extension.ToLowerInvariant());
        }
        
        public static bool IsArchive(string extension)
        {
            if (string.IsNullOrEmpty(extension)) return false;
            return ArchiveExtensions.Contains(extension.ToLowerInvariant());
        }
        
        public static bool IsBinary(string extension)
        {
            if (string.IsNullOrEmpty(extension)) return false;
            return BinaryExtensions.Contains(extension.ToLowerInvariant()) ||
                   ArchiveExtensions.Contains(extension.ToLowerInvariant()) ||
                   NetworkCaptureExtensions.Contains(extension.ToLowerInvariant()) ||
                   WindowsEventExtensions.Contains(extension.ToLowerInvariant());
        }
    }
}