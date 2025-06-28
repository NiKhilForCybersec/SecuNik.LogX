using System.ComponentModel.DataAnnotations;

namespace SecuNik.LogX.Core.Configuration
{
    public class StorageOptions
    {
        public const string SectionName = "Storage";
        
        [Required]
        public string BasePath { get; set; } = "Storage";
        
        [Required]
        public string UploadsPath { get; set; } = "Uploads";
        
        [Required]
        public string ParsersPath { get; set; } = "Parsers";
        
        [Required]
        public string RulesPath { get; set; } = "Rules";
        
        [Required]
        public string ResultsPath { get; set; } = "Results";
        
        [Required]
        public string TempPath { get; set; } = "Temp";
        
        /// <summary>
        /// Maximum file size in bytes (default: 1GB)
        /// </summary>
        [Range(1, long.MaxValue)]
        public long MaxFileSize { get; set; } = 1073741824; // 1GB
        
        /// <summary>
        /// Maximum storage space in bytes (default: 50GB)
        /// </summary>
        [Range(1, long.MaxValue)]
        public long MaxStorageSize { get; set; } = 53687091200; // 50GB
        
        /// <summary>
        /// Number of days to keep analysis files (default: 30 days)
        /// </summary>
        [Range(1, 365)]
        public int RetentionDays { get; set; } = 30;
        
        /// <summary>
        /// Enable automatic cleanup of old files
        /// </summary>
        public bool EnableAutoCleanup { get; set; } = true;
        
        /// <summary>
        /// Cleanup interval in hours (default: 24 hours)
        /// </summary>
        [Range(1, 168)]
        public int CleanupIntervalHours { get; set; } = 24;
        
        /// <summary>
        /// Enable file compression for storage
        /// </summary>
        public bool EnableCompression { get; set; } = true;
        
        /// <summary>
        /// Allowed file extensions for upload
        /// </summary>
        public List<string> AllowedExtensions { get; set; } = new()
        {
            ".log", ".txt", ".json", ".xml", ".csv", ".evtx", ".evt", 
            ".pcap", ".pcapng", ".zip", ".rar", ".7z", ".eml", ".msg"
        };
        
        /// <summary>
        /// Blocked file extensions
        /// </summary>
        public List<string> BlockedExtensions { get; set; } = new()
        {
            ".exe", ".bat", ".cmd", ".scr", ".pif", ".com"
        };
        
        // Helper methods
        public string GetUploadsPath() => Path.Combine(BasePath, UploadsPath);
        public string GetParsersPath() => Path.Combine(BasePath, ParsersPath);
        public string GetRulesPath() => Path.Combine(BasePath, RulesPath);
        public string GetResultsPath() => Path.Combine(BasePath, ResultsPath);
        public string GetTempPath() => Path.Combine(BasePath, TempPath);
        
        public string GetAnalysisPath(Guid analysisId) => Path.Combine(GetUploadsPath(), analysisId.ToString());
        public string GetResultsPath(Guid analysisId) => Path.Combine(GetResultsPath(), analysisId.ToString());
        
        public bool IsExtensionAllowed(string extension)
        {
            if (string.IsNullOrEmpty(extension)) return false;
            
            extension = extension.ToLowerInvariant();
            
            // Check if blocked
            if (BlockedExtensions.Contains(extension)) return false;
            
            // Check if allowed
            return AllowedExtensions.Contains(extension);
        }
    }
}