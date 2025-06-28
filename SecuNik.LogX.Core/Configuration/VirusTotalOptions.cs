using System.ComponentModel.DataAnnotations;

namespace SecuNik.LogX.Core.Configuration
{
    public class VirusTotalOptions
    {
        public const string SectionName = "VirusTotal";
        
        /// <summary>
        /// VirusTotal API Key
        /// </summary>
        [Required]
        public string ApiKey { get; set; } = string.Empty;
        
        /// <summary>
        /// VirusTotal API Base URL
        /// </summary>
        public string BaseUrl { get; set; } = "https://www.virustotal.com/api/v3";
        
        /// <summary>
        /// Enable VirusTotal integration
        /// </summary>
        public bool EnableIntegration { get; set; } = false;
        
        /// <summary>
        /// Delay between requests in milliseconds
        /// </summary>
        [Range(1000, 60000)]
        public int RequestDelayMs { get; set; } = 15000;
        
        /// <summary>
        /// Maximum requests per minute
        /// </summary>
        [Range(1, 60)]
        public int MaxRequestsPerMinute { get; set; } = 4;
        
        /// <summary>
        /// Cache expiration in hours
        /// </summary>
        [Range(1, 720)]
        public int CacheExpirationHours { get; set; } = 24;
    }
}