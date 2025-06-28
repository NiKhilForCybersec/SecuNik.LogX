using System.ComponentModel.DataAnnotations;

namespace SecuNik.LogX.Core.Configuration
{
    public class OpenAIOptions
    {
        public const string SectionName = "OpenAI";
        
        /// <summary>
        /// OpenAI API Key
        /// </summary>
        [Required]
        public string ApiKey { get; set; } = string.Empty;
        
        /// <summary>
        /// OpenAI API Base URL
        /// </summary>
        public string BaseUrl { get; set; } = "https://api.openai.com/v1";
        
        /// <summary>
        /// Default model to use for analysis
        /// </summary>
        public string DefaultModel { get; set; } = "gpt-4";
        
        /// <summary>
        /// Maximum tokens for analysis requests
        /// </summary>
        [Range(1, 32000)]
        public int MaxTokens { get; set; } = 4000;
        
        /// <summary>
        /// Temperature for AI responses (0.0 to 2.0)
        /// </summary>
        [Range(0.0, 2.0)]
        public double Temperature { get; set; } = 0.3;
        
        /// <summary>
        /// Request timeout in seconds
        /// </summary>
        [Range(1, 300)]
        public int TimeoutSeconds { get; set; } = 60;
        
        /// <summary>
        /// Maximum retries for failed requests
        /// </summary>
        [Range(0, 5)]
        public int MaxRetries { get; set; } = 3;
        
        /// <summary>
        /// Enable AI analysis features
        /// </summary>
        public bool EnableAIAnalysis { get; set; } = false;
        
        /// <summary>
        /// Enable AI-powered IOC extraction
        /// </summary>
        public bool EnableAIIOCExtraction { get; set; } = false;
        
        /// <summary>
        /// Enable AI threat assessment
        /// </summary>
        public bool EnableAIThreatAssessment { get; set; } = false;
        
        /// <summary>
        /// Enable AI summary generation
        /// </summary>
        public bool EnableAISummary { get; set; } = false;
        
        /// <summary>
        /// System prompt for analysis
        /// </summary>
        public string AnalysisPrompt { get; set; } = @"
You are a cybersecurity expert analyzing log data for potential threats and anomalies. 
Analyze the provided log data and provide:
1. A concise summary of findings
2. Identified threats or suspicious activities
3. Recommended actions
4. Confidence level for each finding

Be precise, factual, and focus on actionable intelligence.";
        
        /// <summary>
        /// System prompt for IOC extraction
        /// </summary>
        public string IOCExtractionPrompt { get; set; } = @"
Extract all Indicators of Compromise (IOCs) from the provided log data.
Focus on:
- IP addresses
- Domain names
- File hashes
- URLs
- Email addresses
- File paths
- Registry keys

Return results in structured format with confidence levels.";
        
        /// <summary>
        /// System prompt for threat assessment
        /// </summary>
        public string ThreatAssessmentPrompt { get; set; } = @"
Assess the threat level of the analyzed data on a scale of 0-100.
Consider:
- Severity of detected activities
- Potential impact
- Confidence in detection
- Context and patterns

Provide reasoning for the threat score.";
    }
}