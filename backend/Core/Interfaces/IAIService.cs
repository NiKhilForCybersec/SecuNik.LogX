using SecuNikLogX.API.Models;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SecuNikLogX.Core.Interfaces
{
    public interface IAIService
    {
        // Core analysis
        Task<AIAnalysisResult> AnalyzeWithAIAsync(string content, AIAnalysisOptions options, CancellationToken cancellationToken = default);
        Task<ThreatAssessment> GenerateThreatAssessmentAsync(Guid analysisId, CancellationToken cancellationToken = default);
        
        // IOC enrichment
        Task<EnrichedIOC> EnrichIOCAsync(string iocValue, IOCType type, CancellationToken cancellationToken = default);
        Task<List<EnrichedIOC>> EnrichIOCBatchAsync(List<IOC> iocs, CancellationToken cancellationToken = default);
        
        // Report generation
        Task<string> GenerateExecutiveSummaryAsync(Guid analysisId, CancellationToken cancellationToken = default);
        Task<ForensicsReport> GenerateDetailedReportAsync(Guid analysisId, ReportOptions options, CancellationToken cancellationToken = default);
        Task<string> GenerateIncidentResponsePlanAsync(Guid analysisId, CancellationToken cancellationToken = default);
        
        // Cost management
        Task<decimal> EstimateCostAsync(string content, AIModel model, CancellationToken cancellationToken = default);
        Task<AIUsageStatistics> GetUsageStatisticsAsync(DateTime startDate, DateTime endDate, CancellationToken cancellationToken = default);
        
        // Natural language queries
        Task<string> QueryAnalysisAsync(Guid analysisId, string naturalLanguageQuery, CancellationToken cancellationToken = default);
        Task<List<string>> SuggestNextStepsAsync(Guid analysisId, CancellationToken cancellationToken = default);
        
        // Pattern detection
        Task<List<DetectedPattern>> DetectPatternsAsync(string content, PatternDetectionOptions options, CancellationToken cancellationToken = default);
        Task<List<AnomalyResult>> DetectAnomaliesAsync(string content, AnomalyDetectionOptions options, CancellationToken cancellationToken = default);
        
        // Threat intelligence
        Task<ThreatIntelligence> GetThreatIntelligenceAsync(string indicator, CancellationToken cancellationToken = default);
        Task<List<ThreatActor>> IdentifyThreatActorsAsync(Guid analysisId, CancellationToken cancellationToken = default);
        
        // Model management
        Task<List<AIModel>> GetAvailableModelsAsync(CancellationToken cancellationToken = default);
        Task<ModelHealth> CheckModelHealthAsync(AIModel model, CancellationToken cancellationToken = default);
        Task<bool> ValidateApiKeyAsync(string apiKey, CancellationToken cancellationToken = default);
    }

    // Supporting types for the interface
    public class AIAnalysisResult
    {
        public string Summary { get; set; }
        public List<string> KeyFindings { get; set; }
        public double ConfidenceScore { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        public int TokensUsed { get; set; }
        public decimal EstimatedCost { get; set; }
        public TimeSpan ProcessingTime { get; set; }
    }

    public class AIAnalysisOptions
    {
        public AIAnalysisType AnalysisType { get; set; }
        public AIModel Model { get; set; }
        public int MaxTokens { get; set; }
        public double Temperature { get; set; }
        public bool IncludeIOCAnalysis { get; set; }
        public bool IncludeMITREMapping { get; set; }
        public string CustomPrompt { get; set; }
    }

    public enum AIAnalysisType
    {
        Quick,
        Standard,
        Comprehensive,
        Custom
    }

    public enum AIModel
    {
        GPT35Turbo,
        GPT4,
        GPT4Turbo,
        Claude3Opus,
        Claude3Sonnet,
        Custom
    }

    public class ThreatAssessment
    {
        public Guid AnalysisId { get; set; }
        public double ThreatScore { get; set; }
        public string ThreatLevel { get; set; }
        public List<string> RiskFactors { get; set; }
        public List<string> Recommendations { get; set; }
        public Dictionary<string, double> CategoryScores { get; set; }
        public DateTime AssessedAt { get; set; }
    }

    public class EnrichedIOC
    {
        public string Value { get; set; }
        public IOCType Type { get; set; }
        public string Description { get; set; }
        public double RiskScore { get; set; }
        public List<string> RelatedIndicators { get; set; }
        public Dictionary<string, object> ThreatIntelligence { get; set; }
        public DateTime EnrichedAt { get; set; }
    }

    public class ForensicsReport
    {
        public string Title { get; set; }
        public string ExecutiveSummary { get; set; }
        public List<ReportSection> Sections { get; set; }
        public List<string> Recommendations { get; set; }
        public Dictionary<string, object> Statistics { get; set; }
        public DateTime GeneratedAt { get; set; }
    }

    public class ReportSection
    {
        public string Title { get; set; }
        public string Content { get; set; }
        public List<string> KeyPoints { get; set; }
        public Dictionary<string, object> Data { get; set; }
    }

    public class ReportOptions
    {
        public ReportFormat Format { get; set; }
        public ReportDetailLevel DetailLevel { get; set; }
        public bool IncludeRawData { get; set; }
        public bool IncludeVisualizations { get; set; }
        public List<string> CustomSections { get; set; }
    }

    public enum ReportFormat
    {
        Markdown,
        HTML,
        PDF,
        JSON
    }

    public enum ReportDetailLevel
    {
        Executive,
        Standard,
        Technical,
        Comprehensive
    }

    public class AIUsageStatistics
    {
        public int TotalRequests { get; set; }
        public int TotalTokensUsed { get; set; }
        public decimal TotalCost { get; set; }
        public Dictionary<AIModel, int> RequestsByModel { get; set; }
        public Dictionary<DateTime, int> RequestsByDay { get; set; }
        public double AverageResponseTime { get; set; }
    }

    public class DetectedPattern
    {
        public string PatternType { get; set; }
        public string Description { get; set; }
        public double Confidence { get; set; }
        public List<string> Instances { get; set; }
        public Dictionary<string, object> Attributes { get; set; }
    }

    public class PatternDetectionOptions
    {
        public List<string> PatternTypes { get; set; }
        public double MinConfidence { get; set; }
        public int MaxResults { get; set; }
    }

    public class AnomalyResult
    {
        public string AnomalyType { get; set; }
        public string Description { get; set; }
        public double AnomalyScore { get; set; }
        public string Context { get; set; }
        public Dictionary<string, object> Details { get; set; }
    }

    public class AnomalyDetectionOptions
    {
        public double SensitivityThreshold { get; set; }
        public List<string> FocusAreas { get; set; }
        public bool IncludeStatisticalAnalysis { get; set; }
    }

    public class ThreatIntelligence
    {
        public string Indicator { get; set; }
        public string ThreatType { get; set; }
        public double RiskScore { get; set; }
        public List<string> AssociatedCampaigns { get; set; }
        public List<string> RelatedActors { get; set; }
        public Dictionary<string, object> AdditionalContext { get; set; }
        public DateTime LastUpdated { get; set; }
    }

    public class ThreatActor
    {
        public string Name { get; set; }
        public string Alias { get; set; }
        public double ConfidenceScore { get; set; }
        public List<string> KnownTechniques { get; set; }
        public List<string> TargetSectors { get; set; }
        public string MotivationType { get; set; }
    }

    public class ModelHealth
    {
        public AIModel Model { get; set; }
        public bool IsAvailable { get; set; }
        public double ResponseTime { get; set; }
        public int RateLimitRemaining { get; set; }
        public DateTime LastChecked { get; set; }
    }
}