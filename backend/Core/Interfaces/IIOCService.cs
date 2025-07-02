using SecuNikLogX.API.Models;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SecuNikLogX.Core.Interfaces
{
    public interface IIOCService
    {
        // Extraction
        Task<List<ExtractedIOC>> ExtractIOCsAsync(string content, IOCExtractionOptions options, CancellationToken cancellationToken = default);
        Task<List<ExtractedIOC>> ExtractIOCsFromFileAsync(string filePath, IOCExtractionOptions options, CancellationToken cancellationToken = default);
        Task<List<ExtractedIOC>> ExtractIOCsFromBinaryAsync(byte[] data, IOCExtractionOptions options, CancellationToken cancellationToken = default);
        
        // Validation
        Task<IOCValidationResult> ValidateIOCAsync(string iocValue, IOCType type, CancellationToken cancellationToken = default);
        Task<List<IOCValidationResult>> ValidateIOCBatchAsync(List<IOC> iocs, CancellationToken cancellationToken = default);
        Task<bool> IsKnownFalsePositiveAsync(string iocValue, IOCType type, CancellationToken cancellationToken = default);
        
        // Management
        Task<IOC> CreateIOCAsync(CreateIOCRequest request, CancellationToken cancellationToken = default);
        Task<IOC> UpdateIOCAsync(Guid id, UpdateIOCRequest request, CancellationToken cancellationToken = default);
        Task<bool> DeleteIOCAsync(Guid id, CancellationToken cancellationToken = default);
        Task<IOC> GetIOCByIdAsync(Guid id, CancellationToken cancellationToken = default);
        Task<List<IOC>> GetIOCsByAnalysisIdAsync(Guid analysisId, CancellationToken cancellationToken = default);
        
        // Search and filtering
        Task<IOCSearchResult> SearchIOCsAsync(IOCSearchCriteria criteria, CancellationToken cancellationToken = default);
        Task<List<IOC>> GetIOCsByTypeAsync(IOCType type, int limit = 100, CancellationToken cancellationToken = default);
        Task<List<IOC>> GetIOCsByDateRangeAsync(DateTime startDate, DateTime endDate, CancellationToken cancellationToken = default);
        Task<List<IOC>> GetHighConfidenceIOCsAsync(double minConfidence = 0.8, CancellationToken cancellationToken = default);
        
        // Enrichment
        Task<IOC> EnrichIOCAsync(Guid id, IOCEnrichmentOptions options, CancellationToken cancellationToken = default);
        Task<GeoLocationInfo> GetGeoLocationAsync(string ipAddress, CancellationToken cancellationToken = default);
        Task<DomainInfo> GetDomainInfoAsync(string domain, CancellationToken cancellationToken = default);
        Task<FileHashInfo> GetFileHashInfoAsync(string hash, HashType hashType, CancellationToken cancellationToken = default);
        
        // Correlation
        Task<List<IOCCorrelation>> FindCorrelationsAsync(Guid iocId, CancellationToken cancellationToken = default);
        Task<List<IOC>> GetRelatedIOCsAsync(Guid iocId, int maxResults = 50, CancellationToken cancellationToken = default);
        Task<IOCCluster> ClusterIOCsAsync(List<Guid> iocIds, ClusteringOptions options, CancellationToken cancellationToken = default);
        
        // Export and reporting
        Task<string> ExportIOCsAsync(ExportIOCOptions options, CancellationToken cancellationToken = default);
        Task<IOCStatistics> GetStatisticsAsync(Guid? analysisId = null, CancellationToken cancellationToken = default);
        Task<List<IOCTrend>> GetTrendsAsync(DateTime startDate, DateTime endDate, CancellationToken cancellationToken = default);
        
        // Whitelist/Blacklist management
        Task<bool> AddToWhitelistAsync(string iocValue, IOCType type, string reason, CancellationToken cancellationToken = default);
        Task<bool> AddToBlacklistAsync(string iocValue, IOCType type, string reason, CancellationToken cancellationToken = default);
        Task<bool> RemoveFromWhitelistAsync(string iocValue, IOCType type, CancellationToken cancellationToken = default);
        Task<bool> RemoveFromBlacklistAsync(string iocValue, IOCType type, CancellationToken cancellationToken = default);
        Task<bool> IsWhitelistedAsync(string iocValue, IOCType type, CancellationToken cancellationToken = default);
        Task<bool> IsBlacklistedAsync(string iocValue, IOCType type, CancellationToken cancellationToken = default);
    }

    // Supporting types for the interface
    public class ExtractedIOC
    {
        public string Value { get; set; }
        public IOCType Type { get; set; }
        public string Context { get; set; }
        public int Offset { get; set; }
        public double Confidence { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        public DateTime ExtractedAt { get; set; }
    }

    public class IOCExtractionOptions
    {
        public Guid AnalysisId { get; set; }
        public bool EnableContextExtraction { get; set; }
        public int ContextWindowSize { get; set; }
        public List<IOCType> TypesToExtract { get; set; }
        public bool IncludeMetadata { get; set; }
        public bool ValidateExtractedIOCs { get; set; }
        public int? ChunkIndex { get; set; }
    }

    public class IOCValidationResult
    {
        public string Value { get; set; }
        public IOCType Type { get; set; }
        public bool IsValid { get; set; }
        public List<string> ValidationErrors { get; set; }
        public double ConfidenceScore { get; set; }
        public Dictionary<string, object> ValidationDetails { get; set; }
    }

    public class CreateIOCRequest
    {
        public string Value { get; set; }
        public IOCType Type { get; set; }
        public Guid AnalysisId { get; set; }
        public string Context { get; set; }
        public double Confidence { get; set; }
        public string Source { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
    }

    public class UpdateIOCRequest
    {
        public double? Confidence { get; set; }
        public string Context { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        public bool? IsFalsePositive { get; set; }
        public string Notes { get; set; }
    }

    public class IOCSearchResult
    {
        public List<IOC> Items { get; set; }
        public int TotalCount { get; set; }
        public int PageNumber { get; set; }
        public int PageSize { get; set; }
        public Dictionary<IOCType, int> TypeCounts { get; set; }
    }

    public class IOCSearchCriteria
    {
        public string SearchTerm { get; set; }
        public List<IOCType> Types { get; set; }
        public double? MinConfidence { get; set; }
        public DateTime? StartDate { get; set; }
        public DateTime? EndDate { get; set; }
        public Guid? AnalysisId { get; set; }
        public bool? ExcludeFalsePositives { get; set; }
        public int PageNumber { get; set; }
        public int PageSize { get; set; }
        public string SortBy { get; set; }
        public bool SortDescending { get; set; }
    }

    public class IOCEnrichmentOptions
    {
        public bool IncludeGeoLocation { get; set; }
        public bool IncludeDomainInfo { get; set; }
        public bool IncludeReputation { get; set; }
        public bool IncludeThreatIntelligence { get; set; }
        public List<string> EnrichmentSources { get; set; }
    }

    public class GeoLocationInfo
    {
        public string IpAddress { get; set; }
        public string Country { get; set; }
        public string CountryCode { get; set; }
        public string Region { get; set; }
        public string City { get; set; }
        public double? Latitude { get; set; }
        public double? Longitude { get; set; }
        public string ISP { get; set; }
        public string Organization { get; set; }
    }

    public class DomainInfo
    {
        public string Domain { get; set; }
        public DateTime? RegisteredDate { get; set; }
        public DateTime? ExpirationDate { get; set; }
        public string Registrar { get; set; }
        public List<string> NameServers { get; set; }
        public List<string> IpAddresses { get; set; }
        public int? AgeInDays { get; set; }
        public Dictionary<string, object> WhoisData { get; set; }
    }

    public class FileHashInfo
    {
        public string Hash { get; set; }
        public HashType HashType { get; set; }
        public string FileName { get; set; }
        public long? FileSize { get; set; }
        public string FileType { get; set; }
        public DateTime? FirstSeen { get; set; }
        public DateTime? LastSeen { get; set; }
        public int? PrevalenceCount { get; set; }
        public List<string> AssociatedMalware { get; set; }
    }

    public enum HashType
    {
        MD5,
        SHA1,
        SHA256,
        SHA512,
        SSDEEP
    }

    public class IOCCorrelation
    {
        public Guid SourceIOCId { get; set; }
        public Guid TargetIOCId { get; set; }
        public string CorrelationType { get; set; }
        public double CorrelationScore { get; set; }
        public string Reason { get; set; }
        public Dictionary<string, object> Details { get; set; }
    }

    public class IOCCluster
    {
        public string ClusterId { get; set; }
        public List<IOC> Members { get; set; }
        public string ClusterType { get; set; }
        public Dictionary<string, object> ClusterCharacteristics { get; set; }
        public double IntraClusterSimilarity { get; set; }
    }

    public class ClusteringOptions
    {
        public ClusteringAlgorithm Algorithm { get; set; }
        public double SimilarityThreshold { get; set; }
        public int? MaxClusters { get; set; }
        public List<string> FeaturesToConsider { get; set; }
    }

    public enum ClusteringAlgorithm
    {
        KMeans,
        DBSCAN,
        Hierarchical,
        Custom
    }

    public class ExportIOCOptions
    {
        public ExportFormat Format { get; set; }
        public Guid? AnalysisId { get; set; }
        public List<IOCType> TypesToExport { get; set; }
        public DateTime? StartDate { get; set; }
        public DateTime? EndDate { get; set; }
        public bool IncludeMetadata { get; set; }
        public bool IncludeContext { get; set; }
    }

    public enum ExportFormat
    {
        CSV,
        JSON,
        STIX,
        OpenIOC,
        MISP,
        PlainText
    }

    public class IOCStatistics
    {
        public int TotalIOCs { get; set; }
        public Dictionary<IOCType, int> CountByType { get; set; }
        public Dictionary<string, int> CountBySource { get; set; }
        public double AverageConfidence { get; set; }
        public int HighConfidenceCount { get; set; }
        public int FalsePositiveCount { get; set; }
        public Dictionary<DateTime, int> CountByDate { get; set; }
    }

    public class IOCTrend
    {
        public DateTime Date { get; set; }
        public Dictionary<IOCType, int> CountByType { get; set; }
        public int TotalCount { get; set; }
        public double AverageConfidence { get; set; }
        public List<string> TopIndicators { get; set; }
    }
}