namespace SecuNik.LogX.Core.Interfaces
{
    public interface IStorageService
    {
        // File operations
        Task<string> SaveFileAsync(Guid analysisId, string fileName, Stream fileStream, CancellationToken cancellationToken = default);
        Task<Stream> GetFileAsync(Guid analysisId, string fileName, CancellationToken cancellationToken = default);
        Task<bool> DeleteFileAsync(Guid analysisId, string fileName, CancellationToken cancellationToken = default);
        Task<bool> FileExistsAsync(Guid analysisId, string fileName, CancellationToken cancellationToken = default);
        
        // Analysis results
        Task SaveAnalysisResultAsync(Guid analysisId, string resultType, object data, CancellationToken cancellationToken = default);
        Task<T?> GetAnalysisResultAsync<T>(Guid analysisId, string resultType, CancellationToken cancellationToken = default) where T : class;
        Task<bool> DeleteAnalysisResultAsync(Guid analysisId, string resultType, CancellationToken cancellationToken = default);
        
        // Parser management
        Task<string> SaveParserAsync(string parserName, string content, CancellationToken cancellationToken = default);
        Task<string?> GetParserAsync(string parserName, CancellationToken cancellationToken = default);
        Task<bool> DeleteParserAsync(string parserName, CancellationToken cancellationToken = default);
        Task<List<string>> ListParsersAsync(CancellationToken cancellationToken = default);
        
        // Rule management
        Task<string> SaveRuleAsync(string ruleName, string ruleType, string content, CancellationToken cancellationToken = default);
        Task<string?> GetRuleAsync(string ruleName, string ruleType, CancellationToken cancellationToken = default);
        Task<bool> DeleteRuleAsync(string ruleName, string ruleType, CancellationToken cancellationToken = default);
        Task<List<string>> ListRulesAsync(string ruleType, CancellationToken cancellationToken = default);
        
        // Cleanup operations
        Task CleanupOldFilesAsync(TimeSpan maxAge, CancellationToken cancellationToken = default);
        Task<StorageInfo> GetStorageInfoAsync(CancellationToken cancellationToken = default);
        
        // Directory operations
        Task<bool> CreateAnalysisDirectoryAsync(Guid analysisId, CancellationToken cancellationToken = default);
        Task<bool> DeleteAnalysisDirectoryAsync(Guid analysisId, CancellationToken cancellationToken = default);
        Task<List<string>> ListAnalysisFilesAsync(Guid analysisId, CancellationToken cancellationToken = default);
        
        // Path helper
        string GetAnalysisPath(Guid analysisId);
    }
    
    public class StorageInfo
    {
        public long TotalSpace { get; set; }
        public long UsedSpace { get; set; }
        public long AvailableSpace { get; set; }
        public int TotalFiles { get; set; }
        public int TotalAnalyses { get; set; }
        public DateTime LastCleanup { get; set; }
    }
}