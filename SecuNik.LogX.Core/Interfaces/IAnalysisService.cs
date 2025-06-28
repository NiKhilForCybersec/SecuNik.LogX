using SecuNik.LogX.Core.Entities;

namespace SecuNik.LogX.Core.Interfaces
{
    
    public interface IAnalysisService
    {
        Task<Analysis> StartAnalysisAsync(Guid uploadId, AnalysisOptions options, CancellationToken cancellationToken = default);
        Task<Analysis?> GetAnalysisAsync(Guid analysisId, CancellationToken cancellationToken = default);
        Task<List<Analysis>> GetRecentAnalysesAsync(int limit = 10, CancellationToken cancellationToken = default);
        Task<bool> CancelAnalysisAsync(Guid analysisId, CancellationToken cancellationToken = default);
        Task<bool> DeleteAnalysisAsync(Guid analysisId, CancellationToken cancellationToken = default);
    }

    public class AnalysisOptions
    {
        public Guid? PreferredParserId { get; set; }
        public bool DeepScan { get; set; } = true;
        public bool ExtractIOCs { get; set; } = true;
        public bool CheckVirusTotal { get; set; } = false;
        public bool EnableAI { get; set; } = false;
        public int MaxEvents { get; set; } = 100000;
        public int TimeoutMinutes { get; set; } = 30;
        public List<string>? IncludeRuleTypes { get; set; }
        public List<string>? ExcludeRuleCategories { get; set; }
        public Dictionary<string, object>? CustomOptions { get; set; }
    }
}