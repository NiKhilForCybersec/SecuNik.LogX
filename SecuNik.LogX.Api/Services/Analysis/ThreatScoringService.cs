using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Core.Entities;

namespace SecuNik.LogX.Api.Services.Analysis
{
    public class ThreatScoringService
    {
        private readonly ILogger<ThreatScoringService> _logger;
        
        public ThreatScoringService(ILogger<ThreatScoringService> logger)
        {
            _logger = logger;
        }
        
        public int CalculateThreatScore(List<RuleMatchResult> ruleMatches, List<IOC>? iocs = null)
        {
            try
            {
                if ((ruleMatches == null || ruleMatches.Count == 0) && (iocs == null || iocs.Count == 0))
                {
                    return 0;
                }
                
                int score = 0;
                int totalFactors = 0;
                
                // Calculate score from rule matches
                if (ruleMatches != null && ruleMatches.Count > 0)
                {
                    int ruleScore = CalculateRuleMatchScore(ruleMatches);
                    score += ruleScore;
                    totalFactors++;
                }
                
                // Calculate score from IOCs
                if (iocs != null && iocs.Count > 0)
                {
                    int iocScore = CalculateIOCScore(iocs);
                    score += iocScore;
                    totalFactors++;
                }
                
                // Normalize score
                int normalizedScore = totalFactors > 0 ? score / totalFactors : 0;
                
                // Cap at 100
                return Math.Min(100, normalizedScore);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calculating threat score");
                return 0;
            }
        }
        
        private int CalculateRuleMatchScore(List<RuleMatchResult> ruleMatches)
        {
            // Calculate weighted score based on severity and match count
            int totalScore = 0;
            int totalWeight = 0;
            
            foreach (var match in ruleMatches)
            {
                int severityWeight = match.Severity switch
                {
                    ThreatLevel.Critical => 100,
                    ThreatLevel.High => 75,
                    ThreatLevel.Medium => 50,
                    ThreatLevel.Low => 25,
                    _ => 10
                };
                
                // Apply confidence factor
                double confidenceFactor = match.Confidence;
                
                // Calculate weighted score for this match
                int matchScore = (int)(severityWeight * confidenceFactor);
                
                // Weight by match count
                int weight = match.MatchCount;
                totalScore += matchScore * weight;
                totalWeight += weight;
            }
            
            // Normalize
            return totalWeight > 0 ? totalScore / totalWeight : 0;
        }
        
        private int CalculateIOCScore(List<IOC> iocs)
        {
            // Calculate score based on IOC types and maliciousness
            int totalScore = 0;
            
            foreach (var ioc in iocs)
            {
                int baseScore = ioc.IsMalicious ? 75 : 25;
                
                // Adjust by IOC type
                int typeMultiplier = ioc.Type switch
                {
                    IOCType.IPAddress => 1,
                    IOCType.Domain => 1,
                    IOCType.URL => 1,
                    IOCType.FileHash => 2, // File hashes are stronger indicators
                    IOCType.Email => 1,
                    IOCType.FilePath => 1,
                    IOCType.RegistryKey => 1,
                    IOCType.Mutex => 2, // Mutexes are often specific to malware
                    _ => 1
                };
                
                // Apply confidence factor
                double confidenceFactor = ioc.Confidence / 100.0;
                
                totalScore += (int)(baseScore * typeMultiplier * confidenceFactor);
            }
            
            // Normalize to 0-100 scale
            return Math.Min(100, totalScore / Math.Max(1, iocs.Count));
        }
        
        public string GetSeverityFromScore(int score)
        {
            if (score >= 80) return "critical";
            if (score >= 60) return "high";
            if (score >= 30) return "medium";
            return "low";
        }
    }
}