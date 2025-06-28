using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Core.DTOs;
using System.Text.RegularExpressions;

namespace SecuNik.LogX.Api.Services.Analysis
{
    public class MitreMapperService
    {
        private readonly ILogger<MitreMapperService> _logger;
        
        // Regex for MITRE ATT&CK technique IDs
        private static readonly Regex TechniqueIdRegex = new Regex(@"T\d{4}(?:\.\d{3})?", RegexOptions.Compiled);
        
        // Mapping of common tactics
        private static readonly Dictionary<string, string> TacticMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "initial_access", "Initial Access" },
            { "execution", "Execution" },
            { "persistence", "Persistence" },
            { "privilege_escalation", "Privilege Escalation" },
            { "defense_evasion", "Defense Evasion" },
            { "credential_access", "Credential Access" },
            { "discovery", "Discovery" },
            { "lateral_movement", "Lateral Movement" },
            { "collection", "Collection" },
            { "command_and_control", "Command and Control" },
            { "exfiltration", "Exfiltration" },
            { "impact", "Impact" }
        };
        
        public MitreMapperService(ILogger<MitreMapperService> logger)
        {
            _logger = logger;
        }
        
        public async Task<MitreAttackDto> MapToMitreAsync(
            List<RuleMatchResult> ruleMatches,
            CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Mapping {RuleMatchCount} rule matches to MITRE ATT&CK", ruleMatches.Count);
                
                var result = new MitreAttackDto
                {
                    Techniques = new List<TechniqueDto>(),
                    Tactics = new List<TacticDto>(),
                    KillChainPhases = new List<string>(),
                    TechniqueFrequency = new Dictionary<string, int>(),
                    TacticFrequency = new Dictionary<string, int>()
                };
                
                // Extract MITRE ATT&CK technique IDs from rule matches
                var techniqueMap = new Dictionary<string, TechniqueDto>();
                var tacticMap = new Dictionary<string, TacticDto>();
                
                foreach (var match in ruleMatches)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    // Extract from MITRE ATT&CK IDs
                    foreach (var techniqueId in match.MitreAttackIds)
                    {
                        await ProcessTechniqueId(techniqueId, match, techniqueMap, tacticMap, result);
                    }
                    
                    // Extract from rule content and metadata
                    await ExtractFromRuleContent(match, techniqueMap, tacticMap, result);
                }
                
                // Finalize results
                result.Techniques = techniqueMap.Values.ToList();
                result.Tactics = tacticMap.Values.ToList();
                
                // Calculate statistics
                result.Statistics = CalculateStatistics(result);
                
                _logger.LogInformation("Mapped {TechniqueCount} techniques and {TacticCount} tactics", 
                    result.Techniques.Count, result.Tactics.Count);
                
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error mapping to MITRE ATT&CK");
                throw;
            }
        }
        
        private async Task ProcessTechniqueId(
            string techniqueId,
            RuleMatchResult match,
            Dictionary<string, TechniqueDto> techniqueMap,
            Dictionary<string, TacticDto> tacticMap,
            MitreAttackDto result)
        {
            // Normalize technique ID
            techniqueId = techniqueId.ToUpperInvariant();
            
            // Check if it's a sub-technique
            bool isSubTechnique = techniqueId.Contains('.');
            string parentTechniqueId = isSubTechnique ? techniqueId.Split('.')[0] : techniqueId;
            
            // Update technique frequency
            if (result.TechniqueFrequency.ContainsKey(techniqueId))
            {
                result.TechniqueFrequency[techniqueId]++;
            }
            else
            {
                result.TechniqueFrequency[techniqueId] = 1;
            }
            
            // Get or create technique
            if (!techniqueMap.TryGetValue(parentTechniqueId, out var technique))
            {
                technique = new TechniqueDto
                {
                    TechniqueId = parentTechniqueId,
                    TechniqueName = GetTechniqueName(parentTechniqueId),
                    Description = GetTechniqueDescription(parentTechniqueId),
                    Tactics = GetTacticsByTechnique(parentTechniqueId),
                    Platforms = new List<string>(),
                    DataSources = new List<string>(),
                    SubTechniques = new List<SubTechniqueDto>(),
                    Confidence = 1.0,
                    MatchCount = 0,
                    Evidence = new List<string>()
                };
                
                techniqueMap[parentTechniqueId] = technique;
            }
            
            // Update match count
            technique.MatchCount++;
            
            // Add evidence
            if (match.Matches.Count > 0)
            {
                var evidence = $"Rule '{match.RuleName}' matched: {match.Matches[0].MatchedContent}";
                if (!technique.Evidence.Contains(evidence))
                {
                    technique.Evidence.Add(evidence);
                }
            }
            
            // Handle sub-technique
            if (isSubTechnique)
            {
                var subTechniqueId = techniqueId;
                var existingSubTechnique = technique.SubTechniques.FirstOrDefault(st => st.SubTechniqueId == subTechniqueId);
                
                if (existingSubTechnique == null)
                {
                    var subTechnique = new SubTechniqueDto
                    {
                        SubTechniqueId = subTechniqueId,
                        SubTechniqueName = GetTechniqueName(subTechniqueId),
                        Description = GetTechniqueDescription(subTechniqueId),
                        Confidence = 1.0,
                        MatchCount = 1,
                        Evidence = new List<string>()
                    };
                    
                    if (match.Matches.Count > 0)
                    {
                        var evidence = $"Rule '{match.RuleName}' matched: {match.Matches[0].MatchedContent}";
                        subTechnique.Evidence.Add(evidence);
                    }
                    
                    technique.SubTechniques.Add(subTechnique);
                }
                else
                {
                    existingSubTechnique.MatchCount++;
                    
                    if (match.Matches.Count > 0)
                    {
                        var evidence = $"Rule '{match.RuleName}' matched: {match.Matches[0].MatchedContent}";
                        if (!existingSubTechnique.Evidence.Contains(evidence))
                        {
                            existingSubTechnique.Evidence.Add(evidence);
                        }
                    }
                }
            }
            
            // Process tactics
            foreach (var tactic in technique.Tactics)
            {
                // Update tactic frequency
                if (result.TacticFrequency.ContainsKey(tactic))
                {
                    result.TacticFrequency[tactic]++;
                }
                else
                {
                    result.TacticFrequency[tactic] = 1;
                }
                
                // Get or create tactic
                if (!tacticMap.TryGetValue(tactic, out var tacticDto))
                {
                    tacticDto = new TacticDto
                    {
                        TacticId = GetTacticId(tactic),
                        TacticName = tactic,
                        Description = GetTacticDescription(tactic),
                        TechniqueIds = new List<string>(),
                        TechniqueCount = 0,
                        Coverage = 0.0
                    };
                    
                    tacticMap[tactic] = tacticDto;
                }
                
                // Add technique to tactic
                if (!tacticDto.TechniqueIds.Contains(parentTechniqueId))
                {
                    tacticDto.TechniqueIds.Add(parentTechniqueId);
                    tacticDto.TechniqueCount++;
                }
            }
        }
        
        private async Task ExtractFromRuleContent(
            RuleMatchResult match,
            Dictionary<string, TechniqueDto> techniqueMap,
            Dictionary<string, TacticDto> tacticMap,
            MitreAttackDto result)
        {
            // Extract technique IDs from rule metadata
            foreach (var entry in match.Metadata)
            {
                if (entry.Value is string valueStr)
                {
                    var techniqueMatches = TechniqueIdRegex.Matches(valueStr);
                    foreach (Match techniqueMatch in techniqueMatches)
                    {
                        await ProcessTechniqueId(techniqueMatch.Value, match, techniqueMap, tacticMap, result);
                    }
                }
            }
            
            // Extract from match content
            foreach (var matchDetail in match.Matches)
            {
                if (!string.IsNullOrEmpty(matchDetail.MatchedContent))
                {
                    var techniqueMatches = TechniqueIdRegex.Matches(matchDetail.MatchedContent);
                    foreach (Match techniqueMatch in techniqueMatches)
                    {
                        await ProcessTechniqueId(techniqueMatch.Value, match, techniqueMap, tacticMap, result);
                    }
                }
                
                if (!string.IsNullOrEmpty(matchDetail.Context))
                {
                    var techniqueMatches = TechniqueIdRegex.Matches(matchDetail.Context);
                    foreach (Match techniqueMatch in techniqueMatches)
                    {
                        await ProcessTechniqueId(techniqueMatch.Value, match, techniqueMap, tacticMap, result);
                    }
                }
            }
        }
        
        private MitreStatisticsDto CalculateStatistics(MitreAttackDto result)
        {
            var stats = new MitreStatisticsDto
            {
                TotalTechniques = result.Techniques.Count,
                TotalTactics = result.Tactics.Count,
                TotalSubTechniques = result.Techniques.Sum(t => t.SubTechniques.Count),
                TechniquesByTactic = new Dictionary<string, int>(),
                ConfidenceByTactic = new Dictionary<string, double>(),
                MostCommonTechniques = new List<string>(),
                HighConfidenceTechniques = new List<string>()
            };
            
            // Techniques by tactic
            foreach (var tactic in result.Tactics)
            {
                stats.TechniquesByTactic[tactic.TacticName] = tactic.TechniqueCount;
                
                // Calculate average confidence for this tactic
                double totalConfidence = 0;
                int techniqueCount = 0;
                
                foreach (var techniqueId in tactic.TechniqueIds)
                {
                    if (result.Techniques.FirstOrDefault(t => t.TechniqueId == techniqueId) is TechniqueDto technique)
                    {
                        totalConfidence += technique.Confidence;
                        techniqueCount++;
                    }
                }
                
                stats.ConfidenceByTactic[tactic.TacticName] = techniqueCount > 0 
                    ? totalConfidence / techniqueCount 
                    : 0;
            }
            
            // Most common techniques
            stats.MostCommonTechniques = result.TechniqueFrequency
                .OrderByDescending(kvp => kvp.Value)
                .Take(5)
                .Select(kvp => kvp.Key)
                .ToList();
                
            // High confidence techniques
            stats.HighConfidenceTechniques = result.Techniques
                .Where(t => t.Confidence >= 0.8)
                .OrderByDescending(t => t.Confidence)
                .Take(5)
                .Select(t => t.TechniqueId)
                .ToList();
                
            // Overall threat score based on techniques and their severity
            double overallScore = 0;
            
            if (result.Techniques.Count > 0)
            {
                // Calculate weighted score based on technique count and confidence
                double totalWeight = 0;
                double weightedScore = 0;
                
                foreach (var technique in result.Techniques)
                {
                    double weight = technique.MatchCount * technique.Confidence;
                    totalWeight += weight;
                    
                    // Assign base score by tactic
                    double baseScore = 0;
                    foreach (var tactic in technique.Tactics)
                    {
                        baseScore += GetTacticSeverity(tactic);
                    }
                    
                    // Average if multiple tactics
                    if (technique.Tactics.Count > 0)
                    {
                        baseScore /= technique.Tactics.Count;
                    }
                    
                    weightedScore += baseScore * weight;
                }
                
                if (totalWeight > 0)
                {
                    overallScore = weightedScore / totalWeight;
                }
            }
            
            stats.OverallThreatScore = Math.Min(100, overallScore);
            
            return stats;
        }
        
        // Helper methods for MITRE ATT&CK data
        // In a real implementation, these would query a database or API
        
        private string GetTechniqueName(string techniqueId)
        {
            // This would normally look up the technique name from a database
            return $"Technique {techniqueId}";
        }
        
        private string GetTechniqueDescription(string techniqueId)
        {
            // This would normally look up the technique description from a database
            return $"Description for technique {techniqueId}";
        }
        
        private List<string> GetTacticsByTechnique(string techniqueId)
        {
            // This would normally look up the tactics for a technique from a database
            // For now, return some sample tactics
            var tacticIndex = Math.Abs(techniqueId.GetHashCode()) % TacticMap.Count;
            return new List<string> { TacticMap.ElementAt(tacticIndex).Value };
        }
        
        private string GetTacticId(string tacticName)
        {
            // This would normally look up the tactic ID from a database
            return tacticName.Replace(" ", "_").ToLowerInvariant();
        }
        
        private string GetTacticDescription(string tacticName)
        {
            // This would normally look up the tactic description from a database
            return $"Description for tactic {tacticName}";
        }
        
        private double GetTacticSeverity(string tacticName)
        {
            // Assign severity scores to tactics (0-100)
            return tacticName.ToLowerInvariant() switch
            {
                "initial access" => 70,
                "execution" => 80,
                "persistence" => 60,
                "privilege escalation" => 85,
                "defense evasion" => 75,
                "credential access" => 80,
                "discovery" => 40,
                "lateral movement" => 70,
                "collection" => 60,
                "command and control" => 85,
                "exfiltration" => 90,
                "impact" => 95,
                _ => 50
            };
        }
    }
}