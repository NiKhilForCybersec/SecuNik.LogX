using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SecuNik.LogX.Domain.Entities;
using SecuNik.LogX.Domain.Enums;

namespace SecuNik.LogX.API.Services
{
    public class MITREMapper
    {
        private readonly ILogger<MITREMapper> _logger;
        private readonly IConfiguration _configuration;
        private readonly IMemoryCache _cache;
        private readonly HttpClient _httpClient;
        private readonly Dictionary<string, MITRETechnique> _techniqueDatabase;
        private readonly Dictionary<string, List<string>> _tacticTechniques;
        private readonly Dictionary<string, ThreatGroup> _threatGroups;
        private readonly SemaphoreSlim _updateLock;
        private DateTime _lastUpdate;

        public MITREMapper(
            ILogger<MITREMapper> logger,
            IConfiguration configuration,
            IMemoryCache cache,
            HttpClient httpClient)
        {
            _logger = logger;
            _configuration = configuration;
            _cache = cache;
            _httpClient = httpClient;
            _updateLock = new SemaphoreSlim(1, 1);
            _techniqueDatabase = new Dictionary<string, MITRETechnique>();
            _tacticTechniques = new Dictionary<string, List<string>>();
            _threatGroups = new Dictionary<string, ThreatGroup>();
            
            // Initialize with built-in MITRE data
            _ = Task.Run(() => InitializeMITREDataAsync());
        }

        public async Task<List<MITRE>> MapTechniquesAsync(Analysis analysis, CancellationToken cancellationToken = default)
        {
            var techniques = new List<MITRE>();
            var mappingContext = new MappingContext
            {
                AnalysisId = analysis.Id,
                Content = analysis.Findings ?? "",
                IOCs = analysis.IOCs?.ToList() ?? new List<IOC>(),
                FileType = Path.GetExtension(analysis.SourceFile),
                ThreatLevel = analysis.ThreatLevel
            };

            // Ensure MITRE data is loaded
            await EnsureMITREDataLoadedAsync();

            // Map based on different evidence types
            var evidenceMappers = new[]
            {
                MapFromIOCs(mappingContext),
                MapFromBehaviors(mappingContext),
                MapFromArtifacts(mappingContext),
                MapFromFileOperations(mappingContext),
                MapFromNetworkActivity(mappingContext),
                MapFromPersistence(mappingContext),
                MapFromDefenseEvasion(mappingContext),
                MapFromCommandControl(mappingContext)
            };

            var allMappings = new Dictionary<string, MITRE>();

            foreach (var mapper in evidenceMappers)
            {
                var mappedTechniques = await mapper;
                foreach (var technique in mappedTechniques)
                {
                    if (allMappings.ContainsKey(technique.TechniqueId))
                    {
                        // Increase confidence for techniques found through multiple methods
                        allMappings[technique.TechniqueId].Confidence = 
                            Math.Min(100, allMappings[technique.TechniqueId].Confidence + 10);
                    }
                    else
                    {
                        allMappings[technique.TechniqueId] = technique;
                    }
                }
            }

            techniques = allMappings.Values.OrderByDescending(t => t.Confidence).ToList();

            // Add relationships between techniques
            await AddTechniqueRelationshipsAsync(techniques);

            _logger.LogInformation("Mapped {Count} MITRE techniques for analysis {AnalysisId}", 
                techniques.Count, analysis.Id);

            return techniques;
        }

        public async Task<List<string>> GetTechniquesByTacticAsync(string tactic, CancellationToken cancellationToken = default)
        {
            await EnsureMITREDataLoadedAsync();

            if (_tacticTechniques.TryGetValue(tactic.ToLower(), out var techniques))
            {
                return techniques;
            }

            return new List<string>();
        }

        public async Task<TTPAnalysis> AnalyzeTTPAsync(List<MITRE> techniques, CancellationToken cancellationToken = default)
        {
            var analysis = new TTPAnalysis
            {
                AnalysisDate = DateTime.UtcNow,
                TotalTechniques = techniques.Count,
                Tactics = new Dictionary<string, int>(),
                HighConfidenceTechniques = techniques.Where(t => t.Confidence >= 80).ToList(),
                AttackChains = new List<AttackChain>()
            };

            // Count techniques by tactic
            foreach (var technique in techniques)
            {
                if (!string.IsNullOrEmpty(technique.Tactic))
                {
                    if (analysis.Tactics.ContainsKey(technique.Tactic))
                        analysis.Tactics[technique.Tactic]++;
                    else
                        analysis.Tactics[technique.Tactic] = 1;
                }
            }

            // Identify potential attack chains
            analysis.AttackChains = await IdentifyAttackChainsAsync(techniques);

            // Calculate sophistication score
            analysis.SophisticationScore = CalculateSophisticationScore(techniques);

            return analysis;
        }

        public async Task<double> CalculateConfidenceAsync(MITRE technique, MappingContext context, CancellationToken cancellationToken = default)
        {
            var baseConfidence = 50.0;

            // Factor 1: Direct keyword matches
            var keywordScore = CalculateKeywordMatchScore(technique, context.Content);
            baseConfidence += keywordScore * 20;

            // Factor 2: IOC correlation
            var iocScore = CalculateIOCCorrelationScore(technique, context.IOCs);
            baseConfidence += iocScore * 15;

            // Factor 3: Behavioral patterns
            var behaviorScore = CalculateBehaviorScore(technique, context);
            baseConfidence += behaviorScore * 15;

            // Factor 4: Context relevance
            var contextScore = CalculateContextRelevance(technique, context);
            baseConfidence += contextScore * 10;

            // Apply confidence modifiers
            if (context.ThreatLevel == ThreatLevel.Critical)
                baseConfidence += 10;
            else if (context.ThreatLevel == ThreatLevel.Low)
                baseConfidence -= 10;

            return Math.Max(0, Math.Min(100, baseConfidence));
        }

        public async Task<bool> ValidateMappingAsync(MITRE technique, Analysis analysis, CancellationToken cancellationToken = default)
        {
            // Validate that the technique is applicable to the observed evidence
            if (string.IsNullOrEmpty(technique.TechniqueId) || string.IsNullOrEmpty(analysis.Findings))
                return false;

            // Check platform compatibility
            if (!string.IsNullOrEmpty(technique.Platform))
            {
                var platforms = technique.Platform.Split(',').Select(p => p.Trim().ToLower());
                var detectedPlatform = DetectPlatform(analysis.Findings);
                
                if (!platforms.Contains(detectedPlatform.ToLower()) && !platforms.Contains("all"))
                    return false;
            }

            // Validate minimum evidence requirements
            var requiredEvidence = GetRequiredEvidence(technique.TechniqueId);
            var hasRequiredEvidence = requiredEvidence.All(req => 
                analysis.Findings.Contains(req, StringComparison.OrdinalIgnoreCase));

            return hasRequiredEvidence;
        }

        public async Task<double> ScoreTechniqueMatch(MITRE technique, Evidence evidence, CancellationToken cancellationToken = default)
        {
            var score = 0.0;

            // Direct evidence match
            if (evidence.DirectIndicators.Any(i => IsDirectMatch(i, technique)))
                score += 40;

            // Behavioral match
            if (evidence.Behaviors.Any(b => IsBehaviorMatch(b, technique)))
                score += 30;

            // Artifact match
            if (evidence.Artifacts.Any(a => IsArtifactMatch(a, technique)))
                score += 20;

            // Context match
            if (IsContextualMatch(evidence.Context, technique))
                score += 10;

            return Math.Min(100, score);
        }

        public async Task<string> AnalyzeThreatContextAsync(List<MITRE> techniques, CancellationToken cancellationToken = default)
        {
            var context = new System.Text.StringBuilder();
            
            context.AppendLine("# MITRE ATT&CK Analysis Summary");
            context.AppendLine();
            
            // Tactic distribution
            var tacticGroups = techniques.GroupBy(t => t.Tactic).OrderBy(g => GetTacticOrder(g.Key));
            context.AppendLine("## Tactic Distribution:");
            foreach (var group in tacticGroups)
            {
                context.AppendLine($"- **{group.Key}**: {group.Count()} techniques");
            }
            context.AppendLine();

            // High confidence techniques
            var highConfidence = techniques.Where(t => t.Confidence >= 80).ToList();
            if (highConfidence.Any())
            {
                context.AppendLine("## High Confidence Techniques:");
                foreach (var tech in highConfidence.Take(5))
                {
                    context.AppendLine($"- **{tech.TechniqueId}** - {tech.Name} (Confidence: {tech.Confidence}%)");
                    context.AppendLine($"  - {tech.Description}");
                }
                context.AppendLine();
            }

            // Attack patterns
            var chains = await IdentifyAttackChainsAsync(techniques);
            if (chains.Any())
            {
                context.AppendLine("## Identified Attack Patterns:");
                foreach (var chain in chains.Take(3))
                {
                    context.AppendLine($"- **{chain.Name}**");
                    context.AppendLine($"  - Techniques: {string.Join(" → ", chain.Techniques.Select(t => t.TechniqueId))}");
                    context.AppendLine($"  - Confidence: {chain.Confidence}%");
                }
            }

            return context.ToString();
        }

        public async Task<List<MITRE>> GetRelatedTechniquesAsync(string techniqueId, CancellationToken cancellationToken = default)
        {
            await EnsureMITREDataLoadedAsync();

            var related = new List<MITRE>();
            
            if (!_techniqueDatabase.TryGetValue(techniqueId, out var technique))
                return related;

            // Find techniques in the same tactic
            var sameTactic = _techniqueDatabase.Values
                .Where(t => t.Tactic == technique.Tactic && t.TechniqueId != techniqueId)
                .Take(5)
                .Select(t => ConvertToMITRE(t, 70))
                .ToList();
            
            related.AddRange(sameTactic);

            // Find techniques commonly used together
            var commonlyUsedWith = GetCommonlyUsedTechniques(techniqueId);
            foreach (var relatedId in commonlyUsedWith)
            {
                if (_techniqueDatabase.TryGetValue(relatedId, out var relatedTech))
                {
                    related.Add(ConvertToMITRE(relatedTech, 80));
                }
            }

            return related.Distinct().Take(10).ToList();
        }

        public async Task<List<ThreatGroup>> MapToCampaignsAsync(List<MITRE> techniques, CancellationToken cancellationToken = default)
        {
            await EnsureMITREDataLoadedAsync();

            var groupScores = new Dictionary<string, double>();

            foreach (var group in _threatGroups.Values)
            {
                var score = 0.0;
                var matchedTechniques = 0;

                foreach (var technique in techniques)
                {
                    if (group.Techniques.Contains(technique.TechniqueId))
                    {
                        matchedTechniques++;
                        score += technique.Confidence;
                    }
                }

                if (matchedTechniques > 0)
                {
                    // Normalize score
                    var normalizedScore = (score / matchedTechniques) * (matchedTechniques / (double)group.Techniques.Count);
                    groupScores[group.Name] = normalizedScore;
                }
            }

            return groupScores
                .OrderByDescending(kvp => kvp.Value)
                .Take(5)
                .Select(kvp => _threatGroups[kvp.Key])
                .ToList();
        }

        public async Task<CorrelationResult> CorrelateEvidenceToTechniquesAsync(List<Evidence> evidence, CancellationToken cancellationToken = default)
        {
            var result = new CorrelationResult
            {
                Correlations = new List<EvidenceTechniqueCorrelation>(),
                ConfidenceScore = 0
            };

            foreach (var ev in evidence)
            {
                var matchedTechniques = new List<MITRE>();

                // Search for technique matches
                foreach (var technique in _techniqueDatabase.Values)
                {
                    var score = await ScoreTechniqueMatch(
                        ConvertToMITRE(technique, 0), 
                        ev, 
                        cancellationToken);

                    if (score > 50)
                    {
                        var mitre = ConvertToMITRE(technique, (int)score);
                        matchedTechniques.Add(mitre);
                    }
                }

                if (matchedTechniques.Any())
                {
                    result.Correlations.Add(new EvidenceTechniqueCorrelation
                    {
                        Evidence = ev,
                        Techniques = matchedTechniques.OrderByDescending(t => t.Confidence).ToList()
                    });
                }
            }

            // Calculate overall confidence
            if (result.Correlations.Any())
            {
                result.ConfidenceScore = result.Correlations
                    .SelectMany(c => c.Techniques)
                    .Average(t => t.Confidence);
            }

            return result;
        }

        public async Task<Timeline> GenerateTTPTimelineAsync(List<MITRE> techniques, List<IOC> iocs, CancellationToken cancellationToken = default)
        {
            var timeline = new Timeline
            {
                Events = new List<TimelineEvent>()
            };

            // Group techniques by tactic order
            var tacticOrder = new[] 
            { 
                "initial-access", "execution", "persistence", "privilege-escalation",
                "defense-evasion", "credential-access", "discovery", "lateral-movement",
                "collection", "command-and-control", "exfiltration", "impact"
            };

            var techniquesByTactic = techniques
                .GroupBy(t => t.Tactic?.ToLower() ?? "unknown")
                .ToDictionary(g => g.Key, g => g.ToList());

            var baseTime = DateTime.UtcNow.AddDays(-30); // Assume attack started 30 days ago
            var currentTime = baseTime;

            foreach (var tactic in tacticOrder)
            {
                if (techniquesByTactic.TryGetValue(tactic, out var tacticTechniques))
                {
                    foreach (var technique in tacticTechniques.OrderByDescending(t => t.Confidence))
                    {
                        timeline.Events.Add(new TimelineEvent
                        {
                            Timestamp = currentTime,
                            Type = "MITRE Technique",
                            TechniqueId = technique.TechniqueId,
                            Description = $"{technique.Name} - {technique.Description}",
                            Confidence = technique.Confidence,
                            RelatedIOCs = GetRelatedIOCs(technique, iocs)
                        });

                        currentTime = currentTime.AddHours(Random.Shared.Next(1, 24));
                    }

                    currentTime = currentTime.AddDays(Random.Shared.Next(1, 3));
                }
            }

            timeline.StartTime = baseTime;
            timeline.EndTime = currentTime;
            timeline.Duration = currentTime - baseTime;

            return timeline;
        }

        public async Task<List<ThreatGroup>> MapToThreatGroupsAsync(List<MITRE> techniques, CancellationToken cancellationToken = default)
        {
            var groupMatches = new Dictionary<string, GroupMatch>();

            foreach (var group in _threatGroups.Values)
            {
                var match = new GroupMatch
                {
                    Group = group,
                    MatchedTechniques = new List<string>(),
                    Score = 0
                };

                foreach (var technique in techniques)
                {
                    if (group.Techniques.Contains(technique.TechniqueId))
                    {
                        match.MatchedTechniques.Add(technique.TechniqueId);
                        match.Score += technique.Confidence;
                    }
                }

                if (match.MatchedTechniques.Any())
                {
                    match.MatchPercentage = (match.MatchedTechniques.Count / (double)group.Techniques.Count) * 100;
                    groupMatches[group.Name] = match;
                }
            }

            return groupMatches.Values
                .OrderByDescending(m => m.Score)
                .Take(5)
                .Select(m => m.Group)
                .ToList();
        }

        public async Task<AttributionAnalysis> AnalyzeAttributionAsync(List<MITRE> techniques, List<IOC> iocs, CancellationToken cancellationToken = default)
        {
            var analysis = new AttributionAnalysis
            {
                AnalysisDate = DateTime.UtcNow,
                PotentialGroups = await MapToThreatGroupsAsync(techniques, cancellationToken),
                ConfidenceFactors = new Dictionary<string, double>()
            };

            // Calculate confidence factors
            analysis.ConfidenceFactors["technique_coverage"] = 
                techniques.Count > 10 ? 0.8 : techniques.Count / 12.5;
            
            analysis.ConfidenceFactors["high_confidence_techniques"] = 
                techniques.Count(t => t.Confidence >= 80) / (double)techniques.Count;
            
            analysis.ConfidenceFactors["ioc_correlation"] = 
                iocs.Any(i => i.Enriched) ? 0.7 : 0.3;

            // Calculate overall attribution confidence
            analysis.AttributionConfidence = analysis.ConfidenceFactors.Values.Average() * 100;

            // Generate attribution summary
            if (analysis.PotentialGroups.Any())
            {
                var topGroup = analysis.PotentialGroups.First();
                analysis.Summary = $"Analysis suggests potential attribution to {topGroup.Name} " +
                    $"with {analysis.AttributionConfidence:F1}% confidence. " +
                    $"Based on {techniques.Count} identified techniques and {iocs.Count} IOCs.";
            }
            else
            {
                analysis.Summary = "Insufficient evidence for attribution to known threat groups.";
            }

            return analysis;
        }

        public async Task<List<Mitigation>> GetMitigationsAsync(List<MITRE> techniques, CancellationToken cancellationToken = default)
        {
            var mitigations = new List<Mitigation>();
            var addedMitigations = new HashSet<string>();

            foreach (var technique in techniques.OrderByDescending(t => t.Confidence))
            {
                var techniqueMitigations = GetMitigationsForTechnique(technique.TechniqueId);
                
                foreach (var mitigation in techniqueMitigations)
                {
                    if (!addedMitigations.Contains(mitigation.Id))
                    {
                        addedMitigations.Add(mitigation.Id);
                        mitigation.Priority = CalculateMitigationPriority(mitigation, technique);
                        mitigations.Add(mitigation);
                    }
                }
            }

            return mitigations.OrderByDescending(m => m.Priority).ToList();
        }

        public async Task<DefenseGapAnalysis> AnalyzeDefenseGapsAsync(List<MITRE> techniques, List<string> existingControls, CancellationToken cancellationToken = default)
        {
            var analysis = new DefenseGapAnalysis
            {
                AnalysisDate = DateTime.UtcNow,
                TotalTechniques = techniques.Count,
                Gaps = new List<DefenseGap>(),
                CoverageScore = 0
            };

            var coveredTechniques = 0;

            foreach (var technique in techniques)
            {
                var mitigations = GetMitigationsForTechnique(technique.TechniqueId);
                var implemented = mitigations.Where(m => existingControls.Contains(m.Id)).ToList();
                
                if (!implemented.Any())
                {
                    analysis.Gaps.Add(new DefenseGap
                    {
                        TechniqueId = technique.TechniqueId,
                        TechniqueName = technique.Name,
                        Impact = technique.Confidence,
                        RecommendedMitigations = mitigations.Take(3).ToList()
                    });
                }
                else
                {
                    coveredTechniques++;
                }
            }

            analysis.CoverageScore = (coveredTechniques / (double)techniques.Count) * 100;
            analysis.CriticalGaps = analysis.Gaps.Where(g => g.Impact >= 80).ToList();

            return analysis;
        }

        public async Task<KillChainMapping> MapToKillChainAsync(List<MITRE> techniques, CancellationToken cancellationToken = default)
        {
            var mapping = new KillChainMapping
            {
                Phases = new Dictionary<string, List<MITRE>>()
            };

            // Map MITRE tactics to kill chain phases
            var killChainMap = new Dictionary<string, string>
            {
                ["initial-access"] = "Delivery",
                ["execution"] = "Exploitation",
                ["persistence"] = "Installation",
                ["privilege-escalation"] = "Exploitation",
                ["defense-evasion"] = "Installation",
                ["credential-access"] = "Exploitation",
                ["discovery"] = "Reconnaissance",
                ["lateral-movement"] = "Exploitation",
                ["collection"] = "Actions on Objectives",
                ["command-and-control"] = "Command & Control",
                ["exfiltration"] = "Actions on Objectives",
                ["impact"] = "Actions on Objectives"
            };

            foreach (var technique in techniques)
            {
                var tactic = technique.Tactic?.ToLower() ?? "unknown";
                if (killChainMap.TryGetValue(tactic, out var phase))
                {
                    if (!mapping.Phases.ContainsKey(phase))
                        mapping.Phases[phase] = new List<MITRE>();
                    
                    mapping.Phases[phase].Add(technique);
                }
            }

            mapping.CompletedPhases = mapping.Phases.Keys.ToList();
            mapping.MissingPhases = new[] 
            { 
                "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
                "Installation", "Command & Control", "Actions on Objectives"
            }.Except(mapping.CompletedPhases).ToList();

            return mapping;
        }

        public async Task<PhaseProgression> AnalyzePhaseProgressionAsync(List<MITRE> techniques, Timeline timeline, CancellationToken cancellationToken = default)
        {
            var progression = new PhaseProgression
            {
                Phases = new List<AttackPhase>()
            };

            var killChainMapping = await MapToKillChainAsync(techniques, cancellationToken);
            var phaseOrder = new[] 
            { 
                "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
                "Installation", "Command & Control", "Actions on Objectives"
            };

            foreach (var phase in phaseOrder)
            {
                if (killChainMapping.Phases.TryGetValue(phase, out var phaseTechniques))
                {
                    var phaseEvents = timeline.Events
                        .Where(e => phaseTechniques.Any(t => t.TechniqueId == e.TechniqueId))
                        .OrderBy(e => e.Timestamp)
                        .ToList();

                    if (phaseEvents.Any())
                    {
                        progression.Phases.Add(new AttackPhase
                        {
                            Name = phase,
                            StartTime = phaseEvents.First().Timestamp,
                            EndTime = phaseEvents.Last().Timestamp,
                            Techniques = phaseTechniques,
                            Duration = phaseEvents.Last().Timestamp - phaseEvents.First().Timestamp,
                            Completed = true
                        });
                    }
                }
            }

            progression.CurrentPhase = progression.Phases.LastOrDefault()?.Name ?? "Unknown";
            progression.AttackMaturity = (progression.Phases.Count / (double)phaseOrder.Length) * 100;

            return progression;
        }

        public async Task<DetectionCoverage> AnalyzeDetectionCoverageAsync(List<MITRE> techniques, List<string> dataSources, CancellationToken cancellationToken = default)
        {
            var coverage = new DetectionCoverage
            {
                TotalTechniques = techniques.Count,
                CoveredTechniques = 0,
                DataSourceCoverage = new Dictionary<string, int>(),
                UncoveredTechniques = new List<MITRE>()
            };

            foreach (var technique in techniques)
            {
                var requiredDataSources = GetDataSourcesForTechnique(technique.TechniqueId);
                var hasRequiredSources = requiredDataSources.Any(ds => dataSources.Contains(ds));

                if (hasRequiredSources)
                {
                    coverage.CoveredTechniques++;
                    
                    foreach (var ds in requiredDataSources.Where(ds => dataSources.Contains(ds)))
                    {
                        if (coverage.DataSourceCoverage.ContainsKey(ds))
                            coverage.DataSourceCoverage[ds]++;
                        else
                            coverage.DataSourceCoverage[ds] = 1;
                    }
                }
                else
                {
                    coverage.UncoveredTechniques.Add(technique);
                }
            }

            coverage.CoveragePercentage = (coverage.CoveredTechniques / (double)coverage.TotalTechniques) * 100;
            coverage.RecommendedDataSources = GetRecommendedDataSources(coverage.UncoveredTechniques);

            return coverage;
        }

        public async Task<List<string>> GetDataSourcesAsync(MITRE technique, CancellationToken cancellationToken = default)
        {
            return GetDataSourcesForTechnique(technique.TechniqueId);
        }

        public async Task<List<MITRE>> FilterByPlatformAsync(List<MITRE> techniques, string platform, CancellationToken cancellationToken = default)
        {
            return techniques
                .Where(t => string.IsNullOrEmpty(t.Platform) || 
                           t.Platform.Contains(platform, StringComparison.OrdinalIgnoreCase) ||
                           t.Platform.Contains("All", StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        public async Task<PlatformCoverage> AnalyzePlatformCoverageAsync(List<MITRE> techniques, CancellationToken cancellationToken = default)
        {
            var coverage = new PlatformCoverage
            {
                Platforms = new Dictionary<string, List<MITRE>>()
            };

            var platforms = new[] { "Windows", "Linux", "macOS", "Cloud", "Network", "Mobile" };

            foreach (var platform in platforms)
            {
                var platformTechniques = await FilterByPlatformAsync(techniques, platform, cancellationToken);
                if (platformTechniques.Any())
                {
                    coverage.Platforms[platform] = platformTechniques;
                }
            }

            coverage.PrimaryPlatform = coverage.Platforms
                .OrderByDescending(kvp => kvp.Value.Count)
                .FirstOrDefault().Key ?? "Unknown";

            return coverage;
        }

        public async Task<bool> UpdateMITREDataAsync(CancellationToken cancellationToken = default)
        {
            await _updateLock.WaitAsync(cancellationToken);
            try
            {
                _logger.LogInformation("Updating MITRE ATT&CK data");

                // In production, this would fetch from MITRE's TAXII server or GitHub
                // For now, we'll use built-in data
                await InitializeMITREDataAsync();

                _lastUpdate = DateTime.UtcNow;
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update MITRE data");
                return false;
            }
            finally
            {
                _updateLock.Release();
            }
        }

        public async Task<bool> ValidateFrameworkAsync(CancellationToken cancellationToken = default)
        {
            await EnsureMITREDataLoadedAsync();
            
            // Validate that we have techniques for all tactics
            var requiredTactics = new[] 
            { 
                "initial-access", "execution", "persistence", "privilege-escalation",
                "defense-evasion", "credential-access", "discovery", "lateral-movement",
                "collection", "command-and-control", "exfiltration", "impact"
            };

            foreach (var tactic in requiredTactics)
            {
                if (!_tacticTechniques.ContainsKey(tactic) || !_tacticTechniques[tactic].Any())
                {
                    _logger.LogWarning("Missing techniques for tactic: {Tactic}", tactic);
                    return false;
                }
            }

            return _techniqueDatabase.Count > 100; // Should have at least 100 techniques
        }

        public async Task<bool> SyncTechniquesAsync(CancellationToken cancellationToken = default)
        {
            return await UpdateMITREDataAsync(cancellationToken);
        }

        // Private helper methods
        private async Task InitializeMITREDataAsync()
        {
            // Initialize with common MITRE techniques
            // In production, this would load from a database or API
            
            var techniques = GetBuiltInTechniques();
            foreach (var technique in techniques)
            {
                _techniqueDatabase[technique.TechniqueId] = technique;
                
                var tactic = technique.Tactic.ToLower();
                if (!_tacticTechniques.ContainsKey(tactic))
                    _tacticTechniques[tactic] = new List<string>();
                
                _tacticTechniques[tactic].Add(technique.TechniqueId);
            }

            // Initialize threat groups
            var groups = GetBuiltInThreatGroups();
            foreach (var group in groups)
            {
                _threatGroups[group.Name] = group;
            }

            _lastUpdate = DateTime.UtcNow;
        }

        private async Task EnsureMITREDataLoadedAsync()
        {
            if (!_techniqueDatabase.Any() || DateTime.UtcNow - _lastUpdate > TimeSpan.FromDays(7))
            {
                await UpdateMITREDataAsync();
            }
        }

        private List<MITRETechnique> GetBuiltInTechniques()
        {
            return new List<MITRETechnique>
            {
                // Initial Access
                new MITRETechnique
                {
                    TechniqueId = "T1566",
                    Name = "Phishing",
                    Description = "Adversaries may send phishing messages to gain access to victim systems",
                    Tactic = "initial-access",
                    Platform = "Windows,macOS,Linux",
                    DataSources = new[] { "Email Gateway", "Mail Server", "Network Traffic" }
                },
                new MITRETechnique
                {
                    TechniqueId = "T1078",
                    Name = "Valid Accounts",
                    Description = "Adversaries may obtain and abuse credentials of existing accounts",
                    Tactic = "initial-access",
                    Platform = "All",
                    DataSources = new[] { "Authentication Logs", "Process Monitoring" }
                },
                
                // Execution
                new MITRETechnique
                {
                    TechniqueId = "T1059",
                    Name = "Command and Scripting Interpreter",
                    Description = "Adversaries may abuse command and script interpreters to execute commands",
                    Tactic = "execution",
                    Platform = "All",
                    DataSources = new[] { "Command Execution", "Process Monitoring", "Script Logs" }
                },
                new MITRETechnique
                {
                    TechniqueId = "T1053",
                    Name = "Scheduled Task/Job",
                    Description = "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution",
                    Tactic = "execution",
                    Platform = "Windows,Linux,macOS",
                    DataSources = new[] { "File Monitoring", "Process Monitoring", "Windows Event Logs" }
                },
                
                // Persistence
                new MITRETechnique
                {
                    TechniqueId = "T1547",
                    Name = "Boot or Logon Autostart Execution",
                    Description = "Adversaries may configure system settings to automatically execute a program during system boot or logon",
                    Tactic = "persistence",
                    Platform = "Windows,Linux,macOS",
                    DataSources = new[] { "Registry Monitoring", "File Monitoring", "Process Monitoring" }
                },
                new MITRETechnique
                {
                    TechniqueId = "T1136",
                    Name = "Create Account",
                    Description = "Adversaries may create an account to maintain access to victim systems",
                    Tactic = "persistence",
                    Platform = "All",
                    DataSources = new[] { "Authentication Logs", "Windows Event Logs", "Command Execution" }
                },
                
                // Privilege Escalation
                new MITRETechnique
                {
                    TechniqueId = "T1548",
                    Name = "Abuse Elevation Control Mechanism",
                    Description = "Adversaries may circumvent mechanisms designed to control elevate privileges",
                    Tactic = "privilege-escalation",
                    Platform = "Windows,Linux,macOS",
                    DataSources = new[] { "Process Monitoring", "Windows Event Logs", "API Monitoring" }
                },
                
                // Defense Evasion
                new MITRETechnique
                {
                    TechniqueId = "T1070",
                    Name = "Indicator Removal on Host",
                    Description = "Adversaries may delete or alter generated artifacts on a host system",
                    Tactic = "defense-evasion",
                    Platform = "All",
                    DataSources = new[] { "File Monitoring", "Process Monitoring", "Windows Event Logs" }
                },
                new MITRETechnique
                {
                    TechniqueId = "T1027",
                    Name = "Obfuscated Files or Information",
                    Description = "Adversaries may attempt to make an executable or file difficult to discover or analyze",
                    Tactic = "defense-evasion",
                    Platform = "All",
                    DataSources = new[] { "File Monitoring", "Process Monitoring", "Network Traffic" }
                },
                
                // Discovery
                new MITRETechnique
                {
                    TechniqueId = "T1057",
                    Name = "Process Discovery",
                    Description = "Adversaries may attempt to get information about running processes",
                    Tactic = "discovery",
                    Platform = "All",
                    DataSources = new[] { "Process Monitoring", "Command Execution" }
                },
                new MITRETechnique
                {
                    TechniqueId = "T1083",
                    Name = "File and Directory Discovery",
                    Description = "Adversaries may enumerate files and directories",
                    Tactic = "discovery",
                    Platform = "All",
                    DataSources = new[] { "File Monitoring", "Process Monitoring", "Command Execution" }
                },
                
                // Lateral Movement
                new MITRETechnique
                {
                    TechniqueId = "T1021",
                    Name = "Remote Services",
                    Description = "Adversaries may use valid accounts to log into a service specifically designed to accept remote connections",
                    Tactic = "lateral-movement",
                    Platform = "All",
                    DataSources = new[] { "Authentication Logs", "Network Traffic", "Process Monitoring" }
                },
                
                // Collection
                new MITRETechnique
                {
                    TechniqueId = "T1005",
                    Name = "Data from Local System",
                    Description = "Adversaries may search local system sources to find files of interest",
                    Tactic = "collection",
                    Platform = "All",
                    DataSources = new[] { "File Monitoring", "Process Monitoring", "Command Execution" }
                },
                
                // Command and Control
                new MITRETechnique
                {
                    TechniqueId = "T1071",
                    Name = "Application Layer Protocol",
                    Description = "Adversaries may communicate using application layer protocols",
                    Tactic = "command-and-control",
                    Platform = "All",
                    DataSources = new[] { "Network Traffic", "DNS Logs", "Web Proxy" }
                },
                
                // Exfiltration
                new MITRETechnique
                {
                    TechniqueId = "T1041",
                    Name = "Exfiltration Over C2 Channel",
                    Description = "Adversaries may steal data by exfiltrating it over an existing command and control channel",
                    Tactic = "exfiltration",
                    Platform = "All",
                    DataSources = new[] { "Network Traffic", "Process Monitoring", "File Monitoring" }
                },
                
                // Impact
                new MITRETechnique
                {
                    TechniqueId = "T1486",
                    Name = "Data Encrypted for Impact",
                    Description = "Adversaries may encrypt data on target systems to interrupt availability",
                    Tactic = "impact",
                    Platform = "All",
                    DataSources = new[] { "File Monitoring", "Process Monitoring", "Kernel Drivers" }
                }
            };
        }

        private List<ThreatGroup> GetBuiltInThreatGroups()
        {
            return new List<ThreatGroup>
            {
                new ThreatGroup
                {
                    Name = "APT28",
                    Aliases = new[] { "Fancy Bear", "Sofacy", "Sednit" },
                    Description = "Russian threat group attributed to GRU",
                    Techniques = new List<string> { "T1566", "T1078", "T1059", "T1053", "T1547", "T1021", "T1071" }
                },
                new ThreatGroup
                {
                    Name = "APT29",
                    Aliases = new[] { "Cozy Bear", "The Dukes" },
                    Description = "Russian threat group attributed to SVR",
                    Techniques = new List<string> { "T1078", "T1059", "T1070", "T1027", "T1021", "T1071", "T1041" }
                },
                new ThreatGroup
                {
                    Name = "Lazarus Group",
                    Aliases = new[] { "Hidden Cobra", "Guardians of Peace" },
                    Description = "North Korean threat group",
                    Techniques = new List<string> { "T1566", "T1059", "T1053", "T1070", "T1486", "T1041" }
                }
            };
        }

        private async Task<List<MITRE>> MapFromIOCs(MappingContext context)
        {
            var techniques = new List<MITRE>();

            foreach (var ioc in context.IOCs)
            {
                switch (ioc.Type.ToLower())
                {
                    case "domain":
                    case "url":
                        if (ioc.Tags?.Contains("suspicious_url") == true)
                        {
                            techniques.Add(CreateMITRE("T1566", "Phishing", "initial-access", 70));
                            techniques.Add(CreateMITRE("T1071", "Application Layer Protocol", "command-and-control", 65));
                        }
                        break;

                    case "file_path":
                        if (ioc.Value.Contains("\\AppData\\") || ioc.Value.Contains("/tmp/"))
                        {
                            techniques.Add(CreateMITRE("T1059", "Command and Scripting Interpreter", "execution", 75));
                            techniques.Add(CreateMITRE("T1027", "Obfuscated Files or Information", "defense-evasion", 60));
                        }
                        break;

                    case "registry_key":
                        if (ioc.Tags?.Contains("suspicious_registry") == true)
                        {
                            techniques.Add(CreateMITRE("T1547", "Boot or Logon Autostart Execution", "persistence", 80));
                            techniques.Add(CreateMITRE("T1112", "Modify Registry", "defense-evasion", 75));
                        }
                        break;

                    case "md5":
                    case "sha1":
                    case "sha256":
                        techniques.Add(CreateMITRE("T1204", "User Execution", "execution", 60));
                        break;
                }
            }

            return techniques;
        }

        private async Task<List<MITRE>> MapFromBehaviors(MappingContext context)
        {
            var techniques = new List<MITRE>();
            var contentLower = context.Content.ToLower();

            // Process creation patterns
            if (Regex.IsMatch(contentLower, @"(cmd\.exe|powershell\.exe|bash|sh)\s+[/-]"))
            {
                techniques.Add(CreateMITRE("T1059", "Command and Scripting Interpreter", "execution", 85));
            }

            // Network connections
            if (Regex.IsMatch(contentLower, @"(established|listening|syn_sent)\s+\d+\.\d+\.\d+\.\d+"))
            {
                techniques.Add(CreateMITRE("T1071", "Application Layer Protocol", "command-and-control", 70));
            }

            // File operations
            if (contentLower.Contains("delete") && contentLower.Contains("log"))
            {
                techniques.Add(CreateMITRE("T1070", "Indicator Removal on Host", "defense-evasion", 80));
            }

            // Account operations
            if (Regex.IsMatch(contentLower, @"(useradd|net user|new-localuser)"))
            {
                techniques.Add(CreateMITRE("T1136", "Create Account", "persistence", 85));
            }

            return techniques;
        }

        private async Task<List<MITRE>> MapFromArtifacts(MappingContext context)
        {
            var techniques = new List<MITRE>();

            // File type specific mappings
            switch (context.FileType?.ToLower())
            {
                case ".exe":
                case ".dll":
                    techniques.Add(CreateMITRE("T1204", "User Execution", "execution", 70));
                    techniques.Add(CreateMITRE("T1055", "Process Injection", "defense-evasion", 65));
                    break;

                case ".ps1":
                    techniques.Add(CreateMITRE("T1059.001", "PowerShell", "execution", 90));
                    break;

                case ".bat":
                case ".cmd":
                    techniques.Add(CreateMITRE("T1059.003", "Windows Command Shell", "execution", 85));
                    break;

                case ".vbs":
                case ".js":
                    techniques.Add(CreateMITRE("T1059.005", "Visual Basic", "execution", 80));
                    break;
            }

            return techniques;
        }

        private async Task<List<MITRE>> MapFromFileOperations(MappingContext context)
        {
            var techniques = new List<MITRE>();
            var content = context.Content.ToLower();

            if (content.Contains("encrypted") || content.Contains("ransom"))
            {
                techniques.Add(CreateMITRE("T1486", "Data Encrypted for Impact", "impact", 90));
            }

            if (Regex.IsMatch(content, @"copy\s+.*\s+(\\\\|smb:|admin\$)"))
            {
                techniques.Add(CreateMITRE("T1021", "Remote Services", "lateral-movement", 75));
            }

            return techniques;
        }

        private async Task<List<MITRE>> MapFromNetworkActivity(MappingContext context)
        {
            var techniques = new List<MITRE>();
            var content = context.Content.ToLower();

            if (content.Contains("dns") && (content.Contains("tunnel") || content.Contains("exfil")))
            {
                techniques.Add(CreateMITRE("T1071.004", "DNS", "command-and-control", 80));
            }

            if (Regex.IsMatch(content, @"port\s*(443|8443|8080)"))
            {
                techniques.Add(CreateMITRE("T1071.001", "Web Protocols", "command-and-control", 75));
            }

            return techniques;
        }

        private async Task<List<MITRE>> MapFromPersistence(MappingContext context)
        {
            var techniques = new List<MITRE>();
            var content = context.Content.ToLower();

            if (content.Contains("scheduled task") || content.Contains("crontab"))
            {
                techniques.Add(CreateMITRE("T1053", "Scheduled Task/Job", "persistence", 85));
            }

            if (content.Contains("service") && (content.Contains("create") || content.Contains("install")))
            {
                techniques.Add(CreateMITRE("T1543", "Create or Modify System Process", "persistence", 80));
            }

            return techniques;
        }

        private async Task<List<MITRE>> MapFromDefenseEvasion(MappingContext context)
        {
            var techniques = new List<MITRE>();
            var content = context.Content.ToLower();

            if (content.Contains("base64") || content.Contains("encoded"))
            {
                techniques.Add(CreateMITRE("T1027", "Obfuscated Files or Information", "defense-evasion", 75));
            }

            if (content.Contains("disable") && (content.Contains("defender") || content.Contains("antivirus")))
            {
                techniques.Add(CreateMITRE("T1562", "Impair Defenses", "defense-evasion", 85));
            }

            return techniques;
        }

        private async Task<List<MITRE>> MapFromCommandControl(MappingContext context)
        {
            var techniques = new List<MITRE>();
            var content = context.Content.ToLower();

            if (Regex.IsMatch(content, @"(beacon|heartbeat|keepalive|callback)"))
            {
                techniques.Add(CreateMITRE("T1071", "Application Layer Protocol", "command-and-control", 70));
            }

            if (content.Contains("proxy") || content.Contains("tunnel"))
            {
                techniques.Add(CreateMITRE("T1090", "Proxy", "command-and-control", 75));
            }

            return techniques;
        }

        private MITRE CreateMITRE(string techniqueId, string name, string tactic, int confidence)
        {
            var technique = _techniqueDatabase.GetValueOrDefault(techniqueId);
            
            return new MITRE
            {
                Id = Guid.NewGuid(),
                TechniqueId = techniqueId,
                Name = name,
                Tactic = tactic,
                Description = technique?.Description ?? $"{name} technique detected",
                Confidence = confidence,
                Platform = technique?.Platform ?? "All",
                CreatedAt = DateTime.UtcNow
            };
        }

        private MITRE ConvertToMITRE(MITRETechnique technique, int confidence)
        {
            return new MITRE
            {
                Id = Guid.NewGuid(),
                TechniqueId = technique.TechniqueId,
                Name = technique.Name,
                Description = technique.Description,
                Tactic = technique.Tactic,
                Platform = technique.Platform,
                Confidence = confidence,
                CreatedAt = DateTime.UtcNow
            };
        }

        private async Task AddTechniqueRelationshipsAsync(List<MITRE> techniques)
        {
            // Add relationships based on common attack patterns
            var relationships = new Dictionary<string, List<string>>
            {
                ["T1566"] = new[] { "T1059", "T1204" }.ToList(), // Phishing often leads to execution
                ["T1078"] = new[] { "T1021", "T1136" }.ToList(), // Valid accounts used for lateral movement
                ["T1059"] = new[] { "T1055", "T1070" }.ToList(), // Scripts used for injection and cleanup
                ["T1053"] = new[] { "T1059", "T1070" }.ToList(), // Scheduled tasks run scripts
            };

            foreach (var technique in techniques)
            {
                if (relationships.TryGetValue(technique.TechniqueId, out var related))
                {
                    var relatedTechniques = techniques
                        .Where(t => related.Contains(t.TechniqueId))
                        .Select(t => t.TechniqueId)
                        .ToList();

                    if (relatedTechniques.Any())
                    {
                        technique.Metadata = technique.Metadata ?? new Dictionary<string, object>();
                        technique.Metadata["related_techniques"] = relatedTechniques;
                    }
                }
            }
        }

        private double CalculateKeywordMatchScore(MITRE technique, string content)
        {
            var keywords = GetTechniqueKeywords(technique.TechniqueId);
            var matches = 0;
            var contentLower = content.ToLower();

            foreach (var keyword in keywords)
            {
                if (contentLower.Contains(keyword.ToLower()))
                    matches++;
            }

            return matches > 0 ? Math.Min(1.0, matches / (double)keywords.Count) : 0;
        }

        private double CalculateIOCCorrelationScore(MITRE technique, List<IOC> iocs)
        {
            var techniqueIOCTypes = GetExpectedIOCTypes(technique.TechniqueId);
            var matchingIOCs = iocs.Where(i => techniqueIOCTypes.Contains(i.Type.ToLower())).Count();

            return matchingIOCs > 0 ? Math.Min(1.0, matchingIOCs / 5.0) : 0;
        }

        private double CalculateBehaviorScore(MITRE technique, MappingContext context)
        {
            var behaviorPatterns = GetBehaviorPatterns(technique.TechniqueId);
            var score = 0.0;

            foreach (var pattern in behaviorPatterns)
            {
                if (Regex.IsMatch(context.Content, pattern, RegexOptions.IgnoreCase))
                {
                    score += 0.2;
                }
            }

            return Math.Min(1.0, score);
        }

        private double CalculateContextRelevance(MITRE technique, MappingContext context)
        {
            // Higher threat levels increase relevance of certain techniques
            if (context.ThreatLevel >= ThreatLevel.High)
            {
                var highThreatTechniques = new[] { "T1486", "T1490", "T1489", "T1491" };
                if (highThreatTechniques.Contains(technique.TechniqueId))
                    return 1.0;
            }

            return 0.5; // Default relevance
        }

        private string DetectPlatform(string content)
        {
            var contentLower = content.ToLower();

            if (contentLower.Contains("windows") || contentLower.Contains("win32") || 
                contentLower.Contains("registry") || contentLower.Contains(".exe"))
                return "Windows";

            if (contentLower.Contains("linux") || contentLower.Contains("/etc/") || 
                contentLower.Contains("/var/") || contentLower.Contains("bash"))
                return "Linux";

            if (contentLower.Contains("macos") || contentLower.Contains("darwin") || 
                contentLower.Contains("/library/"))
                return "macOS";

            return "Unknown";
        }

        private List<string> GetRequiredEvidence(string techniqueId)
        {
            var evidenceMap = new Dictionary<string, List<string>>
            {
                ["T1059"] = new List<string> { "cmd", "powershell", "script", "command" },
                ["T1070"] = new List<string> { "delete", "remove", "clear", "log" },
                ["T1486"] = new List<string> { "encrypt", "ransom", "locked", "decrypt" }
            };

            return evidenceMap.GetValueOrDefault(techniqueId, new List<string>());
        }

        private List<string> GetCommonlyUsedTechniques(string techniqueId)
        {
            var commonPairs = new Dictionary<string, List<string>>
            {
                ["T1566"] = new List<string> { "T1059", "T1204", "T1027" },
                ["T1059"] = new List<string> { "T1055", "T1070", "T1105" },
                ["T1078"] = new List<string> { "T1021", "T1136", "T1098" }
            };

            return commonPairs.GetValueOrDefault(techniqueId, new List<string>());
        }

        private async Task<List<AttackChain>> IdentifyAttackChainsAsync(List<MITRE> techniques)
        {
            var chains = new List<AttackChain>();

            // Common attack chains
            var chainPatterns = new[]
            {
                new AttackChain
                {
                    Name = "Phishing to Ransomware",
                    RequiredTechniques = new[] { "T1566", "T1059", "T1486" },
                    Description = "Email phishing leading to script execution and ransomware deployment"
                },
                new AttackChain
                {
                    Name = "Credential Theft and Lateral Movement",
                    RequiredTechniques = new[] { "T1078", "T1021", "T1136" },
                    Description = "Using stolen credentials for lateral movement and persistence"
                },
                new AttackChain
                {
                    Name = "Living off the Land",
                    RequiredTechniques = new[] { "T1059", "T1055", "T1070" },
                    Description = "Using built-in tools for execution, injection, and covering tracks"
                }
            };

            var techniqueIds = techniques.Select(t => t.TechniqueId).ToHashSet();

            foreach (var pattern in chainPatterns)
            {
                var matchCount = pattern.RequiredTechniques.Count(rt => techniqueIds.Contains(rt));
                if (matchCount >= 2) // At least 2 out of 3 techniques
                {
                    var chain = new AttackChain
                    {
                        Name = pattern.Name,
                        Description = pattern.Description,
                        Techniques = techniques.Where(t => pattern.RequiredTechniques.Contains(t.TechniqueId)).ToList(),
                        Confidence = (matchCount / (double)pattern.RequiredTechniques.Length) * 100
                    };
                    chains.Add(chain);
                }
            }

            return chains;
        }

        private double CalculateSophisticationScore(List<MITRE> techniques)
        {
            var score = 0.0;

            // Factors that increase sophistication
            var advancedTechniques = new[] { "T1055", "T1014", "T1068", "T1574", "T1562" };
            score += techniques.Count(t => advancedTechniques.Contains(t.TechniqueId)) * 10;

            // Multiple tactics indicate sophistication
            var uniqueTactics = techniques.Select(t => t.Tactic).Distinct().Count();
            score += uniqueTactics * 5;

            // High confidence techniques
            score += techniques.Count(t => t.Confidence >= 80) * 3;

            return Math.Min(100, score);
        }

        private int GetTacticOrder(string tactic)
        {
            var order = new Dictionary<string, int>
            {
                ["initial-access"] = 1,
                ["execution"] = 2,
                ["persistence"] = 3,
                ["privilege-escalation"] = 4,
                ["defense-evasion"] = 5,
                ["credential-access"] = 6,
                ["discovery"] = 7,
                ["lateral-movement"] = 8,
                ["collection"] = 9,
                ["command-and-control"] = 10,
                ["exfiltration"] = 11,
                ["impact"] = 12
            };

            return order.GetValueOrDefault(tactic?.ToLower() ?? "", 99);
        }

        private List<IOC> GetRelatedIOCs(MITRE technique, List<IOC> iocs)
        {
            var relatedTypes = GetExpectedIOCTypes(technique.TechniqueId);
            return iocs.Where(i => relatedTypes.Contains(i.Type.ToLower())).ToList();
        }

        private List<Mitigation> GetMitigationsForTechnique(string techniqueId)
        {
            // Common mitigations mapped to techniques
            var mitigationMap = new Dictionary<string, List<Mitigation>>
            {
                ["T1566"] = new List<Mitigation>
                {
                    new Mitigation { Id = "M1049", Name = "Antivirus/Antimalware", Description = "Use signatures or behavior to detect malicious email attachments" },
                    new Mitigation { Id = "M1031", Name = "Network Intrusion Prevention", Description = "Network intrusion prevention systems to identify and prevent phishing" },
                    new Mitigation { Id = "M1017", Name = "User Training", Description = "Train users to identify phishing emails" }
                },
                ["T1059"] = new List<Mitigation>
                {
                    new Mitigation { Id = "M1038", Name = "Execution Prevention", Description = "Block execution of code on a system" },
                    new Mitigation { Id = "M1026", Name = "Privileged Account Management", Description = "Restrict privileges of accounts that can run scripts" }
                },
                ["T1070"] = new List<Mitigation>
                {
                    new Mitigation { Id = "M1022", Name = "Restrict File and Directory Permissions", Description = "Restrict access to log files" },
                    new Mitigation { Id = "M1029", Name = "Remote Data Storage", Description = "Automatically forward logs to a central server" }
                }
            };

            return mitigationMap.GetValueOrDefault(techniqueId, new List<Mitigation>());
        }

        private int CalculateMitigationPriority(Mitigation mitigation, MITRE technique)
        {
            // Base priority on technique confidence and criticality
            var priority = technique.Confidence;

            // Boost priority for certain critical mitigations
            if (mitigation.Id == "M1049" || mitigation.Id == "M1038") // AV or Execution Prevention
                priority += 20;

            return Math.Min(100, priority);
        }

        private List<string> GetDataSourcesForTechnique(string techniqueId)
        {
            if (_techniqueDatabase.TryGetValue(techniqueId, out var technique))
            {
                return technique.DataSources?.ToList() ?? new List<string>();
            }

            return new List<string>();
        }

        private List<string> GetRecommendedDataSources(List<MITRE> uncoveredTechniques)
        {
            var dataSources = new Dictionary<string, int>();

            foreach (var technique in uncoveredTechniques)
            {
                var sources = GetDataSourcesForTechnique(technique.TechniqueId);
                foreach (var source in sources)
                {
                    if (dataSources.ContainsKey(source))
                        dataSources[source]++;
                    else
                        dataSources[source] = 1;
                }
            }

            return dataSources
                .OrderByDescending(kvp => kvp.Value)
                .Take(5)
                .Select(kvp => kvp.Key)
                .ToList();
        }

        private bool IsDirectMatch(string indicator, MITRE technique)
        {
            var techniqueIndicators = GetTechniqueKeywords(technique.TechniqueId);
            return techniqueIndicators.Any(ti => indicator.Contains(ti, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsBehaviorMatch(string behavior, MITRE technique)
        {
            var behaviorPatterns = GetBehaviorPatterns(technique.TechniqueId);
            return behaviorPatterns.Any(pattern => Regex.IsMatch(behavior, pattern, RegexOptions.IgnoreCase));
        }

        private bool IsArtifactMatch(string artifact, MITRE technique)
        {
            var artifactTypes = GetExpectedArtifacts(technique.TechniqueId);
            return artifactTypes.Any(at => artifact.Contains(at, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsContextualMatch(string context, MITRE technique)
        {
            // Simple contextual matching based on technique characteristics
            return !string.IsNullOrEmpty(context) && context.Length > 50;
        }

        private List<string> GetTechniqueKeywords(string techniqueId)
        {
            var keywordMap = new Dictionary<string, List<string>>
            {
                ["T1566"] = new List<string> { "phish", "email", "attachment", "malicious link" },
                ["T1059"] = new List<string> { "powershell", "cmd", "script", "command line", "bash" },
                ["T1070"] = new List<string> { "delete", "clear", "remove", "log", "event", "artifact" },
                ["T1486"] = new List<string> { "encrypt", "ransom", "decrypt", "locked", "payment" }
            };

            return keywordMap.GetValueOrDefault(techniqueId, new List<string>());
        }

        private List<string> GetExpectedIOCTypes(string techniqueId)
        {
            var iocTypeMap = new Dictionary<string, List<string>>
            {
                ["T1566"] = new List<string> { "email", "domain", "url", "md5", "sha256" },
                ["T1071"] = new List<string> { "domain", "url", "ipv4", "ipv6" },
                ["T1486"] = new List<string> { "bitcoin_address", "email", "domain" }
            };

            return iocTypeMap.GetValueOrDefault(techniqueId, new List<string>());
        }

        private List<string> GetBehaviorPatterns(string techniqueId)
        {
            var patternMap = new Dictionary<string, List<string>>
            {
                ["T1059"] = new List<string> 
                { 
                    @"powershell.*-enc", 
                    @"cmd.*\/c", 
                    @"bash.*-c",
                    @"wscript.*\.vbs"
                },
                ["T1070"] = new List<string> 
                { 
                    @"del.*\.log", 
                    @"wevtutil.*cl", 
                    @"Clear-EventLog",
                    @"rm.*\/var\/log"
                }
            };

            return patternMap.GetValueOrDefault(techniqueId, new List<string>());
        }

        private List<string> GetExpectedArtifacts(string techniqueId)
        {
            var artifactMap = new Dictionary<string, List<string>>
            {
                ["T1059"] = new List<string> { ".ps1", ".bat", ".cmd", ".vbs", ".js" },
                ["T1486"] = new List<string> { ".encrypted", ".locked", "readme.txt", "decrypt_instructions" }
            };

            return artifactMap.GetValueOrDefault(techniqueId, new List<string>());
        }
    }

    // Supporting classes
    public class MappingContext
    {
        public Guid AnalysisId { get; set; }
        public string Content { get; set; }
        public List<IOC> IOCs { get; set; }
        public string FileType { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
    }

    public class MITRETechnique
    {
        public string TechniqueId { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string Tactic { get; set; }
        public string Platform { get; set; }
        public string[] DataSources { get; set; }
    }

    public class ThreatGroup
    {
        public string Name { get; set; }
        public string[] Aliases { get; set; }
        public string Description { get; set; }
        public List<string> Techniques { get; set; }
    }

    public class TTPAnalysis
    {
        public DateTime AnalysisDate { get; set; }
        public int TotalTechniques { get; set; }
        public Dictionary<string, int> Tactics { get; set; }
        public List<MITRE> HighConfidenceTechniques { get; set; }
        public List<AttackChain> AttackChains { get; set; }
        public double SophisticationScore { get; set; }
    }

    public class AttackChain
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public List<MITRE> Techniques { get; set; }
        public double Confidence { get; set; }
        public string[] RequiredTechniques { get; set; }
    }

    public class Evidence
    {
        public List<string> DirectIndicators { get; set; }
        public List<string> Behaviors { get; set; }
        public List<string> Artifacts { get; set; }
        public string Context { get; set; }
    }

    public class CorrelationResult
    {
        public List<EvidenceTechniqueCorrelation> Correlations { get; set; }
        public double ConfidenceScore { get; set; }
    }

    public class EvidenceTechniqueCorrelation
    {
        public Evidence Evidence { get; set; }
        public List<MITRE> Techniques { get; set; }
    }

    public class Timeline
    {
        public List<TimelineEvent> Events { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
    }

    public class TimelineEvent
    {
        public DateTime Timestamp { get; set; }
        public string Type { get; set; }
        public string TechniqueId { get; set; }
        public string Description { get; set; }
        public int Confidence { get; set; }
        public List<IOC> RelatedIOCs { get; set; }
    }

    public class GroupMatch
    {
        public ThreatGroup Group { get; set; }
        public List<string> MatchedTechniques { get; set; }
        public double Score { get; set; }
        public double MatchPercentage { get; set; }
    }

    public class AttributionAnalysis
    {
        public DateTime AnalysisDate { get; set; }
        public List<ThreatGroup> PotentialGroups { get; set; }
        public Dictionary<string, double> ConfidenceFactors { get; set; }
        public double AttributionConfidence { get; set; }
        public string Summary { get; set; }
    }

    public class Mitigation
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public int Priority { get; set; }
    }

    public class DefenseGapAnalysis
    {
        public DateTime AnalysisDate { get; set; }
        public int TotalTechniques { get; set; }
        public List<DefenseGap> Gaps { get; set; }
        public List<DefenseGap> CriticalGaps { get; set; }
        public double CoverageScore { get; set; }
    }

    public class DefenseGap
    {
        public string TechniqueId { get; set; }
        public string TechniqueName { get; set; }
        public int Impact { get; set; }
        public List<Mitigation> RecommendedMitigations { get; set; }
    }

    public class KillChainMapping
    {
        public Dictionary<string, List<MITRE>> Phases { get; set; }
        public List<string> CompletedPhases { get; set; }
        public List<string> MissingPhases { get; set; }
    }

    public class PhaseProgression
    {
        public List<AttackPhase> Phases { get; set; }
        public string CurrentPhase { get; set; }
        public double AttackMaturity { get; set; }
    }

    public class AttackPhase
    {
        public string Name { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public List<MITRE> Techniques { get; set; }
        public TimeSpan Duration { get; set; }
        public bool Completed { get; set; }
    }

    public class DetectionCoverage
    {
        public int TotalTechniques { get; set; }
        public int CoveredTechniques { get; set; }
        public double CoveragePercentage { get; set; }
        public Dictionary<string, int> DataSourceCoverage { get; set; }
        public List<MITRE> UncoveredTechniques { get; set; }
        public List<string> RecommendedDataSources { get; set; }
    }

    public class PlatformCoverage
    {
        public Dictionary<string, List<MITRE>> Platforms { get; set; }
        public string PrimaryPlatform { get; set; }
    }
}