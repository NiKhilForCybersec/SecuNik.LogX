using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Core.Entities;
using SecuNik.LogX.Api.Data;
using Microsoft.EntityFrameworkCore;

namespace SecuNik.LogX.Api.Services.Rules
{
    public class RuleEngineService : IRuleEngine
    {
        private readonly LogXDbContext _dbContext;
        private readonly YaraRuleProcessor _yaraProcessor;
        private readonly SigmaRuleProcessor _sigmaProcessor;
        private readonly StixRuleProcessor _stixProcessor;
        private readonly ILogger<RuleEngineService> _logger;
        private readonly Dictionary<RuleType, IRuleProcessor> _processors;

        public RuleEngineService(
            LogXDbContext dbContext,
            YaraRuleProcessor yaraProcessor,
            SigmaRuleProcessor sigmaProcessor,
            StixRuleProcessor stixProcessor,
            ILogger<RuleEngineService> logger)
        {
            _dbContext = dbContext;
            _yaraProcessor = yaraProcessor;
            _sigmaProcessor = sigmaProcessor;
            _stixProcessor = stixProcessor;
            _logger = logger;

            _processors = new Dictionary<RuleType, IRuleProcessor>
            {
                { RuleType.Yara, _yaraProcessor },
                { RuleType.Sigma, _sigmaProcessor },
                { RuleType.Stix, _stixProcessor }
            };
        }

        public async Task<List<RuleMatchResult>> ProcessAsync(
            Guid analysisId, 
            List<LogEvent> events, 
            string rawContent, 
            CancellationToken cancellationToken = default)
        {
            var activeRules = await GetActiveRulesAsync(cancellationToken: cancellationToken);
            return await ProcessWithRulesAsync(analysisId, events, rawContent, activeRules, cancellationToken);
        }

        public async Task<List<RuleMatchResult>> ProcessWithRulesAsync(
            Guid analysisId,
            List<LogEvent> events,
            string rawContent,
            List<Rule> rules,
            CancellationToken cancellationToken = default)
        {
            var allResults = new List<RuleMatchResult>();

            try
            {
                _logger.LogInformation("Processing {EventCount} events with {RuleCount} rules for analysis {AnalysisId}",
                    events.Count, rules.Count, analysisId);

                // Group rules by type for efficient processing
                var rulesByType = rules.GroupBy(r => r.Type).ToList();

                foreach (var ruleGroup in rulesByType)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var ruleType = ruleGroup.Key;
                    var rulesOfType = ruleGroup.ToList();

                    if (_processors.TryGetValue(ruleType, out var processor))
                    {
                        try
                        {
                            var results = await processor.ProcessAsync(events, rawContent, rulesOfType, cancellationToken);
                            allResults.AddRange(results);

                            _logger.LogDebug("Processed {RuleCount} {RuleType} rules, found {MatchCount} matches",
                                rulesOfType.Count, ruleType, results.Count);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "Error processing {RuleType} rules for analysis {AnalysisId}",
                                ruleType, analysisId);
                        }
                    }
                    else
                    {
                        _logger.LogWarning("No processor found for rule type {RuleType}", ruleType);
                    }
                }

                // Update rule match statistics
                await UpdateRuleStatisticsAsync(allResults);

                _logger.LogInformation("Rule processing completed for analysis {AnalysisId}. Found {TotalMatches} matches",
                    analysisId, allResults.Count);

                return allResults;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during rule processing for analysis {AnalysisId}", analysisId);
                throw;
            }
        }

        public async Task<ValidationResult> ValidateRuleAsync(Rule rule, CancellationToken cancellationToken = default)
        {
            try
            {
                if (_processors.TryGetValue(rule.Type, out var processor))
                {
                    return await processor.ValidateRuleAsync(rule, cancellationToken);
                }

                return new ValidationResult
                {
                    IsValid = false,
                    Errors = { $"No processor found for rule type {rule.Type}" }
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating rule {RuleId}", rule.Id);
                return new ValidationResult
                {
                    IsValid = false,
                    Errors = { $"Validation error: {ex.Message}" }
                };
            }
        }

        public async Task<TestResult> TestRuleAsync(Rule rule, string testContent, CancellationToken cancellationToken = default)
        {
            try
            {
                if (_processors.TryGetValue(rule.Type, out var processor))
                {
                    return await processor.TestRuleAsync(rule, testContent, cancellationToken);
                }

                return new TestResult
                {
                    Success = false,
                    ErrorMessage = $"No processor found for rule type {rule.Type}"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error testing rule {RuleId}", rule.Id);
                return new TestResult
                {
                    Success = false,
                    ErrorMessage = ex.Message
                };
            }
        }

        public async Task LoadRulesAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Loading rules into processors...");

                var rules = await _dbContext.Rules
                    .Where(r => r.IsEnabled)
                    .ToListAsync(cancellationToken);

                var rulesByType = rules.GroupBy(r => r.Type);

                foreach (var ruleGroup in rulesByType)
                {
                    var ruleType = ruleGroup.Key;
                    var rulesOfType = ruleGroup.ToList();

                    if (_processors.TryGetValue(ruleType, out var processor))
                    {
                        await processor.LoadRulesAsync(rulesOfType, cancellationToken);
                        _logger.LogInformation("Loaded {RuleCount} {RuleType} rules", rulesOfType.Count, ruleType);
                    }
                }

                _logger.LogInformation("Rule loading completed. Total rules loaded: {TotalRules}", rules.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading rules");
                throw;
            }
        }

        public async Task<List<Rule>> GetActiveRulesAsync(RuleType? ruleType = null, CancellationToken cancellationToken = default)
        {
            try
            {
                var query = _dbContext.Rules.Where(r => r.IsEnabled);

                if (ruleType.HasValue)
                {
                    query = query.Where(r => r.Type == ruleType.Value);
                }

                return await query.OrderBy(r => r.Priority).ToListAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting active rules");
                throw;
            }
        }

        private async Task UpdateRuleStatisticsAsync(List<RuleMatchResult> results)
        {
            try
            {
                var ruleIds = results.Select(r => r.RuleId).Distinct().ToList();
                var rules = await _dbContext.Rules
                    .Where(r => ruleIds.Contains(r.Id))
                    .ToListAsync();

                foreach (var rule in rules)
                {
                    var matchCount = results.Where(r => r.RuleId == rule.Id).Sum(r => r.MatchCount);
                    rule.MatchCount += matchCount;
                    rule.LastMatched = DateTime.UtcNow;
                }

                await _dbContext.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error updating rule statistics");
                // Don't throw - this is not critical
            }
        }
    }

    public interface IRuleProcessor
    {
        Task<List<RuleMatchResult>> ProcessAsync(List<LogEvent> events, string rawContent, List<Rule> rules, CancellationToken cancellationToken = default);
        Task<ValidationResult> ValidateRuleAsync(Rule rule, CancellationToken cancellationToken = default);
        Task<TestResult> TestRuleAsync(Rule rule, string testContent, CancellationToken cancellationToken = default);
        Task LoadRulesAsync(List<Rule> rules, CancellationToken cancellationToken = default);
    }
}