using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Core.Entities;
using System.Text.RegularExpressions;
using System.Text;

namespace SecuNik.LogX.Api.Services.Rules
{
    public class YaraRuleProcessor : IRuleProcessor
    {
        private readonly ILogger<YaraRuleProcessor> _logger;
        private readonly Dictionary<Guid, CompiledYaraRule> _compiledRules;

        public YaraRuleProcessor(ILogger<YaraRuleProcessor> logger)
        {
            _logger = logger;
            _compiledRules = new Dictionary<Guid, CompiledYaraRule>();
        }

        public async Task<List<RuleMatchResult>> ProcessAsync(
            List<LogEvent> events, 
            string rawContent, 
            List<Rule> rules, 
            CancellationToken cancellationToken = default)
        {
            var results = new List<RuleMatchResult>();

            try
            {
                foreach (var rule in rules)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var compiledRule = await GetOrCompileRuleAsync(rule);
                    if (compiledRule == null) continue;

                    var matches = await ProcessRuleAsync(compiledRule, events, rawContent);
                    if (matches.Count > 0)
                    {
                        results.Add(new RuleMatchResult
                        {
                            RuleId = rule.Id,
                            RuleName = rule.Name,
                            RuleType = RuleType.Yara,
                            Severity = rule.Severity,
                            MatchCount = matches.Count,
                            Matches = matches,
                            Confidence = CalculateConfidence(matches),
                            MitreAttackIds = ExtractMitreIds(rule),
                            Metadata = new Dictionary<string, object>
                            {
                                ["rule_category"] = rule.Category,
                                ["rule_author"] = rule.Author,
                                ["rule_tags"] = rule.GetTags()
                            }
                        });
                    }
                }

                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing YARA rules");
                throw;
            }
        }

        public async Task<ValidationResult> ValidateRuleAsync(Rule rule, CancellationToken cancellationToken = default)
        {
            var result = new ValidationResult { IsValid = true };

            try
            {
                // Basic YARA syntax validation
                if (string.IsNullOrWhiteSpace(rule.Content))
                {
                    result.IsValid = false;
                    result.Errors.Add("Rule content is empty");
                    return result;
                }

                // Check for required YARA structure
                if (!rule.Content.Contains("rule "))
                {
                    result.IsValid = false;
                    result.Errors.Add("Rule must contain 'rule' keyword");
                }

                if (!rule.Content.Contains("condition:"))
                {
                    result.IsValid = false;
                    result.Errors.Add("Rule must contain 'condition:' section");
                }

                // Validate rule name format
                var ruleNameMatch = Regex.Match(rule.Content, @"rule\s+(\w+)\s*\{");
                if (!ruleNameMatch.Success)
                {
                    result.IsValid = false;
                    result.Errors.Add("Invalid rule name format");
                }
                else
                {
                    var ruleName = ruleNameMatch.Groups[1].Value;
                    if (string.IsNullOrEmpty(ruleName))
                    {
                        result.IsValid = false;
                        result.Errors.Add("Rule name cannot be empty");
                    }
                }

                // Check for balanced braces
                var openBraces = rule.Content.Count(c => c == '{');
                var closeBraces = rule.Content.Count(c => c == '}');
                if (openBraces != closeBraces)
                {
                    result.IsValid = false;
                    result.Errors.Add("Unbalanced braces in rule");
                }

                // Validate strings section if present
                if (rule.Content.Contains("strings:"))
                {
                    var stringsSection = ExtractSection(rule.Content, "strings:");
                    if (string.IsNullOrWhiteSpace(stringsSection))
                    {
                        result.Warnings.Add("Empty strings section found");
                    }
                    else
                    {
                        ValidateStringsSection(stringsSection, result);
                    }
                }

                // Validate condition section
                var conditionSection = ExtractSection(rule.Content, "condition:");
                if (string.IsNullOrWhiteSpace(conditionSection))
                {
                    result.IsValid = false;
                    result.Errors.Add("Empty condition section");
                }

                return result;
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.Errors.Add($"Validation error: {ex.Message}");
                return result;
            }
        }

        public async Task<TestResult> TestRuleAsync(Rule rule, string testContent, CancellationToken cancellationToken = default)
        {
            var result = new TestResult();
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                // First validate the rule
                var validation = await ValidateRuleAsync(rule, cancellationToken);
                if (!validation.IsValid)
                {
                    result.Success = false;
                    result.ErrorMessage = string.Join("; ", validation.Errors);
                    return result;
                }

                // Compile the rule
                var compiledRule = await CompileRuleAsync(rule);
                if (compiledRule == null)
                {
                    result.Success = false;
                    result.ErrorMessage = "Failed to compile rule";
                    return result;
                }

                // Create test events from content
                var testEvents = CreateTestEvents(testContent);

                // Test the rule
                var matches = await ProcessRuleAsync(compiledRule, testEvents, testContent);

                result.Success = true;
                result.Matches = new List<RuleMatchResult>
                {
                    new RuleMatchResult
                    {
                        RuleId = rule.Id,
                        RuleName = rule.Name,
                        RuleType = RuleType.Yara,
                        Severity = rule.Severity,
                        MatchCount = matches.Count,
                        Matches = matches,
                        Confidence = CalculateConfidence(matches)
                    }
                };

                if (matches.Count == 0)
                {
                    result.Warnings.Add("Rule did not match test content");
                }

                return result;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                return result;
            }
            finally
            {
                stopwatch.Stop();
                result.ProcessingTime = stopwatch.Elapsed;
            }
        }

        public async Task LoadRulesAsync(List<Rule> rules, CancellationToken cancellationToken = default)
        {
            try
            {
                _compiledRules.Clear();

                foreach (var rule in rules)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var compiledRule = await CompileRuleAsync(rule);
                    if (compiledRule != null)
                    {
                        _compiledRules[rule.Id] = compiledRule;
                    }
                }

                _logger.LogInformation("Loaded {RuleCount} YARA rules", _compiledRules.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading YARA rules");
                throw;
            }
        }

        private async Task<CompiledYaraRule?> GetOrCompileRuleAsync(Rule rule)
        {
            if (_compiledRules.TryGetValue(rule.Id, out var compiledRule))
            {
                return compiledRule;
            }

            compiledRule = await CompileRuleAsync(rule);
            if (compiledRule != null)
            {
                _compiledRules[rule.Id] = compiledRule;
            }

            return compiledRule;
        }

        private async Task<CompiledYaraRule?> CompileRuleAsync(Rule rule)
        {
            try
            {
                // Parse YARA rule content
                var ruleNameMatch = Regex.Match(rule.Content, @"rule\s+(\w+)\s*\{");
                if (!ruleNameMatch.Success)
                {
                    _logger.LogWarning("Could not extract rule name from YARA rule {RuleId}", rule.Id);
                    return null;
                }

                var ruleName = ruleNameMatch.Groups[1].Value;
                var strings = ExtractStrings(rule.Content);
                var condition = ExtractSection(rule.Content, "condition:");
                var meta = ExtractMeta(rule.Content);

                return new CompiledYaraRule
                {
                    RuleId = rule.Id,
                    RuleName = ruleName,
                    Strings = strings,
                    Condition = condition,
                    Meta = meta,
                    CompiledAt = DateTime.UtcNow
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error compiling YARA rule {RuleId}", rule.Id);
                return null;
            }
        }

        private async Task<List<MatchDetail>> ProcessRuleAsync(
            CompiledYaraRule compiledRule, 
            List<LogEvent> events, 
            string rawContent)
        {
            var matches = new List<MatchDetail>();

            try
            {
                // Process string matches against raw content
                foreach (var yaraString in compiledRule.Strings)
                {
                    var stringMatches = FindStringMatches(rawContent, yaraString);
                    matches.AddRange(stringMatches);
                }

                // Process string matches against individual events
                foreach (var logEvent in events)
                {
                    foreach (var yaraString in compiledRule.Strings)
                    {
                        var eventMatches = FindStringMatches(logEvent.RawData, yaraString);
                        foreach (var match in eventMatches)
                        {
                            match.LineNumber = logEvent.LineNumber;
                            match.Timestamp = logEvent.Timestamp;
                            match.Fields = new Dictionary<string, object>(logEvent.Fields);
                        }
                        matches.AddRange(eventMatches);
                    }
                }

                // Evaluate condition (simplified)
                if (matches.Count > 0 && EvaluateCondition(compiledRule.Condition, matches))
                {
                    return matches;
                }

                return new List<MatchDetail>();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing YARA rule {RuleName}", compiledRule.RuleName);
                return new List<MatchDetail>();
            }
        }

        private List<MatchDetail> FindStringMatches(string content, YaraString yaraString)
        {
            var matches = new List<MatchDetail>();

            try
            {
                if (yaraString.IsRegex)
                {
                    var regex = new Regex(yaraString.Value, RegexOptions.IgnoreCase | RegexOptions.Multiline);
                    var regexMatches = regex.Matches(content);

                    foreach (Match match in regexMatches)
                    {
                        matches.Add(new MatchDetail
                        {
                            MatchedContent = match.Value,
                            FileOffset = match.Index,
                            Context = GetContext(content, match.Index, match.Length),
                            Fields = new Dictionary<string, object>
                            {
                                ["string_name"] = yaraString.Name,
                                ["string_type"] = "regex",
                                ["match_length"] = match.Length
                            }
                        });
                    }
                }
                else
                {
                    // Simple string search
                    var index = 0;
                    while ((index = content.IndexOf(yaraString.Value, index, StringComparison.OrdinalIgnoreCase)) != -1)
                    {
                        matches.Add(new MatchDetail
                        {
                            MatchedContent = yaraString.Value,
                            FileOffset = index,
                            Context = GetContext(content, index, yaraString.Value.Length),
                            Fields = new Dictionary<string, object>
                            {
                                ["string_name"] = yaraString.Name,
                                ["string_type"] = "text",
                                ["match_length"] = yaraString.Value.Length
                            }
                        });

                        index += yaraString.Value.Length;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error finding matches for YARA string {StringName}", yaraString.Name);
            }

            return matches;
        }

        private string GetContext(string content, int offset, int length, int contextSize = 50)
        {
            var start = Math.Max(0, offset - contextSize);
            var end = Math.Min(content.Length, offset + length + contextSize);
            return content.Substring(start, end - start);
        }

        private bool EvaluateCondition(string condition, List<MatchDetail> matches)
        {
            // Simplified condition evaluation
            // In a real implementation, you'd parse and evaluate the YARA condition properly
            
            if (string.IsNullOrWhiteSpace(condition))
                return matches.Count > 0;

            // Basic evaluation for common patterns
            if (condition.Contains("any of them"))
                return matches.Count > 0;

            if (condition.Contains("all of them"))
            {
                // This would require more sophisticated parsing
                return matches.Count > 0;
            }

            // Default: if we have matches, condition is satisfied
            return matches.Count > 0;
        }

        private List<YaraString> ExtractStrings(string ruleContent)
        {
            var strings = new List<YaraString>();
            var stringsSection = ExtractSection(ruleContent, "strings:");

            if (string.IsNullOrWhiteSpace(stringsSection))
                return strings;

            var stringPattern = @"\$(\w+)\s*=\s*(.+)";
            var matches = Regex.Matches(stringsSection, stringPattern);

            foreach (Match match in matches)
            {
                var name = match.Groups[1].Value;
                var value = match.Groups[2].Value.Trim();

                // Remove quotes and determine type
                var isRegex = value.StartsWith("/") && value.EndsWith("/");
                if (isRegex)
                {
                    value = value.Substring(1, value.Length - 2); // Remove / /
                }
                else if (value.StartsWith("\"") && value.EndsWith("\""))
                {
                    value = value.Substring(1, value.Length - 2); // Remove quotes
                }

                strings.Add(new YaraString
                {
                    Name = name,
                    Value = value,
                    IsRegex = isRegex
                });
            }

            return strings;
        }

        private Dictionary<string, string> ExtractMeta(string ruleContent)
        {
            var meta = new Dictionary<string, string>();
            var metaSection = ExtractSection(ruleContent, "meta:");

            if (string.IsNullOrWhiteSpace(metaSection))
                return meta;

            var metaPattern = @"(\w+)\s*=\s*""([^""]*)""";
            var matches = Regex.Matches(metaSection, metaPattern);

            foreach (Match match in matches)
            {
                var key = match.Groups[1].Value;
                var value = match.Groups[2].Value;
                meta[key] = value;
            }

            return meta;
        }

        private string ExtractSection(string ruleContent, string sectionName)
        {
            var sectionStart = ruleContent.IndexOf(sectionName);
            if (sectionStart == -1) return string.Empty;

            sectionStart += sectionName.Length;
            var nextSection = FindNextSection(ruleContent, sectionStart);
            
            if (nextSection == -1)
            {
                // Take until the end of the rule
                var ruleEnd = ruleContent.LastIndexOf('}');
                nextSection = ruleEnd == -1 ? ruleContent.Length : ruleEnd;
            }

            return ruleContent.Substring(sectionStart, nextSection - sectionStart).Trim();
        }

        private int FindNextSection(string content, int startIndex)
        {
            var sections = new[] { "meta:", "strings:", "condition:" };
            var minIndex = int.MaxValue;

            foreach (var section in sections)
            {
                var index = content.IndexOf(section, startIndex);
                if (index != -1 && index < minIndex)
                {
                    minIndex = index;
                }
            }

            return minIndex == int.MaxValue ? -1 : minIndex;
        }

        private void ValidateStringsSection(string stringsSection, ValidationResult result)
        {
            var stringPattern = @"\$(\w+)\s*=\s*(.+)";
            var matches = Regex.Matches(stringsSection, stringPattern);

            if (matches.Count == 0)
            {
                result.Warnings.Add("No string definitions found in strings section");
            }

            foreach (Match match in matches)
            {
                var name = match.Groups[1].Value;
                var value = match.Groups[2].Value.Trim();

                if (string.IsNullOrEmpty(name))
                {
                    result.Errors.Add("String name cannot be empty");
                }

                if (string.IsNullOrEmpty(value))
                {
                    result.Errors.Add($"String value for ${name} cannot be empty");
                }
            }
        }

        private List<LogEvent> CreateTestEvents(string testContent)
        {
            var events = new List<LogEvent>();
            var lines = testContent.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            for (int i = 0; i < lines.Length; i++)
            {
                events.Add(new LogEvent
                {
                    LineNumber = i + 1,
                    RawData = lines[i],
                    Timestamp = DateTime.UtcNow,
                    Message = lines[i],
                    Level = "INFO",
                    Source = "test"
                });
            }

            return events;
        }

        private double CalculateConfidence(List<MatchDetail> matches)
        {
            if (matches.Count == 0) return 0.0;

            // Simple confidence calculation based on match count and context
            var baseConfidence = Math.Min(1.0, matches.Count / 10.0);
            return baseConfidence;
        }

        private List<string> ExtractMitreIds(Rule rule)
        {
            var mitreIds = new List<string>();
            
            // Extract from rule content
            var mitrePattern = @"T\d{4}(?:\.\d{3})?";
            var matches = Regex.Matches(rule.Content, mitrePattern);
            
            foreach (Match match in matches)
            {
                mitreIds.Add(match.Value);
            }

            // Extract from tags
            var tags = rule.GetTags();
            foreach (var tag in tags)
            {
                if (Regex.IsMatch(tag, mitrePattern))
                {
                    mitreIds.Add(tag);
                }
            }

            return mitreIds.Distinct().ToList();
        }
    }

    public class CompiledYaraRule
    {
        public Guid RuleId { get; set; }
        public string RuleName { get; set; } = string.Empty;
        public List<YaraString> Strings { get; set; } = new();
        public string Condition { get; set; } = string.Empty;
        public Dictionary<string, string> Meta { get; set; } = new();
        public DateTime CompiledAt { get; set; }
    }

    public class YaraString
    {
        public string Name { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public bool IsRegex { get; set; }
    }
}