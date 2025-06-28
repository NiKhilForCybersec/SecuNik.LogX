using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Core.Entities;
using System.Text.Json;
using System.Text.RegularExpressions;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace SecuNik.LogX.Api.Services.Rules
{
    public class SigmaRuleProcessor : IRuleProcessor
    {
        private readonly ILogger<SigmaRuleProcessor> _logger;
        private readonly Dictionary<Guid, CompiledSigmaRule> _compiledRules;
        private readonly IDeserializer _yamlDeserializer;

        public SigmaRuleProcessor(ILogger<SigmaRuleProcessor> logger)
        {
            _logger = logger;
            _compiledRules = new Dictionary<Guid, CompiledSigmaRule>();
            _yamlDeserializer = new DeserializerBuilder()
                .WithNamingConvention(UnderscoredNamingConvention.Instance)
                .Build();
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

                    var matches = await ProcessRuleAsync(compiledRule, events);
                    if (matches.Count > 0)
                    {
                        results.Add(new RuleMatchResult
                        {
                            RuleId = rule.Id,
                            RuleName = rule.Name,
                            RuleType = RuleType.Sigma,
                            Severity = rule.Severity,
                            MatchCount = matches.Count,
                            Matches = matches,
                            Confidence = CalculateConfidence(matches, compiledRule),
                            MitreAttackIds = ExtractMitreIds(compiledRule),
                            Metadata = new Dictionary<string, object>
                            {
                                ["rule_category"] = rule.Category,
                                ["rule_author"] = rule.Author,
                                ["sigma_level"] = compiledRule.Level,
                                ["sigma_status"] = compiledRule.Status,
                                ["logsource"] = compiledRule.LogSource
                            }
                        });
                    }
                }

                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing Sigma rules");
                throw;
            }
        }

        public async Task<ValidationResult> ValidateRuleAsync(Rule rule, CancellationToken cancellationToken = default)
        {
            var result = new ValidationResult { IsValid = true };

            try
            {
                if (string.IsNullOrWhiteSpace(rule.Content))
                {
                    result.IsValid = false;
                    result.Errors.Add("Rule content is empty");
                    return result;
                }

                // Try to parse as YAML
                SigmaRuleDefinition sigmaRule;
                try
                {
                    sigmaRule = _yamlDeserializer.Deserialize<SigmaRuleDefinition>(rule.Content);
                }
                catch (Exception ex)
                {
                    result.IsValid = false;
                    result.Errors.Add($"Invalid YAML format: {ex.Message}");
                    return result;
                }

                // Validate required fields
                if (string.IsNullOrWhiteSpace(sigmaRule.Title))
                {
                    result.IsValid = false;
                    result.Errors.Add("Title is required");
                }

                if (sigmaRule.Detection == null)
                {
                    result.IsValid = false;
                    result.Errors.Add("Detection section is required");
                }
                else
                {
                    if (sigmaRule.Detection.Condition == null)
                    {
                        result.IsValid = false;
                        result.Errors.Add("Detection condition is required");
                    }

                    // Validate that referenced selections exist
                    ValidateDetectionReferences(sigmaRule.Detection, result);
                }

                if (sigmaRule.LogSource == null)
                {
                    result.Warnings.Add("LogSource is recommended for better rule matching");
                }

                // Validate level
                if (!string.IsNullOrEmpty(sigmaRule.Level))
                {
                    var validLevels = new[] { "informational", "low", "medium", "high", "critical" };
                    if (!validLevels.Contains(sigmaRule.Level.ToLower()))
                    {
                        result.Warnings.Add($"Unknown level '{sigmaRule.Level}'. Valid levels: {string.Join(", ", validLevels)}");
                    }
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
                var matches = await ProcessRuleAsync(compiledRule, testEvents);

                result.Success = true;
                result.Matches = new List<RuleMatchResult>
                {
                    new RuleMatchResult
                    {
                        RuleId = rule.Id,
                        RuleName = rule.Name,
                        RuleType = RuleType.Sigma,
                        Severity = rule.Severity,
                        MatchCount = matches.Count,
                        Matches = matches,
                        Confidence = CalculateConfidence(matches, compiledRule)
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

                _logger.LogInformation("Loaded {RuleCount} Sigma rules", _compiledRules.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading Sigma rules");
                throw;
            }
        }

        private async Task<CompiledSigmaRule?> GetOrCompileRuleAsync(Rule rule)
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

        private async Task<CompiledSigmaRule?> CompileRuleAsync(Rule rule)
        {
            try
            {
                var sigmaRule = _yamlDeserializer.Deserialize<SigmaRuleDefinition>(rule.Content);

                return new CompiledSigmaRule
                {
                    RuleId = rule.Id,
                    Title = sigmaRule.Title ?? rule.Name,
                    Description = sigmaRule.Description ?? rule.Description,
                    Level = sigmaRule.Level ?? "medium",
                    Status = sigmaRule.Status ?? "experimental",
                    LogSource = sigmaRule.LogSource,
                    Detection = sigmaRule.Detection,
                    Tags = sigmaRule.Tags ?? new List<string>(),
                    References = sigmaRule.References ?? new List<string>(),
                    CompiledAt = DateTime.UtcNow
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error compiling Sigma rule {RuleId}", rule.Id);
                return null;
            }
        }

        private async Task<List<MatchDetail>> ProcessRuleAsync(CompiledSigmaRule compiledRule, List<LogEvent> events)
        {
            var matches = new List<MatchDetail>();

            try
            {
                foreach (var logEvent in events)
                {
                    if (await EvaluateEventAsync(compiledRule, logEvent))
                    {
                        matches.Add(new MatchDetail
                        {
                            MatchedContent = logEvent.RawData,
                            LineNumber = logEvent.LineNumber,
                            Timestamp = logEvent.Timestamp,
                            Context = $"Event matched Sigma rule conditions",
                            Fields = new Dictionary<string, object>(logEvent.Fields)
                            {
                                ["event_level"] = logEvent.Level,
                                ["event_source"] = logEvent.Source,
                                ["event_message"] = logEvent.Message
                            }
                        });
                    }
                }

                return matches;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing Sigma rule {RuleTitle}", compiledRule.Title);
                return new List<MatchDetail>();
            }
        }

        private async Task<bool> EvaluateEventAsync(CompiledSigmaRule rule, LogEvent logEvent)
        {
            try
            {
                // Check log source compatibility
                if (rule.LogSource != null && !IsLogSourceCompatible(rule.LogSource, logEvent))
                {
                    return false;
                }

                // Evaluate detection condition
                return await EvaluateDetectionAsync(rule.Detection, logEvent);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error evaluating event against Sigma rule {RuleTitle}", rule.Title);
                return false;
            }
        }

        private bool IsLogSourceCompatible(SigmaLogSource logSource, LogEvent logEvent)
        {
            // Simple log source matching - in a real implementation, this would be more sophisticated
            if (!string.IsNullOrEmpty(logSource.Product))
            {
                // Check if the event source matches the product
                if (!logEvent.Source.ToLower().Contains(logSource.Product.ToLower()))
                {
                    return false;
                }
            }

            if (!string.IsNullOrEmpty(logSource.Service))
            {
                // Check if the event relates to the specified service
                if (!logEvent.Fields.ContainsKey("service") || 
                    !logEvent.Fields["service"].ToString()!.ToLower().Contains(logSource.Service.ToLower()))
                {
                    return false;
                }
            }

            return true;
        }

        private async Task<bool> EvaluateDetectionAsync(SigmaDetection detection, LogEvent logEvent)
        {
            try
            {
                // Get all selection criteria
                var selections = new Dictionary<string, bool>();

                // Evaluate each selection
                foreach (var kvp in detection.AdditionalData)
                {
                    if (kvp.Key == "condition") continue;

                    var selectionResult = EvaluateSelection(kvp.Value, logEvent);
                    selections[kvp.Key] = selectionResult;
                }

                // Evaluate condition
                return EvaluateCondition(detection.Condition, selections);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error evaluating Sigma detection");
                return false;
            }
        }

        private bool EvaluateSelection(object selectionData, LogEvent logEvent)
        {
            try
            {
                if (selectionData is JsonElement jsonElement)
                {
                    return EvaluateJsonSelection(jsonElement, logEvent);
                }

                if (selectionData is Dictionary<object, object> dict)
                {
                    return EvaluateDictionarySelection(dict, logEvent);
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error evaluating selection");
                return false;
            }
        }

        private bool EvaluateJsonSelection(JsonElement selection, LogEvent logEvent)
        {
            if (selection.ValueKind == JsonValueKind.Object)
            {
                foreach (var property in selection.EnumerateObject())
                {
                    var fieldName = property.Name;
                    var expectedValue = property.Value;

                    if (!MatchesField(logEvent, fieldName, expectedValue))
                    {
                        return false;
                    }
                }
                return true;
            }

            return false;
        }

        private bool EvaluateDictionarySelection(Dictionary<object, object> selection, LogEvent logEvent)
        {
            foreach (var kvp in selection)
            {
                var fieldName = kvp.Key.ToString();
                var expectedValue = kvp.Value;

                if (!MatchesFieldValue(logEvent, fieldName!, expectedValue))
                {
                    return false;
                }
            }
            return true;
        }

        private bool MatchesField(LogEvent logEvent, string fieldName, JsonElement expectedValue)
        {
            // Get field value from log event
            var fieldValue = GetFieldValue(logEvent, fieldName);
            if (fieldValue == null) return false;

            if (expectedValue.ValueKind == JsonValueKind.String)
            {
                var expectedString = expectedValue.GetString();
                return MatchesStringValue(fieldValue.ToString()!, expectedString!);
            }

            if (expectedValue.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in expectedValue.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String)
                    {
                        var expectedString = item.GetString();
                        if (MatchesStringValue(fieldValue.ToString()!, expectedString!))
                        {
                            return true;
                        }
                    }
                }
                return false;
            }

            return fieldValue.ToString() == expectedValue.ToString();
        }

        private bool MatchesFieldValue(LogEvent logEvent, string fieldName, object expectedValue)
        {
            var fieldValue = GetFieldValue(logEvent, fieldName);
            if (fieldValue == null) return false;

            if (expectedValue is string expectedString)
            {
                return MatchesStringValue(fieldValue.ToString()!, expectedString);
            }

            if (expectedValue is List<object> expectedList)
            {
                foreach (var item in expectedList)
                {
                    if (MatchesStringValue(fieldValue.ToString()!, item.ToString()!))
                    {
                        return true;
                    }
                }
                return false;
            }

            return fieldValue.ToString() == expectedValue.ToString();
        }

        private object? GetFieldValue(LogEvent logEvent, string fieldName)
        {
            // Check common log event properties first
            switch (fieldName.ToLower())
            {
                case "eventid":
                case "event_id":
                    return logEvent.Fields.GetValueOrDefault("EventID") ?? 
                           logEvent.Fields.GetValueOrDefault("event_id");
                case "level":
                    return logEvent.Level;
                case "message":
                    return logEvent.Message;
                case "source":
                    return logEvent.Source;
                case "timestamp":
                    return logEvent.Timestamp;
                default:
                    return logEvent.Fields.GetValueOrDefault(fieldName);
            }
        }

        private bool MatchesStringValue(string actualValue, string expectedValue)
        {
            if (string.IsNullOrEmpty(expectedValue)) return false;

            // Handle wildcards
            if (expectedValue.Contains("*"))
            {
                var pattern = "^" + Regex.Escape(expectedValue).Replace("\\*", ".*") + "$";
                return Regex.IsMatch(actualValue, pattern, RegexOptions.IgnoreCase);
            }

            // Handle contains operations
            if (expectedValue.StartsWith("*") && expectedValue.EndsWith("*"))
            {
                var searchTerm = expectedValue.Substring(1, expectedValue.Length - 2);
                return actualValue.Contains(searchTerm, StringComparison.OrdinalIgnoreCase);
            }

            // Exact match (case insensitive)
            return string.Equals(actualValue, expectedValue, StringComparison.OrdinalIgnoreCase);
        }

        private bool EvaluateCondition(object? condition, Dictionary<string, bool> selections)
        {
            if (condition == null) return false;

            var conditionString = condition.ToString()!.ToLower();

            // Simple condition evaluation - in a real implementation, this would be more sophisticated
            if (conditionString.Contains(" and "))
            {
                var parts = conditionString.Split(" and ");
                return parts.All(part => EvaluateConditionPart(part.Trim(), selections));
            }

            if (conditionString.Contains(" or "))
            {
                var parts = conditionString.Split(" or ");
                return parts.Any(part => EvaluateConditionPart(part.Trim(), selections));
            }

            return EvaluateConditionPart(conditionString, selections);
        }

        private bool EvaluateConditionPart(string part, Dictionary<string, bool> selections)
        {
            part = part.Trim();

            // Handle negation
            if (part.StartsWith("not "))
            {
                var innerPart = part.Substring(4).Trim();
                return !EvaluateConditionPart(innerPart, selections);
            }

            // Check if it's a selection reference
            if (selections.TryGetValue(part, out var result))
            {
                return result;
            }

            // Default to false for unknown conditions
            return false;
        }

        private void ValidateDetectionReferences(SigmaDetection detection, ValidationResult result)
        {
            if (detection.Condition == null) return;

            var conditionString = detection.Condition.ToString()!;
            var referencedSelections = ExtractSelectionReferences(conditionString);

            foreach (var reference in referencedSelections)
            {
                if (!detection.AdditionalData.ContainsKey(reference))
                {
                    result.Errors.Add($"Condition references undefined selection '{reference}'");
                }
            }
        }

        private List<string> ExtractSelectionReferences(string condition)
        {
            var references = new List<string>();
            var words = condition.Split(new[] { ' ', '(', ')', '|', '&' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var word in words)
            {
                var cleanWord = word.Trim().ToLower();
                if (cleanWord != "and" && cleanWord != "or" && cleanWord != "not" && 
                    !cleanWord.StartsWith("1") && !cleanWord.StartsWith("all") && 
                    !cleanWord.StartsWith("any"))
                {
                    references.Add(cleanWord);
                }
            }

            return references.Distinct().ToList();
        }

        private List<LogEvent> CreateTestEvents(string testContent)
        {
            var events = new List<LogEvent>();

            try
            {
                // Try to parse as JSON first
                if (testContent.TrimStart().StartsWith("{") || testContent.TrimStart().StartsWith("["))
                {
                    var jsonEvents = JsonSerializer.Deserialize<List<Dictionary<string, object>>>(testContent);
                    if (jsonEvents != null)
                    {
                        for (int i = 0; i < jsonEvents.Count; i++)
                        {
                            var eventData = jsonEvents[i];
                            var logEvent = new LogEvent
                            {
                                LineNumber = i + 1,
                                RawData = JsonSerializer.Serialize(eventData),
                                Timestamp = DateTime.UtcNow,
                                Fields = eventData
                            };

                            // Extract common fields
                            if (eventData.TryGetValue("message", out var message))
                                logEvent.Message = message.ToString()!;
                            if (eventData.TryGetValue("level", out var level))
                                logEvent.Level = level.ToString()!;
                            if (eventData.TryGetValue("source", out var source))
                                logEvent.Source = source.ToString()!;

                            events.Add(logEvent);
                        }
                    }
                }
                else
                {
                    // Parse as plain text
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
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error creating test events, falling back to plain text parsing");
                
                // Fallback to plain text
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
            }

            return events;
        }

        private double CalculateConfidence(List<MatchDetail> matches, CompiledSigmaRule rule)
        {
            if (matches.Count == 0) return 0.0;

            // Base confidence on rule level and match count
            var levelConfidence = rule.Level.ToLower() switch
            {
                "critical" => 0.9,
                "high" => 0.8,
                "medium" => 0.7,
                "low" => 0.6,
                "informational" => 0.5,
                _ => 0.7
            };

            // Adjust based on match count
            var matchConfidence = Math.Min(1.0, matches.Count / 5.0);

            return (levelConfidence + matchConfidence) / 2.0;
        }

        private List<string> ExtractMitreIds(CompiledSigmaRule rule)
        {
            var mitreIds = new List<string>();

            // Extract from tags
            foreach (var tag in rule.Tags)
            {
                if (tag.StartsWith("attack.t") || tag.StartsWith("attack.T"))
                {
                    var techniqueId = tag.Substring(7).ToUpper(); // Remove "attack." prefix
                    if (Regex.IsMatch(techniqueId, @"T\d{4}(?:\.\d{3})?"))
                    {
                        mitreIds.Add(techniqueId);
                    }
                }
            }

            return mitreIds.Distinct().ToList();
        }
    }

    // Sigma rule data structures
    public class SigmaRuleDefinition
    {
        public string? Title { get; set; }
        public string? Id { get; set; }
        public string? Description { get; set; }
        public string? Status { get; set; }
        public string? Level { get; set; }
        public string? Author { get; set; }
        public string? Date { get; set; }
        public string? Modified { get; set; }
        public List<string>? Tags { get; set; }
        public List<string>? References { get; set; }
        public SigmaLogSource? LogSource { get; set; }
        public SigmaDetection? Detection { get; set; }
        public List<string>? FalsePositives { get; set; }
    }

    public class SigmaLogSource
    {
        public string? Product { get; set; }
        public string? Service { get; set; }
        public string? Category { get; set; }
        public string? Definition { get; set; }
    }

    public class SigmaDetection
    {
        public object? Condition { get; set; }
        public Dictionary<string, object> AdditionalData { get; set; } = new();
    }

    public class CompiledSigmaRule
    {
        public Guid RuleId { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Level { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public SigmaLogSource? LogSource { get; set; }
        public SigmaDetection? Detection { get; set; }
        public List<string> Tags { get; set; } = new();
        public List<string> References { get; set; } = new();
        public DateTime CompiledAt { get; set; }
    }
}