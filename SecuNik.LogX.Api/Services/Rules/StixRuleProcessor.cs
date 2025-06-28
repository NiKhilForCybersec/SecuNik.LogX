using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Core.Entities;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SecuNik.LogX.Api.Services.Rules
{
    public class StixRuleProcessor : IRuleProcessor
    {
        private readonly ILogger<StixRuleProcessor> _logger;
        private readonly Dictionary<Guid, CompiledStixRule> _compiledRules;

        public StixRuleProcessor(ILogger<StixRuleProcessor> logger)
        {
            _logger = logger;
            _compiledRules = new Dictionary<Guid, CompiledStixRule>();
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
                            RuleType = RuleType.Stix,
                            Severity = rule.Severity,
                            MatchCount = matches.Count,
                            Matches = matches,
                            Confidence = CalculateConfidence(matches, compiledRule),
                            MitreAttackIds = ExtractMitreIds(compiledRule),
                            Metadata = new Dictionary<string, object>
                            {
                                ["rule_category"] = rule.Category,
                                ["rule_author"] = rule.Author,
                                ["stix_version"] = compiledRule.SpecVersion,
                                ["pattern_type"] = compiledRule.PatternType,
                                ["object_type"] = compiledRule.Type
                            }
                        });
                    }
                }

                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing STIX rules");
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

                // Try to parse as JSON
                StixIndicator stixIndicator;
                try
                {
                    stixIndicator = JsonSerializer.Deserialize<StixIndicator>(rule.Content, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    })!;
                }
                catch (Exception ex)
                {
                    result.IsValid = false;
                    result.Errors.Add($"Invalid JSON format: {ex.Message}");
                    return result;
                }

                // Validate required STIX fields
                if (string.IsNullOrWhiteSpace(stixIndicator.Type))
                {
                    result.IsValid = false;
                    result.Errors.Add("STIX type is required");
                }
                else if (stixIndicator.Type != "indicator")
                {
                    result.IsValid = false;
                    result.Errors.Add("STIX object must be of type 'indicator'");
                }

                if (string.IsNullOrWhiteSpace(stixIndicator.Id))
                {
                    result.IsValid = false;
                    result.Errors.Add("STIX ID is required");
                }
                else if (!IsValidStixId(stixIndicator.Id))
                {
                    result.IsValid = false;
                    result.Errors.Add("Invalid STIX ID format");
                }

                if (string.IsNullOrWhiteSpace(stixIndicator.Pattern))
                {
                    result.IsValid = false;
                    result.Errors.Add("STIX pattern is required");
                }
                else
                {
                    // Validate pattern syntax
                    var patternValidation = ValidateStixPattern(stixIndicator.Pattern);
                    if (!patternValidation.IsValid)
                    {
                        result.IsValid = false;
                        result.Errors.AddRange(patternValidation.Errors);
                    }
                    result.Warnings.AddRange(patternValidation.Warnings);
                }

                if (string.IsNullOrWhiteSpace(stixIndicator.SpecVersion))
                {
                    result.Warnings.Add("STIX spec_version is recommended");
                }

                if (stixIndicator.Labels == null || stixIndicator.Labels.Count == 0)
                {
                    result.Warnings.Add("STIX labels are recommended for categorization");
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
                        RuleType = RuleType.Stix,
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

                _logger.LogInformation("Loaded {RuleCount} STIX rules", _compiledRules.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading STIX rules");
                throw;
            }
        }

        private async Task<CompiledStixRule?> GetOrCompileRuleAsync(Rule rule)
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

        private async Task<CompiledStixRule?> CompileRuleAsync(Rule rule)
        {
            try
            {
                var stixIndicator = JsonSerializer.Deserialize<StixIndicator>(rule.Content, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                })!;

                var compiledPatterns = CompileStixPattern(stixIndicator.Pattern);

                return new CompiledStixRule
                {
                    RuleId = rule.Id,
                    Id = stixIndicator.Id,
                    Type = stixIndicator.Type,
                    SpecVersion = stixIndicator.SpecVersion ?? "2.1",
                    Pattern = stixIndicator.Pattern,
                    PatternType = stixIndicator.PatternType ?? "stix",
                    ValidFrom = stixIndicator.ValidFrom ?? DateTime.UtcNow,
                    ValidUntil = stixIndicator.ValidUntil,
                    Labels = stixIndicator.Labels ?? new List<string>(),
                    CompiledPatterns = compiledPatterns,
                    KillChainPhases = stixIndicator.KillChainPhases ?? new List<StixKillChainPhase>(),
                    CompiledAt = DateTime.UtcNow
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error compiling STIX rule {RuleId}", rule.Id);
                return null;
            }
        }

        private async Task<List<MatchDetail>> ProcessRuleAsync(
            CompiledStixRule compiledRule,
            List<LogEvent> events,
            string rawContent)
        {
            var matches = new List<MatchDetail>();

            try
            {
                // Check if rule is still valid
                if (compiledRule.ValidUntil.HasValue && DateTime.UtcNow > compiledRule.ValidUntil.Value)
                {
                    return matches; // Rule has expired
                }

                if (DateTime.UtcNow < compiledRule.ValidFrom)
                {
                    return matches; // Rule is not yet valid
                }

                // Process each compiled pattern
                foreach (var pattern in compiledRule.CompiledPatterns)
                {
                    var patternMatches = await ProcessPatternAsync(pattern, events, rawContent);
                    matches.AddRange(patternMatches);
                }

                return matches;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing STIX rule {RuleId}", compiledRule.RuleId);
                return new List<MatchDetail>();
            }
        }

        private async Task<List<MatchDetail>> ProcessPatternAsync(
            CompiledStixPattern pattern,
            List<LogEvent> events,
            string rawContent)
        {
            var matches = new List<MatchDetail>();

            try
            {
                switch (pattern.ObjectType.ToLower())
                {
                    case "file":
                        matches.AddRange(ProcessFilePattern(pattern, events, rawContent));
                        break;
                    case "network-traffic":
                        matches.AddRange(ProcessNetworkPattern(pattern, events));
                        break;
                    case "process":
                        matches.AddRange(ProcessProcessPattern(pattern, events));
                        break;
                    case "domain-name":
                        matches.AddRange(ProcessDomainPattern(pattern, events, rawContent));
                        break;
                    case "ipv4-addr":
                    case "ipv6-addr":
                        matches.AddRange(ProcessIpPattern(pattern, events, rawContent));
                        break;
                    case "url":
                        matches.AddRange(ProcessUrlPattern(pattern, events, rawContent));
                        break;
                    default:
                        matches.AddRange(ProcessGenericPattern(pattern, events, rawContent));
                        break;
                }

                return matches;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error processing STIX pattern {PatternType}", pattern.ObjectType);
                return new List<MatchDetail>();
            }
        }

        private List<MatchDetail> ProcessFilePattern(CompiledStixPattern pattern, List<LogEvent> events, string rawContent)
        {
            var matches = new List<MatchDetail>();

            foreach (var condition in pattern.Conditions)
            {
                switch (condition.Property.ToLower())
                {
                    case "hashes.md5":
                    case "hashes.sha1":
                    case "hashes.sha256":
                        matches.AddRange(FindHashMatches(condition.Value, events, rawContent, condition.Property));
                        break;
                    case "name":
                        matches.AddRange(FindFileNameMatches(condition.Value, events, rawContent));
                        break;
                    case "size":
                        matches.AddRange(FindFileSizeMatches(condition.Value, events));
                        break;
                }
            }

            return matches;
        }

        private List<MatchDetail> ProcessNetworkPattern(CompiledStixPattern pattern, List<LogEvent> events)
        {
            var matches = new List<MatchDetail>();

            foreach (var logEvent in events)
            {
                foreach (var condition in pattern.Conditions)
                {
                    var fieldValue = GetFieldValue(logEvent, condition.Property);
                    if (fieldValue != null && MatchesCondition(fieldValue.ToString()!, condition))
                    {
                        matches.Add(new MatchDetail
                        {
                            MatchedContent = logEvent.RawData,
                            LineNumber = logEvent.LineNumber,
                            Timestamp = logEvent.Timestamp,
                            Context = $"Network traffic pattern matched: {condition.Property} {condition.Operator} {condition.Value}",
                            Fields = new Dictionary<string, object>(logEvent.Fields)
                            {
                                ["matched_property"] = condition.Property,
                                ["matched_value"] = fieldValue,
                                ["pattern_type"] = "network-traffic"
                            }
                        });
                    }
                }
            }

            return matches;
        }

        private List<MatchDetail> ProcessProcessPattern(CompiledStixPattern pattern, List<LogEvent> events)
        {
            var matches = new List<MatchDetail>();

            foreach (var logEvent in events)
            {
                foreach (var condition in pattern.Conditions)
                {
                    var fieldValue = GetFieldValue(logEvent, condition.Property);
                    if (fieldValue != null && MatchesCondition(fieldValue.ToString()!, condition))
                    {
                        matches.Add(new MatchDetail
                        {
                            MatchedContent = logEvent.RawData,
                            LineNumber = logEvent.LineNumber,
                            Timestamp = logEvent.Timestamp,
                            Context = $"Process pattern matched: {condition.Property} {condition.Operator} {condition.Value}",
                            Fields = new Dictionary<string, object>(logEvent.Fields)
                            {
                                ["matched_property"] = condition.Property,
                                ["matched_value"] = fieldValue,
                                ["pattern_type"] = "process"
                            }
                        });
                    }
                }
            }

            return matches;
        }

        private List<MatchDetail> ProcessDomainPattern(CompiledStixPattern pattern, List<LogEvent> events, string rawContent)
        {
            var matches = new List<MatchDetail>();

            foreach (var condition in pattern.Conditions)
            {
                if (condition.Property.ToLower() == "value")
                {
                    matches.AddRange(FindDomainMatches(condition.Value, events, rawContent));
                }
            }

            return matches;
        }

        private List<MatchDetail> ProcessIpPattern(CompiledStixPattern pattern, List<LogEvent> events, string rawContent)
        {
            var matches = new List<MatchDetail>();

            foreach (var condition in pattern.Conditions)
            {
                if (condition.Property.ToLower() == "value")
                {
                    matches.AddRange(FindIpMatches(condition.Value, events, rawContent));
                }
            }

            return matches;
        }

        private List<MatchDetail> ProcessUrlPattern(CompiledStixPattern pattern, List<LogEvent> events, string rawContent)
        {
            var matches = new List<MatchDetail>();

            foreach (var condition in pattern.Conditions)
            {
                if (condition.Property.ToLower() == "value")
                {
                    matches.AddRange(FindUrlMatches(condition.Value, events, rawContent));
                }
            }

            return matches;
        }

        private List<MatchDetail> ProcessGenericPattern(CompiledStixPattern pattern, List<LogEvent> events, string rawContent)
        {
            var matches = new List<MatchDetail>();

            foreach (var logEvent in events)
            {
                foreach (var condition in pattern.Conditions)
                {
                    var fieldValue = GetFieldValue(logEvent, condition.Property);
                    if (fieldValue != null && MatchesCondition(fieldValue.ToString()!, condition))
                    {
                        matches.Add(new MatchDetail
                        {
                            MatchedContent = logEvent.RawData,
                            LineNumber = logEvent.LineNumber,
                            Timestamp = logEvent.Timestamp,
                            Context = $"Generic pattern matched: {condition.Property} {condition.Operator} {condition.Value}",
                            Fields = new Dictionary<string, object>(logEvent.Fields)
                            {
                                ["matched_property"] = condition.Property,
                                ["matched_value"] = fieldValue,
                                ["pattern_type"] = pattern.ObjectType
                            }
                        });
                    }
                }
            }

            return matches;
        }

        private List<MatchDetail> FindHashMatches(string hashValue, List<LogEvent> events, string rawContent, string hashType)
        {
            var matches = new List<MatchDetail>();
            var hashPattern = new Regex(Regex.Escape(hashValue), RegexOptions.IgnoreCase);

            // Search in raw content
            var rawMatches = hashPattern.Matches(rawContent);
            foreach (Match match in rawMatches)
            {
                matches.Add(new MatchDetail
                {
                    MatchedContent = match.Value,
                    FileOffset = match.Index,
                    Context = GetContext(rawContent, match.Index, match.Length),
                    Fields = new Dictionary<string, object>
                    {
                        ["hash_type"] = hashType,
                        ["hash_value"] = hashValue,
                        ["match_type"] = "file_hash"
                    }
                });
            }

            // Search in events
            foreach (var logEvent in events)
            {
                if (hashPattern.IsMatch(logEvent.RawData))
                {
                    matches.Add(new MatchDetail
                    {
                        MatchedContent = logEvent.RawData,
                        LineNumber = logEvent.LineNumber,
                        Timestamp = logEvent.Timestamp,
                        Context = $"Hash found in log event: {hashType}",
                        Fields = new Dictionary<string, object>(logEvent.Fields)
                        {
                            ["hash_type"] = hashType,
                            ["hash_value"] = hashValue,
                            ["match_type"] = "file_hash"
                        }
                    });
                }
            }

            return matches;
        }

        private List<MatchDetail> FindFileNameMatches(string fileName, List<LogEvent> events, string rawContent)
        {
            var matches = new List<MatchDetail>();
            var filePattern = new Regex(Regex.Escape(fileName), RegexOptions.IgnoreCase);

            foreach (var logEvent in events)
            {
                if (filePattern.IsMatch(logEvent.RawData))
                {
                    matches.Add(new MatchDetail
                    {
                        MatchedContent = logEvent.RawData,
                        LineNumber = logEvent.LineNumber,
                        Timestamp = logEvent.Timestamp,
                        Context = $"Filename found in log event: {fileName}",
                        Fields = new Dictionary<string, object>(logEvent.Fields)
                        {
                            ["filename"] = fileName,
                            ["match_type"] = "filename"
                        }
                    });
                }
            }

            return matches;
        }

        private List<MatchDetail> FindFileSizeMatches(string sizeValue, List<LogEvent> events)
        {
            var matches = new List<MatchDetail>();

            if (long.TryParse(sizeValue, out var targetSize))
            {
                foreach (var logEvent in events)
                {
                    var sizeField = GetFieldValue(logEvent, "size") ?? GetFieldValue(logEvent, "file_size");
                    if (sizeField != null && long.TryParse(sizeField.ToString(), out var eventSize))
                    {
                        if (eventSize == targetSize)
                        {
                            matches.Add(new MatchDetail
                            {
                                MatchedContent = logEvent.RawData,
                                LineNumber = logEvent.LineNumber,
                                Timestamp = logEvent.Timestamp,
                                Context = $"File size matched: {targetSize} bytes",
                                Fields = new Dictionary<string, object>(logEvent.Fields)
                                {
                                    ["file_size"] = eventSize,
                                    ["match_type"] = "file_size"
                                }
                            });
                        }
                    }
                }
            }

            return matches;
        }

        private List<MatchDetail> FindDomainMatches(string domain, List<LogEvent> events, string rawContent)
        {
            var matches = new List<MatchDetail>();
            var domainPattern = new Regex($@"\b{Regex.Escape(domain)}\b", RegexOptions.IgnoreCase);

            foreach (var logEvent in events)
            {
                if (domainPattern.IsMatch(logEvent.RawData))
                {
                    matches.Add(new MatchDetail
                    {
                        MatchedContent = logEvent.RawData,
                        LineNumber = logEvent.LineNumber,
                        Timestamp = logEvent.Timestamp,
                        Context = $"Domain found in log event: {domain}",
                        Fields = new Dictionary<string, object>(logEvent.Fields)
                        {
                            ["domain"] = domain,
                            ["match_type"] = "domain"
                        }
                    });
                }
            }

            return matches;
        }

        private List<MatchDetail> FindIpMatches(string ipAddress, List<LogEvent> events, string rawContent)
        {
            var matches = new List<MatchDetail>();
            var ipPattern = new Regex($@"\b{Regex.Escape(ipAddress)}\b", RegexOptions.IgnoreCase);

            foreach (var logEvent in events)
            {
                if (ipPattern.IsMatch(logEvent.RawData))
                {
                    matches.Add(new MatchDetail
                    {
                        MatchedContent = logEvent.RawData,
                        LineNumber = logEvent.LineNumber,
                        Timestamp = logEvent.Timestamp,
                        Context = $"IP address found in log event: {ipAddress}",
                        Fields = new Dictionary<string, object>(logEvent.Fields)
                        {
                            ["ip_address"] = ipAddress,
                            ["match_type"] = "ip_address"
                        }
                    });
                }
            }

            return matches;
        }

        private List<MatchDetail> FindUrlMatches(string url, List<LogEvent> events, string rawContent)
        {
            var matches = new List<MatchDetail>();
            var urlPattern = new Regex(Regex.Escape(url), RegexOptions.IgnoreCase);

            foreach (var logEvent in events)
            {
                if (urlPattern.IsMatch(logEvent.RawData))
                {
                    matches.Add(new MatchDetail
                    {
                        MatchedContent = logEvent.RawData,
                        LineNumber = logEvent.LineNumber,
                        Timestamp = logEvent.Timestamp,
                        Context = $"URL found in log event: {url}",
                        Fields = new Dictionary<string, object>(logEvent.Fields)
                        {
                            ["url"] = url,
                            ["match_type"] = "url"
                        }
                    });
                }
            }

            return matches;
        }

        private object? GetFieldValue(LogEvent logEvent, string fieldName)
        {
            // Map common STIX properties to log event fields
            switch (fieldName.ToLower())
            {
                case "name":
                    return logEvent.Fields.GetValueOrDefault("filename") ?? 
                           logEvent.Fields.GetValueOrDefault("process_name") ??
                           logEvent.Fields.GetValueOrDefault("name");
                case "command_line":
                    return logEvent.Fields.GetValueOrDefault("command_line") ??
                           logEvent.Fields.GetValueOrDefault("CommandLine");
                case "src_ref.value":
                    return logEvent.Fields.GetValueOrDefault("src_ip") ??
                           logEvent.Fields.GetValueOrDefault("source_ip");
                case "dst_ref.value":
                    return logEvent.Fields.GetValueOrDefault("dst_ip") ??
                           logEvent.Fields.GetValueOrDefault("destination_ip");
                default:
                    return logEvent.Fields.GetValueOrDefault(fieldName);
            }
        }

        private bool MatchesCondition(string actualValue, StixCondition condition)
        {
            switch (condition.Operator.ToLower())
            {
                case "=":
                case "equals":
                    return string.Equals(actualValue, condition.Value, StringComparison.OrdinalIgnoreCase);
                case "!=":
                case "not equals":
                    return !string.Equals(actualValue, condition.Value, StringComparison.OrdinalIgnoreCase);
                case "contains":
                case "like":
                    return actualValue.Contains(condition.Value, StringComparison.OrdinalIgnoreCase);
                case "matches":
                    try
                    {
                        return Regex.IsMatch(actualValue, condition.Value, RegexOptions.IgnoreCase);
                    }
                    catch
                    {
                        return false;
                    }
                case "in":
                    var values = condition.Value.Split(',').Select(v => v.Trim());
                    return values.Any(v => string.Equals(actualValue, v, StringComparison.OrdinalIgnoreCase));
                default:
                    return false;
            }
        }

        private string GetContext(string content, int offset, int length, int contextSize = 50)
        {
            var start = Math.Max(0, offset - contextSize);
            var end = Math.Min(content.Length, offset + length + contextSize);
            return content.Substring(start, end - start);
        }

        private List<CompiledStixPattern> CompileStixPattern(string pattern)
        {
            var compiledPatterns = new List<CompiledStixPattern>();

            try
            {
                // Simple STIX pattern parsing - in a real implementation, this would be more sophisticated
                var objectPatterns = pattern.Split(new[] { " AND ", " OR " }, StringSplitOptions.RemoveEmptyEntries);

                foreach (var objectPattern in objectPatterns)
                {
                    var trimmedPattern = objectPattern.Trim().Trim('[', ']');
                    var parts = trimmedPattern.Split(':');

                    if (parts.Length >= 2)
                    {
                        var objectType = parts[0].Trim();
                        var conditions = ParseConditions(string.Join(":", parts.Skip(1)));

                        compiledPatterns.Add(new CompiledStixPattern
                        {
                            ObjectType = objectType,
                            Conditions = conditions
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error compiling STIX pattern: {Pattern}", pattern);
            }

            return compiledPatterns;
        }

        private List<StixCondition> ParseConditions(string conditionsString)
        {
            var conditions = new List<StixCondition>();

            try
            {
                // Simple condition parsing
                var conditionParts = conditionsString.Split(new[] { " AND ", " OR " }, StringSplitOptions.RemoveEmptyEntries);

                foreach (var conditionPart in conditionParts)
                {
                    var trimmed = conditionPart.Trim();
                    
                    // Look for operators
                    var operators = new[] { " = ", " != ", " LIKE ", " MATCHES ", " IN " };
                    foreach (var op in operators)
                    {
                        var index = trimmed.IndexOf(op, StringComparison.OrdinalIgnoreCase);
                        if (index > 0)
                        {
                            var property = trimmed.Substring(0, index).Trim();
                            var value = trimmed.Substring(index + op.Length).Trim().Trim('\'', '"');

                            conditions.Add(new StixCondition
                            {
                                Property = property,
                                Operator = op.Trim(),
                                Value = value
                            });
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error parsing STIX conditions: {Conditions}", conditionsString);
            }

            return conditions;
        }

        private ValidationResult ValidateStixPattern(string pattern)
        {
            var result = new ValidationResult { IsValid = true };

            try
            {
                if (string.IsNullOrWhiteSpace(pattern))
                {
                    result.IsValid = false;
                    result.Errors.Add("Pattern cannot be empty");
                    return result;
                }

                // Basic pattern validation
                if (!pattern.Contains(":"))
                {
                    result.IsValid = false;
                    result.Errors.Add("Pattern must contain object type and properties");
                }

                // Check for balanced brackets
                var openBrackets = pattern.Count(c => c == '[');
                var closeBrackets = pattern.Count(c => c == ']');
                if (openBrackets != closeBrackets)
                {
                    result.IsValid = false;
                    result.Errors.Add("Unbalanced brackets in pattern");
                }

                // Validate object types
                var objectTypes = new[] { "file", "process", "network-traffic", "domain-name", "ipv4-addr", "ipv6-addr", "url", "email-message" };
                var hasValidObjectType = objectTypes.Any(type => pattern.Contains(type + ":"));
                
                if (!hasValidObjectType)
                {
                    result.Warnings.Add("Pattern should contain a recognized STIX object type");
                }
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.Errors.Add($"Pattern validation error: {ex.Message}");
            }

            return result;
        }

        private bool IsValidStixId(string id)
        {
            // STIX ID format: {object-type}--{UUID}
            var pattern = @"^[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";
            return Regex.IsMatch(id, pattern);
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

        private double CalculateConfidence(List<MatchDetail> matches, CompiledStixRule rule)
        {
            if (matches.Count == 0) return 0.0;

            // Base confidence on match count and rule validity period
            var baseConfidence = Math.Min(1.0, matches.Count / 5.0);

            // Adjust based on rule validity
            if (rule.ValidUntil.HasValue)
            {
                var totalValidPeriod = rule.ValidUntil.Value - rule.ValidFrom;
                var remainingPeriod = rule.ValidUntil.Value - DateTime.UtcNow;
                
                if (totalValidPeriod.TotalDays > 0)
                {
                    var validityFactor = Math.Max(0.5, remainingPeriod.TotalDays / totalValidPeriod.TotalDays);
                    baseConfidence *= validityFactor;
                }
            }

            return Math.Max(0.1, baseConfidence);
        }

        private List<string> ExtractMitreIds(CompiledStixRule rule)
        {
            var mitreIds = new List<string>();

            // Extract from kill chain phases
            foreach (var phase in rule.KillChainPhases)
            {
                if (phase.KillChainName?.ToLower() == "mitre-attack")
                {
                    var techniqueId = phase.PhaseName?.ToUpper();
                    if (!string.IsNullOrEmpty(techniqueId) && Regex.IsMatch(techniqueId, @"T\d{4}(?:\.\d{3})?"))
                    {
                        mitreIds.Add(techniqueId);
                    }
                }
            }

            // Extract from labels
            foreach (var label in rule.Labels)
            {
                if (label.StartsWith("mitre-attack-") || label.StartsWith("attack."))
                {
                    var techniqueId = label.Replace("mitre-attack-", "").Replace("attack.", "").ToUpper();
                    if (Regex.IsMatch(techniqueId, @"T\d{4}(?:\.\d{3})?"))
                    {
                        mitreIds.Add(techniqueId);
                    }
                }
            }

            return mitreIds.Distinct().ToList();
        }
    }

    // STIX data structures
    public class StixIndicator
    {
        public string Type { get; set; } = string.Empty;
        public string Id { get; set; } = string.Empty;
        public string? SpecVersion { get; set; }
        public string Pattern { get; set; } = string.Empty;
        public string? PatternType { get; set; }
        public DateTime? ValidFrom { get; set; }
        public DateTime? ValidUntil { get; set; }
        public List<string>? Labels { get; set; }
        public List<StixKillChainPhase>? KillChainPhases { get; set; }
    }

    public class StixKillChainPhase
    {
        public string? KillChainName { get; set; }
        public string? PhaseName { get; set; }
    }

    public class CompiledStixRule
    {
        public Guid RuleId { get; set; }
        public string Id { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string SpecVersion { get; set; } = string.Empty;
        public string Pattern { get; set; } = string.Empty;
        public string PatternType { get; set; } = string.Empty;
        public DateTime ValidFrom { get; set; }
        public DateTime? ValidUntil { get; set; }
        public List<string> Labels { get; set; } = new();
        public List<CompiledStixPattern> CompiledPatterns { get; set; } = new();
        public List<StixKillChainPhase> KillChainPhases { get; set; } = new();
        public DateTime CompiledAt { get; set; }
    }

    public class CompiledStixPattern
    {
        public string ObjectType { get; set; } = string.Empty;
        public List<StixCondition> Conditions { get; set; } = new();
    }

    public class StixCondition
    {
        public string Property { get; set; } = string.Empty;
        public string Operator { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
    }
}