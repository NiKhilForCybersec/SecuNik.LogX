using SecuNik.LogX.Core.Entities;
using SecuNik.LogX.Core.Interfaces;
using System.Text.Json;
using System.Text.RegularExpressions;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace SecuNik.LogX.Api.Services.Rules
{
    public class RuleValidationService
    {
        private readonly ILogger<RuleValidationService> _logger;
        private readonly IDeserializer _yamlDeserializer;

        public RuleValidationService(ILogger<RuleValidationService> logger)
        {
            _logger = logger;
            _yamlDeserializer = new DeserializerBuilder()
                .WithNamingConvention(UnderscoredNamingConvention.Instance)
                .Build();
        }

        public async Task<ValidationResult> ValidateRuleAsync(Rule rule)
        {
            try
            {
                return rule.Type switch
                {
                    RuleType.Yara => await ValidateYaraRuleAsync(rule),
                    RuleType.Sigma => await ValidateSigmaRuleAsync(rule),
                    RuleType.Stix => await ValidateStixRuleAsync(rule),
                    RuleType.Custom => await ValidateCustomRuleAsync(rule),
                    _ => new ValidationResult
                    {
                        IsValid = false,
                        Errors = { $"Unknown rule type: {rule.Type}" }
                    }
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

        public async Task<ValidationResult> ValidateRuleContentAsync(string content, RuleType ruleType)
        {
            try
            {
                var tempRule = new Rule
                {
                    Content = content,
                    Type = ruleType,
                    Name = "temp_validation_rule"
                };

                return await ValidateRuleAsync(tempRule);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating rule content for type {RuleType}", ruleType);
                return new ValidationResult
                {
                    IsValid = false,
                    Errors = { $"Content validation error: {ex.Message}" }
                };
            }
        }

        public async Task<List<ValidationResult>> ValidateMultipleRulesAsync(List<Rule> rules)
        {
            var results = new List<ValidationResult>();

            foreach (var rule in rules)
            {
                var result = await ValidateRuleAsync(rule);
                result.Metadata["rule_id"] = rule.Id;
                result.Metadata["rule_name"] = rule.Name;
                results.Add(result);
            }

            return results;
        }

        public ValidationResult ValidateRuleMetadata(Rule rule)
        {
            var result = new ValidationResult { IsValid = true };

            // Validate required fields
            if (string.IsNullOrWhiteSpace(rule.Name))
            {
                result.IsValid = false;
                result.Errors.Add("Rule name is required");
            }
            else if (rule.Name.Length > 200)
            {
                result.IsValid = false;
                result.Errors.Add("Rule name cannot exceed 200 characters");
            }

            if (string.IsNullOrWhiteSpace(rule.Content))
            {
                result.IsValid = false;
                result.Errors.Add("Rule content is required");
            }

            // Validate optional fields
            if (!string.IsNullOrEmpty(rule.Description) && rule.Description.Length > 1000)
            {
                result.Warnings.Add("Rule description is very long (>1000 characters)");
            }

            if (!string.IsNullOrEmpty(rule.Author) && rule.Author.Length > 100)
            {
                result.Warnings.Add("Author name is very long (>100 characters)");
            }

            if (!string.IsNullOrEmpty(rule.Category) && rule.Category.Length > 100)
            {
                result.Warnings.Add("Category name is very long (>100 characters)");
            }

            // Validate rule name format
            if (!string.IsNullOrWhiteSpace(rule.Name))
            {
                if (!Regex.IsMatch(rule.Name, @"^[a-zA-Z0-9_\-\s]+$"))
                {
                    result.Warnings.Add("Rule name contains special characters that may cause issues");
                }
            }

            return result;
        }

        private async Task<ValidationResult> ValidateYaraRuleAsync(Rule rule)
        {
            var result = new ValidationResult { IsValid = true };

            try
            {
                // Basic structure validation
                if (!rule.Content.Contains("rule "))
                {
                    result.IsValid = false;
                    result.Errors.Add("YARA rule must contain 'rule' keyword");
                }

                if (!rule.Content.Contains("condition:"))
                {
                    result.IsValid = false;
                    result.Errors.Add("YARA rule must contain 'condition:' section");
                }

                // Validate rule name format
                var ruleNameMatch = Regex.Match(rule.Content,
                    @"rule\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\{",
                    RegexOptions.IgnoreCase);

                if (!ruleNameMatch.Success)
                {
                    result.IsValid = false;
                    result.Errors.Add("Invalid YARA rule name format");
                }
                else
                {
                    var ruleName = ruleNameMatch.Groups[1].Value;
                    if (string.IsNullOrEmpty(ruleName))
                    {
                        result.IsValid = false;
                        result.Errors.Add("YARA rule name cannot be empty");
                    }
                    else if (ruleName.Length > 128)
                    {
                        result.Warnings.Add("YARA rule name is very long (>128 characters)");
                    }
                }

                // Check for balanced braces
                var openBraces = rule.Content.Count(c => c == '{');
                var closeBraces = rule.Content.Count(c => c == '}');
                if (openBraces != closeBraces)
                {
                    result.IsValid = false;
                    result.Errors.Add("Unbalanced braces in YARA rule");
                }

                // Validate strings section if present
                if (rule.Content.Contains("strings:"))
                {
                    ValidateYaraStringsSection(rule.Content, result);
                }

                // Validate meta section if present
                if (rule.Content.Contains("meta:"))
                {
                    ValidateYaraMetaSection(rule.Content, result);
                }

                // Validate condition section
                ValidateYaraConditionSection(rule.Content, result);

                // Check for common YARA keywords and functions
                ValidateYaraKeywords(rule.Content, result);

                // Performance warnings
                CheckYaraPerformanceIssues(rule.Content, result);

                return result;
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.Errors.Add($"YARA validation error: {ex.Message}");
                return result;
            }
        }

        private async Task<ValidationResult> ValidateSigmaRuleAsync(Rule rule)
        {
            var result = new ValidationResult { IsValid = true };

            try
            {
                // Try to parse as YAML
                object sigmaRule;
                try
                {
                    sigmaRule = _yamlDeserializer.Deserialize<object>(rule.Content);
                }
                catch (Exception ex)
                {
                    result.IsValid = false;
                    result.Errors.Add($"Invalid YAML format: {ex.Message}");
                    return result;
                }

                // Convert to dictionary for easier validation
                var ruleDict = sigmaRule as Dictionary<object, object>;
                if (ruleDict == null)
                {
                    result.IsValid = false;
                    result.Errors.Add("Sigma rule must be a YAML object");
                    return result;
                }

                // Validate required fields
                if (!ruleDict.ContainsKey("title"))
                {
                    result.IsValid = false;
                    result.Errors.Add("Sigma rule must have a 'title' field");
                }

                if (!ruleDict.ContainsKey("detection"))
                {
                    result.IsValid = false;
                    result.Errors.Add("Sigma rule must have a 'detection' section");
                }
                else
                {
                    ValidateSigmaDetectionSection(ruleDict["detection"], result);
                }

                // Validate optional but recommended fields
                if (!ruleDict.ContainsKey("id"))
                {
                    result.Warnings.Add("Sigma rule should have an 'id' field");
                }
                else
                {
                    var id = ruleDict["id"]?.ToString();
                    if (!string.IsNullOrEmpty(id) && !Guid.TryParse(id, out _))
                    {
                        result.Warnings.Add("Sigma rule ID should be a valid UUID");
                    }
                }

                if (!ruleDict.ContainsKey("logsource"))
                {
                    result.Warnings.Add("Sigma rule should have a 'logsource' section for better matching");
                }

                // Validate level
                if (ruleDict.ContainsKey("level"))
                {
                    var level = ruleDict["level"]?.ToString()?.ToLower();
                    var validLevels = new[] { "informational", "low", "medium", "high", "critical" };
                    if (!string.IsNullOrEmpty(level) && !validLevels.Contains(level))
                    {
                        result.Warnings.Add($"Unknown level '{level}'. Valid levels: {string.Join(", ", validLevels)}");
                    }
                }

                // Validate status
                if (ruleDict.ContainsKey("status"))
                {
                    var status = ruleDict["status"]?.ToString()?.ToLower();
                    var validStatuses = new[] { "stable", "test", "experimental", "deprecated", "unsupported" };
                    if (!string.IsNullOrEmpty(status) && !validStatuses.Contains(status))
                    {
                        result.Warnings.Add($"Unknown status '{status}'. Valid statuses: {string.Join(", ", validStatuses)}");
                    }
                }

                // Validate tags format
                if (ruleDict.ContainsKey("tags"))
                {
                    ValidateSigmaTags(ruleDict["tags"], result);
                }

                return result;
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.Errors.Add($"Sigma validation error: {ex.Message}");
                return result;
            }
        }

        private async Task<ValidationResult> ValidateStixRuleAsync(Rule rule)
        {
            var result = new ValidationResult { IsValid = true };

            try
            {
                // Try to parse as JSON
                JsonDocument stixDoc;
                try
                {
                    stixDoc = JsonDocument.Parse(rule.Content);
                }
                catch (Exception ex)
                {
                    result.IsValid = false;
                    result.Errors.Add($"Invalid JSON format: {ex.Message}");
                    return result;
                }

                using (stixDoc)
                {
                    var root = stixDoc.RootElement;

                    // Validate required STIX fields
                    if (!root.TryGetProperty("type", out var typeElement))
                    {
                        result.IsValid = false;
                        result.Errors.Add("STIX object must have a 'type' field");
                    }
                    else
                    {
                        var type = typeElement.GetString();
                        if (type != "indicator")
                        {
                            result.IsValid = false;
                            result.Errors.Add("STIX object must be of type 'indicator'");
                        }
                    }

                    if (!root.TryGetProperty("id", out var idElement))
                    {
                        result.IsValid = false;
                        result.Errors.Add("STIX object must have an 'id' field");
                    }
                    else
                    {
                        var id = idElement.GetString();
                        if (!IsValidStixId(id))
                        {
                            result.IsValid = false;
                            result.Errors.Add("Invalid STIX ID format. Must be {object-type}--{UUID}");
                        }
                    }

                    if (!root.TryGetProperty("pattern", out var patternElement))
                    {
                        result.IsValid = false;
                        result.Errors.Add("STIX indicator must have a 'pattern' field");
                    }
                    else
                    {
                        var pattern = patternElement.GetString();
                        if (string.IsNullOrWhiteSpace(pattern))
                        {
                            result.IsValid = false;
                            result.Errors.Add("STIX pattern cannot be empty");
                        }
                        else
                        {
                            ValidateStixPattern(pattern, result);
                        }
                    }

                    // Validate optional but recommended fields
                    if (!root.TryGetProperty("spec_version", out _))
                    {
                        result.Warnings.Add("STIX object should have a 'spec_version' field");
                    }

                    if (!root.TryGetProperty("labels", out var labelsElement))
                    {
                        result.Warnings.Add("STIX indicator should have 'labels' for categorization");
                    }
                    else if (labelsElement.ValueKind == JsonValueKind.Array && labelsElement.GetArrayLength() == 0)
                    {
                        result.Warnings.Add("STIX indicator labels array is empty");
                    }

                    if (!root.TryGetProperty("valid_from", out _))
                    {
                        result.Warnings.Add("STIX indicator should have a 'valid_from' field");
                    }

                    // Validate pattern type
                    if (root.TryGetProperty("pattern_type", out var patternTypeElement))
                    {
                        var patternType = patternTypeElement.GetString();
                        var validPatternTypes = new[] { "stix", "pcre", "sigma", "snort", "suricata", "yara" };
                        if (!string.IsNullOrEmpty(patternType) && !validPatternTypes.Contains(patternType.ToLower()))
                        {
                            result.Warnings.Add($"Unknown pattern type '{patternType}'");
                        }
                    }
                }

                return result;
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.Errors.Add($"STIX validation error: {ex.Message}");
                return result;
            }
        }

        private async Task<ValidationResult> ValidateCustomRuleAsync(Rule rule)
        {
            var result = new ValidationResult { IsValid = true };

            try
            {
                // Basic validation for custom rules
                if (string.IsNullOrWhiteSpace(rule.Content))
                {
                    result.IsValid = false;
                    result.Errors.Add("Custom rule content cannot be empty");
                    return result;
                }

                // Check if it might be a known format
                if (rule.Content.Contains("rule ") && rule.Content.Contains("condition:"))
                {
                    result.Warnings.Add("Content appears to be YARA format. Consider changing rule type to YARA.");
                }
                else if (rule.Content.Contains("title:") && rule.Content.Contains("detection:"))
                {
                    result.Warnings.Add("Content appears to be Sigma format. Consider changing rule type to Sigma.");
                }
                else if (rule.Content.TrimStart().StartsWith("{") && rule.Content.Contains("\"type\": \"indicator\""))
                {
                    result.Warnings.Add("Content appears to be STIX format. Consider changing rule type to STIX.");
                }

                // Basic content validation
                if (rule.Content.Length > 100000) // 100KB
                {
                    result.Warnings.Add("Rule content is very large (>100KB). Consider breaking it into smaller rules.");
                }

                // Check for potentially problematic content
                var suspiciousPatterns = new[]
                {
                    @"<script[^>]*>.*?</script>",
                    @"javascript:",
                    @"eval\s*\(",
                    @"document\.write",
                    @"innerHTML\s*="
                };

                foreach (var pattern in suspiciousPatterns)
                {
                    if (Regex.IsMatch(rule.Content, pattern, RegexOptions.IgnoreCase))
                    {
                        result.Warnings.Add("Rule content contains potentially unsafe patterns");
                        break;
                    }
                }

                return result;
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.Errors.Add($"Custom rule validation error: {ex.Message}");
                return result;
            }
        }

        private void ValidateYaraStringsSection(string content, ValidationResult result)
        {
            var stringsSection = ExtractSection(content, "strings:");
            if (string.IsNullOrWhiteSpace(stringsSection))
            {
                result.Warnings.Add("Empty strings section found");
                return;
            }

            var stringPattern = @"\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)";
            var matches = Regex.Matches(stringsSection, stringPattern);

            if (matches.Count == 0)
            {
                result.Warnings.Add("No string definitions found in strings section");
            }

            var stringNames = new HashSet<string>();
            foreach (Match match in matches)
            {
                var name = match.Groups[1].Value;
                var value = match.Groups[2].Value.Trim();

                // Check for duplicate string names
                if (!stringNames.Add(name))
                {
                    result.Errors.Add($"Duplicate string name: ${name}");
                }

                // Validate string value
                if (string.IsNullOrEmpty(value))
                {
                    result.Errors.Add($"String value for ${name} cannot be empty");
                }

                // Check for regex patterns
                if (value.StartsWith("/") && value.EndsWith("/"))
                {
                    try
                    {
                        var regexPattern = value.Substring(1, value.Length - 2);
                        new Regex(regexPattern);
                    }
                    catch (ArgumentException)
                    {
                        result.Errors.Add($"Invalid regex pattern in string ${name}");
                    }
                }
            }
        }

        private void ValidateYaraMetaSection(string content, ValidationResult result)
        {
            var metaSection = ExtractSection(content, "meta:");
            if (string.IsNullOrWhiteSpace(metaSection))
            {
                result.Warnings.Add("Empty meta section found");
                return;
            }

            // Check for common meta fields
            var recommendedFields = new[] { "description", "author", "date", "version" };
            foreach (var field in recommendedFields)
            {
                if (!metaSection.Contains($"{field} ="))
                {
                    result.Suggestions[$"missing_{field}"] = $"Consider adding {field} to meta section";
                }
            }
        }

        private void ValidateYaraConditionSection(string content, ValidationResult result)
        {
            var conditionSection = ExtractSection(content, "condition:");
            if (string.IsNullOrWhiteSpace(conditionSection))
            {
                result.IsValid = false;
                result.Errors.Add("Empty condition section");
                return;
            }

            // Check for common condition patterns
            if (conditionSection.Trim() == "true")
            {
                result.Warnings.Add("Condition is always true - this may cause performance issues");
            }

            // Check for string references in condition
            var stringRefs = Regex.Matches(conditionSection, @"\$[a-zA-Z_][a-zA-Z0-9_]*");
            if (stringRefs.Count == 0 && !conditionSection.Contains("filesize") && !conditionSection.Contains("entrypoint"))
            {
                result.Warnings.Add("Condition doesn't reference any strings or file properties");
            }
        }

        private void ValidateYaraKeywords(string content, ValidationResult result)
        {
            // Check for deprecated or problematic keywords
            var deprecatedKeywords = new[] { "global", "private" };
            foreach (var keyword in deprecatedKeywords)
            {
                if (content.Contains($"{keyword} "))
                {
                    result.Warnings.Add($"Keyword '{keyword}' is deprecated or should be used carefully");
                }
            }
        }

        private void CheckYaraPerformanceIssues(string content, ValidationResult result)
        {
            // Check for potential performance issues
            if (content.Contains("for ") && content.Contains("of them"))
            {
                result.Warnings.Add("Complex 'for' loops may impact performance");
            }

            if (Regex.Matches(content, @"\$[a-zA-Z_][a-zA-Z0-9_]*").Count > 50)
            {
                result.Warnings.Add("Large number of strings may impact performance");
            }
        }

        private void ValidateSigmaDetectionSection(object detection, ValidationResult result)
        {
            if (detection is not Dictionary<object, object> detectionDict)
            {
                result.IsValid = false;
                result.Errors.Add("Detection section must be an object");
                return;
            }

            if (!detectionDict.ContainsKey("condition"))
            {
                result.IsValid = false;
                result.Errors.Add("Detection section must have a 'condition' field");
            }

            // Check that referenced selections exist
            var condition = detectionDict["condition"]?.ToString();
            if (!string.IsNullOrEmpty(condition))
            {
                var referencedSelections = ExtractSelectionReferences(condition);
                foreach (var reference in referencedSelections)
                {
                    if (!detectionDict.ContainsKey(reference))
                    {
                        result.Errors.Add($"Condition references undefined selection '{reference}'");
                    }
                }
            }
        }

        private void ValidateSigmaTags(object tags, ValidationResult result)
        {
            if (tags is not List<object> tagsList)
            {
                result.Warnings.Add("Tags should be a list");
                return;
            }

            foreach (var tag in tagsList)
            {
                var tagString = tag?.ToString();
                if (string.IsNullOrEmpty(tagString))
                {
                    result.Warnings.Add("Empty tag found");
                    continue;
                }

                // Validate MITRE ATT&CK tags
                if (tagString.StartsWith("attack."))
                {
                    var techniqueId = tagString.Substring(7);
                    if (!Regex.IsMatch(techniqueId, @"^t\d{4}(\.\d{3})?$", RegexOptions.IgnoreCase))
                    {
                        result.Warnings.Add($"Invalid MITRE ATT&CK tag format: {tagString}");
                    }
                }
            }
        }

        private void ValidateStixPattern(string pattern, ValidationResult result)
        {
            if (string.IsNullOrWhiteSpace(pattern))
            {
                result.IsValid = false;
                result.Errors.Add("STIX pattern cannot be empty");
                return;
            }

            // Check for balanced brackets
            var openBrackets = pattern.Count(c => c == '[');
            var closeBrackets = pattern.Count(c => c == ']');
            if (openBrackets != closeBrackets)
            {
                result.IsValid = false;
                result.Errors.Add("Unbalanced brackets in STIX pattern");
            }

            // Check for valid object types
            var objectTypes = new[] { "file", "process", "network-traffic", "domain-name", "ipv4-addr", "ipv6-addr", "url", "email-message" };
            var hasValidObjectType = objectTypes.Any(type => pattern.Contains($"{type}:"));

            if (!hasValidObjectType)
            {
                result.Warnings.Add("Pattern should contain a recognized STIX object type");
            }

            // Check for basic pattern structure
            if (!pattern.Contains(":"))
            {
                result.IsValid = false;
                result.Errors.Add("STIX pattern must contain object type and properties");
            }
        }

        private bool IsValidStixId(string? id)
        {
            if (string.IsNullOrEmpty(id)) return false;

            // STIX ID format: {object-type}--{UUID}
            var pattern = @"^[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";
            return Regex.IsMatch(id, pattern);
        }

        private string ExtractSection(string content, string sectionName)
        {
            var sectionStart = content.IndexOf(sectionName);
            if (sectionStart == -1) return string.Empty;

            sectionStart += sectionName.Length;
            var nextSection = FindNextSection(content, sectionStart);

            if (nextSection == -1)
            {
                var ruleEnd = content.LastIndexOf('}');
                nextSection = ruleEnd == -1 ? content.Length : ruleEnd;
            }

            return content.Substring(sectionStart, nextSection - sectionStart).Trim();
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
    }
}