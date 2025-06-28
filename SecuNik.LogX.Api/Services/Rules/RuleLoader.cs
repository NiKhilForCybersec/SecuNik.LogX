using SecuNik.LogX.Core.Entities;
using SecuNik.LogX.Api.Data;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

namespace SecuNik.LogX.Api.Services.Rules
{
    public class RuleLoader
    {
        private readonly LogXDbContext _dbContext;
        private readonly ILogger<RuleLoader> _logger;
        private readonly string _rulesBasePath;

        public RuleLoader(LogXDbContext dbContext, ILogger<RuleLoader> logger, IConfiguration configuration)
        {
            _dbContext = dbContext;
            _logger = logger;
            _rulesBasePath = Path.Combine(
                configuration.GetValue<string>("Storage:BasePath") ?? "Storage",
                configuration.GetValue<string>("Storage:RulesPath") ?? "Rules"
            );
        }

        public async Task LoadAllRulesAsync()
        {
            try
            {
                _logger.LogInformation("Loading rules from {RulesPath}", _rulesBasePath);

                // Ensure rules directories exist
                EnsureRuleDirectories();

                // Load built-in rules first
                await LoadBuiltInRulesAsync();

                // Load YARA rules
                await LoadYaraRulesAsync();

                // Load Sigma rules
                await LoadSigmaRulesAsync();

                // Load STIX rules
                await LoadStixRulesAsync();

                // Load custom rules
                await LoadCustomRulesAsync();

                _logger.LogInformation("Rule loading completed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading rules");
                throw;
            }
        }

        public async Task LoadRulesByTypeAsync(RuleType ruleType)
        {
            try
            {
                switch (ruleType)
                {
                    case RuleType.Yara:
                        await LoadYaraRulesAsync();
                        break;
                    case RuleType.Sigma:
                        await LoadSigmaRulesAsync();
                        break;
                    case RuleType.Stix:
                        await LoadStixRulesAsync();
                        break;
                    case RuleType.Custom:
                        await LoadCustomRulesAsync();
                        break;
                    default:
                        _logger.LogWarning("Unknown rule type: {RuleType}", ruleType);
                        break;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading rules of type {RuleType}", ruleType);
                throw;
            }
        }

        public async Task<Rule?> LoadRuleFromFileAsync(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    _logger.LogWarning("Rule file not found: {FilePath}", filePath);
                    return null;
                }

                var content = await File.ReadAllTextAsync(filePath);
                var fileName = Path.GetFileName(filePath);
                var extension = Path.GetExtension(filePath).ToLowerInvariant();

                var ruleType = DetermineRuleType(extension, content);
                if (ruleType == null)
                {
                    _logger.LogWarning("Could not determine rule type for file: {FilePath}", filePath);
                    return null;
                }

                var rule = CreateRuleFromContent(fileName, content, ruleType.Value, isBuiltIn: false);
                return rule;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading rule from file {FilePath}", filePath);
                return null;
            }
        }

        public async Task SaveRuleToFileAsync(Rule rule)
        {
            try
            {
                var ruleDirectory = GetRuleDirectory(rule.Type);
                var fileName = SanitizeFileName(rule.Name) + GetRuleFileExtension(rule.Type);
                var filePath = Path.Combine(ruleDirectory, fileName);

                await File.WriteAllTextAsync(filePath, rule.Content);
                _logger.LogInformation("Saved rule {RuleName} to {FilePath}", rule.Name, filePath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving rule {RuleName} to file", rule.Name);
                throw;
            }
        }

        public async Task DeleteRuleFileAsync(Rule rule)
        {
            try
            {
                var ruleDirectory = GetRuleDirectory(rule.Type);
                var fileName = SanitizeFileName(rule.Name) + GetRuleFileExtension(rule.Type);
                var filePath = Path.Combine(ruleDirectory, fileName);

                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                    _logger.LogInformation("Deleted rule file {FilePath}", filePath);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting rule file for {RuleName}", rule.Name);
                throw;
            }
        }

        private async Task LoadBuiltInRulesAsync()
        {
            try
            {
                // Built-in rules are already seeded in the database
                // This method can be used to update them if needed
                var builtInRules = await _dbContext.Rules.Where(r => r.IsBuiltIn).ToListAsync();
                _logger.LogInformation("Found {RuleCount} built-in rules in database", builtInRules.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading built-in rules");
                throw;
            }
        }

        private async Task LoadYaraRulesAsync()
        {
            try
            {
                var yaraDirectory = Path.Combine(_rulesBasePath, "YARA");
                if (!Directory.Exists(yaraDirectory))
                {
                    _logger.LogInformation("YARA rules directory not found: {Directory}", yaraDirectory);
                    return;
                }

                var yaraFiles = Directory.GetFiles(yaraDirectory, "*.yar", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(yaraDirectory, "*.yara", SearchOption.AllDirectories));

                var loadedCount = 0;
                foreach (var filePath in yaraFiles)
                {
                    try
                    {
                        var content = await File.ReadAllTextAsync(filePath);
                        var fileName = Path.GetFileNameWithoutExtension(filePath);

                        var existingRule = await _dbContext.Rules
                            .FirstOrDefaultAsync(r => r.Name == fileName && r.Type == RuleType.Yara && !r.IsBuiltIn);

                        if (existingRule == null)
                        {
                            var rule = CreateRuleFromContent(fileName, content, RuleType.Yara, isBuiltIn: false);
                            _dbContext.Rules.Add(rule);
                            loadedCount++;
                        }
                        else
                        {
                            // Update existing rule if content has changed
                            if (existingRule.Content != content)
                            {
                                existingRule.Content = content;
                                existingRule.UpdatedAt = DateTime.UtcNow;
                                loadedCount++;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error loading YARA rule from {FilePath}", filePath);
                    }
                }

                if (loadedCount > 0)
                {
                    await _dbContext.SaveChangesAsync();
                }

                _logger.LogInformation("Loaded {LoadedCount} YARA rules from {Directory}", loadedCount, yaraDirectory);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading YARA rules");
                throw;
            }
        }

        private async Task LoadSigmaRulesAsync()
        {
            try
            {
                var sigmaDirectory = Path.Combine(_rulesBasePath, "Sigma");
                if (!Directory.Exists(sigmaDirectory))
                {
                    _logger.LogInformation("Sigma rules directory not found: {Directory}", sigmaDirectory);
                    return;
                }

                var sigmaFiles = Directory.GetFiles(sigmaDirectory, "*.yml", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(sigmaDirectory, "*.yaml", SearchOption.AllDirectories));

                var loadedCount = 0;
                foreach (var filePath in sigmaFiles)
                {
                    try
                    {
                        var content = await File.ReadAllTextAsync(filePath);
                        var fileName = Path.GetFileNameWithoutExtension(filePath);

                        var existingRule = await _dbContext.Rules
                            .FirstOrDefaultAsync(r => r.Name == fileName && r.Type == RuleType.Sigma && !r.IsBuiltIn);

                        if (existingRule == null)
                        {
                            var rule = CreateRuleFromContent(fileName, content, RuleType.Sigma, isBuiltIn: false);
                            _dbContext.Rules.Add(rule);
                            loadedCount++;
                        }
                        else
                        {
                            // Update existing rule if content has changed
                            if (existingRule.Content != content)
                            {
                                existingRule.Content = content;
                                existingRule.UpdatedAt = DateTime.UtcNow;
                                loadedCount++;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error loading Sigma rule from {FilePath}", filePath);
                    }
                }

                if (loadedCount > 0)
                {
                    await _dbContext.SaveChangesAsync();
                }

                _logger.LogInformation("Loaded {LoadedCount} Sigma rules from {Directory}", loadedCount, sigmaDirectory);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading Sigma rules");
                throw;
            }
        }

        private async Task LoadStixRulesAsync()
        {
            try
            {
                var stixDirectory = Path.Combine(_rulesBasePath, "STIX");
                if (!Directory.Exists(stixDirectory))
                {
                    _logger.LogInformation("STIX rules directory not found: {Directory}", stixDirectory);
                    return;
                }

                var stixFiles = Directory.GetFiles(stixDirectory, "*.json", SearchOption.AllDirectories);

                var loadedCount = 0;
                foreach (var filePath in stixFiles)
                {
                    try
                    {
                        var content = await File.ReadAllTextAsync(filePath);
                        var fileName = Path.GetFileNameWithoutExtension(filePath);

                        // Try to extract title from STIX content
                        var ruleName = ExtractStixTitle(content) ?? fileName;

                        var existingRule = await _dbContext.Rules
                            .FirstOrDefaultAsync(r => r.Name == ruleName && r.Type == RuleType.Stix && !r.IsBuiltIn);

                        if (existingRule == null)
                        {
                            var rule = CreateRuleFromContent(ruleName, content, RuleType.Stix, isBuiltIn: false);
                            _dbContext.Rules.Add(rule);
                            loadedCount++;
                        }
                        else
                        {
                            // Update existing rule if content has changed
                            if (existingRule.Content != content)
                            {
                                existingRule.Content = content;
                                existingRule.UpdatedAt = DateTime.UtcNow;
                                loadedCount++;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error loading STIX rule from {FilePath}", filePath);
                    }
                }

                if (loadedCount > 0)
                {
                    await _dbContext.SaveChangesAsync();
                }

                _logger.LogInformation("Loaded {LoadedCount} STIX rules from {Directory}", loadedCount, stixDirectory);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading STIX rules");
                throw;
            }
        }

        private async Task LoadCustomRulesAsync()
        {
            try
            {
                var customDirectory = Path.Combine(_rulesBasePath, "Custom");
                if (!Directory.Exists(customDirectory))
                {
                    _logger.LogInformation("Custom rules directory not found: {Directory}", customDirectory);
                    return;
                }

                var customFiles = Directory.GetFiles(customDirectory, "*.*", SearchOption.AllDirectories)
                    .Where(f => IsRuleFile(f));

                var loadedCount = 0;
                foreach (var filePath in customFiles)
                {
                    try
                    {
                        var content = await File.ReadAllTextAsync(filePath);
                        var fileName = Path.GetFileNameWithoutExtension(filePath);
                        var extension = Path.GetExtension(filePath).ToLowerInvariant();

                        var ruleType = DetermineRuleType(extension, content);
                        if (ruleType == null)
                        {
                            _logger.LogWarning("Could not determine rule type for custom rule: {FilePath}", filePath);
                            continue;
                        }

                        var existingRule = await _dbContext.Rules
                            .FirstOrDefaultAsync(r => r.Name == fileName && r.Type == ruleType.Value && !r.IsBuiltIn);

                        if (existingRule == null)
                        {
                            var rule = CreateRuleFromContent(fileName, content, ruleType.Value, isBuiltIn: false);
                            _dbContext.Rules.Add(rule);
                            loadedCount++;
                        }
                        else
                        {
                            // Update existing rule if content has changed
                            if (existingRule.Content != content)
                            {
                                existingRule.Content = content;
                                existingRule.UpdatedAt = DateTime.UtcNow;
                                loadedCount++;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error loading custom rule from {FilePath}", filePath);
                    }
                }

                if (loadedCount > 0)
                {
                    await _dbContext.SaveChangesAsync();
                }

                _logger.LogInformation("Loaded {LoadedCount} custom rules from {Directory}", loadedCount, customDirectory);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading custom rules");
                throw;
            }
        }

        private void EnsureRuleDirectories()
        {
            var directories = new[]
            {
                _rulesBasePath,
                Path.Combine(_rulesBasePath, "YARA"),
                Path.Combine(_rulesBasePath, "Sigma"),
                Path.Combine(_rulesBasePath, "STIX"),
                Path.Combine(_rulesBasePath, "Custom")
            };

            foreach (var directory in directories)
            {
                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                    _logger.LogInformation("Created rules directory: {Directory}", directory);
                }
            }
        }

        private Rule CreateRuleFromContent(string name, string content, RuleType ruleType, bool isBuiltIn)
        {
            var rule = new Rule
            {
                Name = name,
                Type = ruleType,
                Content = content,
                IsBuiltIn = isBuiltIn,
                IsEnabled = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                Priority = isBuiltIn ? 10 : 100
            };

            // Extract metadata based on rule type
            switch (ruleType)
            {
                case RuleType.Yara:
                    ExtractYaraMetadata(rule);
                    break;
                case RuleType.Sigma:
                    ExtractSigmaMetadata(rule);
                    break;
                case RuleType.Stix:
                    ExtractStixMetadata(rule);
                    break;
                case RuleType.Custom:
                    ExtractCustomMetadata(rule);
                    break;
            }

            return rule;
        }

        private void ExtractYaraMetadata(Rule rule)
        {
            try
            {
                // Extract metadata from YARA rule
                var metaMatch = System.Text.RegularExpressions.Regex.Match(rule.Content, @"meta:\s*\{([^}]*)\}", System.Text.RegularExpressions.RegexOptions.Singleline);
                if (metaMatch.Success)
                {
                    var metaContent = metaMatch.Groups[1].Value;
                    
                    // Extract description
                    var descMatch = System.Text.RegularExpressions.Regex.Match(metaContent, @"description\s*=\s*""([^""]*)""");
                    if (descMatch.Success)
                    {
                        rule.Description = descMatch.Groups[1].Value;
                    }

                    // Extract author
                    var authorMatch = System.Text.RegularExpressions.Regex.Match(metaContent, @"author\s*=\s*""([^""]*)""");
                    if (authorMatch.Success)
                    {
                        rule.Author = authorMatch.Groups[1].Value;
                    }

                    // Extract severity
                    var severityMatch = System.Text.RegularExpressions.Regex.Match(metaContent, @"severity\s*=\s*""([^""]*)""");
                    if (severityMatch.Success)
                    {
                        rule.Severity = ParseThreatLevel(severityMatch.Groups[1].Value);
                    }
                }

                // Set default values if not found
                if (string.IsNullOrEmpty(rule.Description))
                    rule.Description = $"YARA rule: {rule.Name}";
                if (string.IsNullOrEmpty(rule.Author))
                    rule.Author = "Unknown";
                if (rule.Severity == default)
                    rule.Severity = ThreatLevel.Medium;

                rule.Category = "malware";
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error extracting YARA metadata for rule {RuleName}", rule.Name);
            }
        }

        private void ExtractSigmaMetadata(Rule rule)
        {
            try
            {
                // Extract metadata from Sigma rule (YAML format)
                var lines = rule.Content.Split('\n');
                
                foreach (var line in lines)
                {
                    var trimmedLine = line.Trim();
                    
                    if (trimmedLine.StartsWith("title:"))
                    {
                        rule.Description = trimmedLine.Substring(6).Trim();
                    }
                    else if (trimmedLine.StartsWith("author:"))
                    {
                        rule.Author = trimmedLine.Substring(7).Trim();
                    }
                    else if (trimmedLine.StartsWith("level:"))
                    {
                        var level = trimmedLine.Substring(6).Trim();
                        rule.Severity = ParseThreatLevel(level);
                    }
                    else if (trimmedLine.StartsWith("logsource:"))
                    {
                        // Start of logsource section, could extract category
                        break;
                    }
                }

                // Set default values if not found
                if (string.IsNullOrEmpty(rule.Description))
                    rule.Description = $"Sigma rule: {rule.Name}";
                if (string.IsNullOrEmpty(rule.Author))
                    rule.Author = "Unknown";
                if (rule.Severity == default)
                    rule.Severity = ThreatLevel.Medium;

                rule.Category = "detection";
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error extracting Sigma metadata for rule {RuleName}", rule.Name);
            }
        }

        private void ExtractStixMetadata(Rule rule)
        {
            try
            {
                // Extract metadata from STIX rule (JSON format)
                using var doc = JsonDocument.Parse(rule.Content);
                var root = doc.RootElement;

                if (root.TryGetProperty("name", out var nameElement))
                {
                    rule.Description = nameElement.GetString() ?? rule.Name;
                }

                if (root.TryGetProperty("created_by_ref", out var authorElement))
                {
                    rule.Author = authorElement.GetString() ?? "Unknown";
                }

                if (root.TryGetProperty("labels", out var labelsElement) && labelsElement.ValueKind == JsonValueKind.Array)
                {
                    var labels = new List<string>();
                    foreach (var label in labelsElement.EnumerateArray())
                    {
                        if (label.ValueKind == JsonValueKind.String)
                        {
                            labels.Add(label.GetString()!);
                        }
                    }
                    rule.SetTags(labels);
                }

                // Set default values if not found
                if (string.IsNullOrEmpty(rule.Description))
                    rule.Description = $"STIX rule: {rule.Name}";
                if (string.IsNullOrEmpty(rule.Author))
                    rule.Author = "Unknown";
                if (rule.Severity == default)
                    rule.Severity = ThreatLevel.Medium;

                rule.Category = "indicator";
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error extracting STIX metadata for rule {RuleName}", rule.Name);
            }
        }

        private void ExtractCustomMetadata(Rule rule)
        {
            // For custom rules, set basic defaults
            if (string.IsNullOrEmpty(rule.Description))
                rule.Description = $"Custom rule: {rule.Name}";
            if (string.IsNullOrEmpty(rule.Author))
                rule.Author = "User";
            if (rule.Severity == default)
                rule.Severity = ThreatLevel.Medium;

            rule.Category = "custom";
        }

        private ThreatLevel ParseThreatLevel(string level)
        {
            return level.ToLowerInvariant() switch
            {
                "critical" => ThreatLevel.Critical,
                "high" => ThreatLevel.High,
                "medium" => ThreatLevel.Medium,
                "low" => ThreatLevel.Low,
                "info" or "informational" => ThreatLevel.Info,
                _ => ThreatLevel.Medium
            };
        }

        private RuleType? DetermineRuleType(string extension, string content)
        {
            switch (extension)
            {
                case ".yar":
                case ".yara":
                    return RuleType.Yara;
                case ".yml":
                case ".yaml":
                    return RuleType.Sigma;
                case ".json":
                    // Check if it's STIX format
                    if (content.Contains("\"type\": \"indicator\"") || content.Contains("\"spec_version\""))
                    {
                        return RuleType.Stix;
                    }
                    return RuleType.Custom;
                default:
                    // Try to determine from content
                    if (content.Contains("rule ") && content.Contains("condition:"))
                        return RuleType.Yara;
                    if (content.Contains("title:") && content.Contains("detection:"))
                        return RuleType.Sigma;
                    if (content.Contains("\"type\": \"indicator\""))
                        return RuleType.Stix;
                    return RuleType.Custom;
            }
        }

        private string? ExtractStixTitle(string content)
        {
            try
            {
                using var doc = JsonDocument.Parse(content);
                var root = doc.RootElement;

                if (root.TryGetProperty("name", out var nameElement))
                {
                    return nameElement.GetString();
                }

                return null;
            }
            catch
            {
                return null;
            }
        }

        private bool IsRuleFile(string filePath)
        {
            var extension = Path.GetExtension(filePath).ToLowerInvariant();
            return extension is ".yar" or ".yara" or ".yml" or ".yaml" or ".json";
        }

        private string GetRuleDirectory(RuleType ruleType)
        {
            return ruleType switch
            {
                RuleType.Yara => Path.Combine(_rulesBasePath, "YARA"),
                RuleType.Sigma => Path.Combine(_rulesBasePath, "Sigma"),
                RuleType.Stix => Path.Combine(_rulesBasePath, "STIX"),
                RuleType.Custom => Path.Combine(_rulesBasePath, "Custom"),
                _ => Path.Combine(_rulesBasePath, "Custom")
            };
        }

        private string GetRuleFileExtension(RuleType ruleType)
        {
            return ruleType switch
            {
                RuleType.Yara => ".yar",
                RuleType.Sigma => ".yml",
                RuleType.Stix => ".json",
                RuleType.Custom => ".txt",
                _ => ".txt"
            };
        }

        private string SanitizeFileName(string fileName)
        {
            var invalidChars = Path.GetInvalidFileNameChars();
            var sanitized = new string(fileName.Where(c => !invalidChars.Contains(c)).ToArray());
            return string.IsNullOrWhiteSpace(sanitized) ? "rule" : sanitized;
        }
    }
}