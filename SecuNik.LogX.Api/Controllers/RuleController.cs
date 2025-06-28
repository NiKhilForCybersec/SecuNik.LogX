using Microsoft.AspNetCore.Mvc;
using SecuNik.LogX.Core.DTOs;
using SecuNik.LogX.Core.Entities;
using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Api.Data;
using SecuNik.LogX.Api.Services.Rules;
using Microsoft.EntityFrameworkCore;

namespace SecuNik.LogX.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class RuleController : ControllerBase
    {
        private readonly LogXDbContext _dbContext;
        private readonly IRuleEngine _ruleEngine;
        private readonly RuleValidationService _validationService;
        private readonly RuleLoader _ruleLoader;
        private readonly ILogger<RuleController> _logger;

        public RuleController(
            LogXDbContext dbContext,
            IRuleEngine ruleEngine,
            RuleValidationService validationService,
            RuleLoader ruleLoader,
            ILogger<RuleController> logger)
        {
            _dbContext = dbContext;
            _ruleEngine = ruleEngine;
            _validationService = validationService;
            _ruleLoader = ruleLoader;
            _logger = logger;
        }

        /// <summary>
        /// Get all rules with optional filtering
        /// </summary>
        [HttpGet]
        public async Task<ActionResult<List<RuleDto>>> GetRules(
            [FromQuery] string? type = null,
            [FromQuery] string? category = null,
            [FromQuery] bool? enabledOnly = null,
            [FromQuery] string? tags = null,
            [FromQuery] string? severity = null,
            [FromQuery] string? search = null,
            [FromQuery] int limit = 50,
            [FromQuery] int offset = 0)
        {
            try
            {
                var query = _dbContext.Rules.AsQueryable();

                // Apply filters
                if (!string.IsNullOrEmpty(type) && Enum.TryParse<RuleType>(type, true, out var ruleType))
                {
                    query = query.Where(r => r.Type == ruleType);
                }

                if (!string.IsNullOrEmpty(category))
                {
                    query = query.Where(r => r.Category.ToLower().Contains(category.ToLower()));
                }

                if (enabledOnly.HasValue)
                {
                    query = query.Where(r => r.IsEnabled == enabledOnly.Value);
                }

                if (!string.IsNullOrEmpty(severity) && Enum.TryParse<ThreatLevel>(severity, true, out var threatLevel))
                {
                    query = query.Where(r => r.Severity == threatLevel);
                }

                if (!string.IsNullOrEmpty(search))
                {
                    query = query.Where(r => 
                        r.Name.ToLower().Contains(search.ToLower()) ||
                        r.Description.ToLower().Contains(search.ToLower()) ||
                        r.Tags.ToLower().Contains(search.ToLower()));
                }

                // Apply tags filter
                if (!string.IsNullOrEmpty(tags))
                {
                    var tagList = tags.Split(',').Select(t => t.Trim().ToLower()).ToList();
                    query = query.Where(r => tagList.All(tag => r.Tags.ToLower().Contains(tag)));
                }

                // Get total count
                var totalCount = await query.CountAsync();

                // Apply pagination
                query = query.OrderBy(r => r.Priority).ThenBy(r => r.Name)
                    .Skip(offset).Take(limit);

                // Get rules
                var rules = await query.ToListAsync();

                // Map to DTOs
                var ruleDtos = rules.Select(r => new RuleDto
                {
                    Id = r.Id,
                    Name = r.Name,
                    Description = r.Description,
                    Type = r.Type.ToString(),
                    Category = r.Category,
                    Severity = r.Severity.ToString(),
                    Content = r.Content,
                    Author = r.Author,
                    CreatedAt = r.CreatedAt,
                    UpdatedAt = r.UpdatedAt,
                    IsEnabled = r.IsEnabled,
                    IsBuiltIn = r.IsBuiltIn,
                    Tags = r.GetTags(),
                    References = r.GetReferences(),
                    RuleId = r.RuleId,
                    Priority = r.Priority,
                    MatchCount = r.MatchCount,
                    LastMatched = r.LastMatched,
                    IsValidated = r.IsValidated,
                    ValidationError = r.ValidationError,
                    Statistics = new RuleStatisticsDto
                    {
                        TotalMatches = r.MatchCount,
                        LastMatch = r.LastMatched
                    }
                }).ToList();

                return Ok(new
                {
                    rules = ruleDtos,
                    total = totalCount,
                    limit = limit,
                    offset = offset
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting rules");
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Get rule by ID
        /// </summary>
        [HttpGet("{id}")]
        public async Task<ActionResult<RuleDto>> GetRule(Guid id)
        {
            try
            {
                var rule = await _dbContext.Rules.FindAsync(id);
                if (rule == null)
                {
                    return NotFound($"Rule with ID {id} not found");
                }

                var ruleDto = new RuleDto
                {
                    Id = rule.Id,
                    Name = rule.Name,
                    Description = rule.Description,
                    Type = rule.Type.ToString(),
                    Category = rule.Category,
                    Severity = rule.Severity.ToString(),
                    Content = rule.Content,
                    Author = rule.Author,
                    CreatedAt = rule.CreatedAt,
                    UpdatedAt = rule.UpdatedAt,
                    IsEnabled = rule.IsEnabled,
                    IsBuiltIn = rule.IsBuiltIn,
                    Tags = rule.GetTags(),
                    References = rule.GetReferences(),
                    RuleId = rule.RuleId,
                    Priority = rule.Priority,
                    MatchCount = rule.MatchCount,
                    LastMatched = rule.LastMatched,
                    IsValidated = rule.IsValidated,
                    ValidationError = rule.ValidationError,
                    Statistics = new RuleStatisticsDto
                    {
                        TotalMatches = rule.MatchCount,
                        LastMatch = rule.LastMatched
                    }
                };

                return Ok(ruleDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting rule {RuleId}", id);
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Create a new rule
        /// </summary>
        [HttpPost]
        public async Task<ActionResult<RuleDto>> CreateRule([FromBody] CreateRuleDto createDto)
        {
            try
            {
                // Validate rule name uniqueness
                var existingRule = await _dbContext.Rules
                    .FirstOrDefaultAsync(r => r.Name == createDto.Name && r.Type == createDto.Type);

                if (existingRule != null)
                {
                    return BadRequest($"A rule with name '{createDto.Name}' and type '{createDto.Type}' already exists");
                }

                // Create rule entity
                var rule = new Rule
                {
                    Name = createDto.Name,
                    Description = createDto.Description,
                    Type = createDto.Type,
                    Category = createDto.Category,
                    Severity = createDto.Severity,
                    Content = createDto.Content,
                    Author = createDto.Author,
                    IsEnabled = true,
                    IsBuiltIn = false,
                    Priority = createDto.Priority,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow,
                    RuleId = createDto.RuleId
                };

                // Set tags and references
                rule.SetTags(createDto.Tags);
                rule.SetReferences(createDto.References);

                // Validate rule content
                var validationResult = await _validationService.ValidateRuleAsync(rule);
                rule.IsValidated = validationResult.IsValid;
                rule.ValidationError = validationResult.IsValid ? null : string.Join("; ", validationResult.Errors);

                // Save rule to database
                _dbContext.Rules.Add(rule);
                await _dbContext.SaveChangesAsync();

                // Save rule to file system
                await _ruleLoader.SaveRuleToFileAsync(rule);

                // Reload rules in rule engine
                await _ruleEngine.LoadRulesAsync();

                // Map to DTO
                var ruleDto = new RuleDto
                {
                    Id = rule.Id,
                    Name = rule.Name,
                    Description = rule.Description,
                    Type = rule.Type.ToString(),
                    Category = rule.Category,
                    Severity = rule.Severity.ToString(),
                    Content = rule.Content,
                    Author = rule.Author,
                    CreatedAt = rule.CreatedAt,
                    UpdatedAt = rule.UpdatedAt,
                    IsEnabled = rule.IsEnabled,
                    IsBuiltIn = rule.IsBuiltIn,
                    Tags = rule.GetTags(),
                    References = rule.GetReferences(),
                    RuleId = rule.RuleId,
                    Priority = rule.Priority,
                    IsValidated = rule.IsValidated,
                    ValidationError = rule.ValidationError
                };

                return CreatedAtAction(nameof(GetRule), new { id = rule.Id }, ruleDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating rule");
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Update an existing rule
        /// </summary>
        [HttpPut("{id}")]
        public async Task<ActionResult<RuleDto>> UpdateRule(Guid id, [FromBody] UpdateRuleDto updateDto)
        {
            try
            {
                var rule = await _dbContext.Rules.FindAsync(id);
                if (rule == null)
                {
                    return NotFound($"Rule with ID {id} not found");
                }

                if (rule.IsBuiltIn)
                {
                    return BadRequest("Built-in rules cannot be modified");
                }

                // Update rule properties
                if (!string.IsNullOrEmpty(updateDto.Description))
                    rule.Description = updateDto.Description;

                if (!string.IsNullOrEmpty(updateDto.Category))
                    rule.Category = updateDto.Category;

                if (updateDto.Severity.HasValue)
                    rule.Severity = updateDto.Severity.Value;

                if (!string.IsNullOrEmpty(updateDto.Content))
                    rule.Content = updateDto.Content;

                if (updateDto.IsEnabled.HasValue)
                    rule.IsEnabled = updateDto.IsEnabled.Value;

                if (updateDto.Tags != null)
                    rule.SetTags(updateDto.Tags);

                if (updateDto.References != null)
                    rule.SetReferences(updateDto.References);

                if (updateDto.Priority.HasValue)
                    rule.Priority = updateDto.Priority.Value;

                rule.UpdatedAt = DateTime.UtcNow;

                // Validate rule content if it was updated
                if (!string.IsNullOrEmpty(updateDto.Content))
                {
                    var validationResult = await _validationService.ValidateRuleAsync(rule);
                    rule.IsValidated = validationResult.IsValid;
                    rule.ValidationError = validationResult.IsValid ? null : string.Join("; ", validationResult.Errors);
                }

                // Save changes to database
                await _dbContext.SaveChangesAsync();

                // Update rule file
                await _ruleLoader.SaveRuleToFileAsync(rule);

                // Reload rules in rule engine if enabled state changed or content changed
                if (updateDto.IsEnabled.HasValue || !string.IsNullOrEmpty(updateDto.Content))
                {
                    await _ruleEngine.LoadRulesAsync();
                }

                // Map to DTO
                var ruleDto = new RuleDto
                {
                    Id = rule.Id,
                    Name = rule.Name,
                    Description = rule.Description,
                    Type = rule.Type.ToString(),
                    Category = rule.Category,
                    Severity = rule.Severity.ToString(),
                    Content = rule.Content,
                    Author = rule.Author,
                    CreatedAt = rule.CreatedAt,
                    UpdatedAt = rule.UpdatedAt,
                    IsEnabled = rule.IsEnabled,
                    IsBuiltIn = rule.IsBuiltIn,
                    Tags = rule.GetTags(),
                    References = rule.GetReferences(),
                    RuleId = rule.RuleId,
                    Priority = rule.Priority,
                    MatchCount = rule.MatchCount,
                    LastMatched = rule.LastMatched,
                    IsValidated = rule.IsValidated,
                    ValidationError = rule.ValidationError
                };

                return Ok(ruleDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating rule {RuleId}", id);
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Delete a rule
        /// </summary>
        [HttpDelete("{id}")]
        public async Task<ActionResult> DeleteRule(Guid id)
        {
            try
            {
                var rule = await _dbContext.Rules.FindAsync(id);
                if (rule == null)
                {
                    return NotFound($"Rule with ID {id} not found");
                }

                if (rule.IsBuiltIn)
                {
                    return BadRequest("Built-in rules cannot be deleted");
                }

                // Delete rule from database
                _dbContext.Rules.Remove(rule);
                await _dbContext.SaveChangesAsync();

                // Delete rule file
                await _ruleLoader.DeleteRuleFileAsync(rule);

                // Reload rules in rule engine
                await _ruleEngine.LoadRulesAsync();

                return NoContent();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting rule {RuleId}", id);
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Test a rule against sample content
        /// </summary>
        [HttpPost("{id}/test")]
        public async Task<ActionResult<RuleTestResultDto>> TestRule(Guid id, [FromBody] RuleTestDto testDto)
        {
            try
            {
                var rule = await _dbContext.Rules.FindAsync(id);
                if (rule == null)
                {
                    return NotFound($"Rule with ID {id} not found");
                }

                var testResult = await _ruleEngine.TestRuleAsync(rule, testDto.TestContent);

                var resultDto = new RuleTestResultDto
                {
                    Success = testResult.Success,
                    ErrorMessage = testResult.ErrorMessage,
                    ProcessingTime = testResult.ProcessingTime,
                    Warnings = testResult.Warnings,
                    Details = testDto.TestOptions
                };

                if (testResult.Success && testResult.Matches.Count > 0)
                {
                    resultDto.Matches = testResult.Matches.Select(m => new RuleMatchDto
                    {
                        RuleId = m.RuleId,
                        RuleName = m.RuleName,
                        RuleType = m.RuleType.ToString(),
                        Severity = m.Severity.ToString(),
                        MatchCount = m.MatchCount,
                        Confidence = m.Confidence,
                        Matches = m.Matches.Select(match => new MatchDetailDto
                        {
                            MatchedContent = match.MatchedContent,
                            FileOffset = match.FileOffset,
                            LineNumber = match.LineNumber,
                            Context = match.Context,
                            Fields = match.Fields,
                            Timestamp = match.Timestamp,
                            Confidence = 1.0
                        }).ToList()
                    }).ToList();
                }

                return Ok(resultDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error testing rule {RuleId}", id);
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Validate rule content
        /// </summary>
        [HttpPost("validate")]
        public async Task<ActionResult> ValidateRule([FromBody] CreateRuleDto createDto)
        {
            try
            {
                var rule = new Rule
                {
                    Name = createDto.Name,
                    Type = createDto.Type,
                    Content = createDto.Content
                };

                var validationResult = await _validationService.ValidateRuleAsync(rule);

                return Ok(new
                {
                    is_valid = validationResult.IsValid,
                    errors = validationResult.Errors,
                    warnings = validationResult.Warnings,
                    suggestions = validationResult.Suggestions
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating rule");
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Get rule categories
        /// </summary>
        [HttpGet("categories")]
        public async Task<ActionResult> GetCategories()
        {
            try
            {
                var categories = await _dbContext.Rules
                    .Where(r => !string.IsNullOrEmpty(r.Category))
                    .Select(r => r.Category)
                    .Distinct()
                    .ToListAsync();

                return Ok(new { categories });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting rule categories");
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Get rule tags
        /// </summary>
        [HttpGet("tags")]
        public async Task<ActionResult> GetTags()
        {
            try
            {
                var rules = await _dbContext.Rules
                    .Where(r => !string.IsNullOrEmpty(r.Tags))
                    .ToListAsync();

                var allTags = new HashSet<string>();
                foreach (var rule in rules)
                {
                    var tags = rule.GetTags();
                    foreach (var tag in tags)
                    {
                        allTags.Add(tag);
                    }
                }

                return Ok(new { tags = allTags.ToList() });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting rule tags");
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Get rule statistics
        /// </summary>
        [HttpGet("stats")]
        public async Task<ActionResult> GetRuleStats()
        {
            try
            {
                var totalRules = await _dbContext.Rules.CountAsync();
                var enabledRules = await _dbContext.Rules.CountAsync(r => r.IsEnabled);
                var builtInRules = await _dbContext.Rules.CountAsync(r => r.IsBuiltIn);
                var customRules = await _dbContext.Rules.CountAsync(r => !r.IsBuiltIn);

                var rulesByType = await _dbContext.Rules
                    .GroupBy(r => r.Type)
                    .Select(g => new { Type = g.Key.ToString(), Count = g.Count() })
                    .ToListAsync();

                var rulesBySeverity = await _dbContext.Rules
                    .GroupBy(r => r.Severity)
                    .Select(g => new { Severity = g.Key.ToString(), Count = g.Count() })
                    .ToListAsync();

                var topMatchedRules = await _dbContext.Rules
                    .Where(r => r.MatchCount > 0)
                    .OrderByDescending(r => r.MatchCount)
                    .Take(10)
                    .Select(r => new
                    {
                        r.Id,
                        r.Name,
                        r.Type,
                        r.Severity,
                        r.MatchCount,
                        r.LastMatched
                    })
                    .ToListAsync();

                var recentlyAddedRules = await _dbContext.Rules
                    .OrderByDescending(r => r.CreatedAt)
                    .Take(10)
                    .Select(r => new
                    {
                        r.Id,
                        r.Name,
                        r.Type,
                        r.Severity,
                        r.CreatedAt
                    })
                    .ToListAsync();

                return Ok(new
                {
                    total_rules = totalRules,
                    enabled_rules = enabledRules,
                    built_in_rules = builtInRules,
                    custom_rules = customRules,
                    rules_by_type = rulesByType,
                    rules_by_severity = rulesBySeverity,
                    top_matched_rules = topMatchedRules,
                    recently_added_rules = recentlyAddedRules
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting rule statistics");
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Import rules from file
        /// </summary>
        [HttpPost("import")]
        public async Task<ActionResult> ImportRules(IFormFile file)
        {
            try
            {
                if (file == null || file.Length == 0)
                {
                    return BadRequest("No file provided");
                }

                var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
                var supportedExtensions = new[] { ".yar", ".yara", ".yml", ".yaml", ".json", ".txt" };

                if (!supportedExtensions.Contains(extension))
                {
                    return BadRequest($"Unsupported file extension: {extension}");
                }

                using var stream = file.OpenReadStream();
                using var reader = new StreamReader(stream);
                var content = await reader.ReadToEndAsync();

                // Determine rule type from file extension
                var ruleType = extension switch
                {
                    ".yar" or ".yara" => RuleType.Yara,
                    ".yml" or ".yaml" => RuleType.Sigma,
                    ".json" => RuleType.Stix,
                    _ => RuleType.Custom
                };

                // Create rule
                var rule = new Rule
                {
                    Name = Path.GetFileNameWithoutExtension(file.FileName),
                    Type = ruleType,
                    Content = content,
                    IsEnabled = true,
                    IsBuiltIn = false,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };

                // Validate rule
                var validationResult = await _validationService.ValidateRuleAsync(rule);
                rule.IsValidated = validationResult.IsValid;
                rule.ValidationError = validationResult.IsValid ? null : string.Join("; ", validationResult.Errors);

                // Save rule to database
                _dbContext.Rules.Add(rule);
                await _dbContext.SaveChangesAsync();

                // Save rule to file system
                await _ruleLoader.SaveRuleToFileAsync(rule);

                // Reload rules in rule engine
                await _ruleEngine.LoadRulesAsync();

                return Ok(new
                {
                    rule_id = rule.Id,
                    name = rule.Name,
                    type = rule.Type.ToString(),
                    is_valid = rule.IsValidated,
                    validation_errors = rule.ValidationError,
                    validation_warnings = validationResult.Warnings
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error importing rule");
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Export rules
        /// </summary>
        [HttpGet("export")]
        public async Task<ActionResult> ExportRules(
            [FromQuery] string? type = null,
            [FromQuery] string? format = "json")
        {
            try
            {
                var query = _dbContext.Rules.AsQueryable();

                // Filter by type if specified
                if (!string.IsNullOrEmpty(type) && Enum.TryParse<RuleType>(type, true, out var ruleType))
                {
                    query = query.Where(r => r.Type == ruleType);
                }

                var rules = await query.ToListAsync();

                if (format?.ToLower() == "json")
                {
                    var ruleDtos = rules.Select(r => new RuleDto
                    {
                        Id = r.Id,
                        Name = r.Name,
                        Description = r.Description,
                        Type = r.Type.ToString(),
                        Category = r.Category,
                        Severity = r.Severity.ToString(),
                        Content = r.Content,
                        Author = r.Author,
                        CreatedAt = r.CreatedAt,
                        UpdatedAt = r.UpdatedAt,
                        IsEnabled = r.IsEnabled,
                        IsBuiltIn = r.IsBuiltIn,
                        Tags = r.GetTags(),
                        References = r.GetReferences(),
                        RuleId = r.RuleId,
                        Priority = r.Priority
                    }).ToList();

                    return Ok(ruleDtos);
                }
                else
                {
                    return BadRequest($"Unsupported export format: {format}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error exporting rules");
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Reload all rules
        /// </summary>
        [HttpPost("reload")]
        public async Task<ActionResult> ReloadRules()
        {
            try
            {
                await _ruleLoader.LoadAllRulesAsync();
                await _ruleEngine.LoadRulesAsync();

                var ruleCount = await _dbContext.Rules.CountAsync();
                var enabledCount = await _dbContext.Rules.CountAsync(r => r.IsEnabled);

                return Ok(new
                {
                    message = "Rules reloaded successfully",
                    total_rules = ruleCount,
                    enabled_rules = enabledCount
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error reloading rules");
                return StatusCode(500, "Internal server error");
            }
        }
    }
}